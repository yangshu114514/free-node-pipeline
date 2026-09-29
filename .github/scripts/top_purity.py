"""top100 ③：读 latency.json（前1000）→ 批量查出口 geo + 纯净度 → purity.json
免费单机代理出口 IP == 节点服务器 IP，故直查 node.server 等价于查出口。
输出结构与旧版完全一致（下游 top_select 只认 geo/exit_ip/is_proxy/is_hosting/isp/as）。

【三层查询链】任何一层失败只降级、绝不让 workflow 变红（数据质量问题≠管线故障）：
  1. 主力 ip-api.com/batch（现有实现原样保留：45/min 滑动窗口限速 + 指数退避；
     免费版只支持 IPv4，IPv6 不进本层）
  2. FFraud 公开端点（GET https://api.ffraud.com/public/ip/<IP>，免 key 免注册，
     无日上限、仅 burst 限速 429）——两个用途：
     ① ip-api 失败批/未查到的 IPv4 逐条补查
     ② IPv6 唯一查询通道（ip-api 免费版不支持 IPv6）
     单条 GET 串行查、批 ≤100 条、每条间隔 FFRAUD_GAP 防 burst 429；
     收到 429 跳过当批剩余不重试轰炸，网络错/非 200 直接放弃该条走下一层。
     文档：响应 success/ip/fraud_score/proxy/hosting/ASN/organization/geo 等，
     可选字段缺失时直接省略键（判存在不判 null），文档没写的字段不用。
  3. 离线兜底 _offline_lookup()：GeoLite2 / IP2Proxy LITE 本地 mmdb 思路，
     本次只留接口与接入点注释（不引入真实 mmdb 下载），当前恒返回 None。
  仍拿不到 → 填 err 占位（保持原 fail 语义），geo 缺失 >20% 照旧 ::warning::。
  全链零 secret 零 key：ip-api 免费版与 FFraud 公开端点都不需要任何凭据。

【跨轮缓存】同一 IP 的 geo/proxy 判定 24h 内不变 → 查询结果落 ip_cache.json
（工作目录，已被 .gitignore 忽略；键=IP，值={cc,proxy,hosting,isp,as,ts}）。
命中则零外查；19k 次/天的查询绝大部分是重复 IP，缓存把真实外查量压到最低。
JSON 损坏自动当空缓存重建，写失败不致命。

【域名】ip-api/FFraud 都只认 IP，域名先 DNS 解析成 A 记录再查；
同 IP 的多个域名合并一次查询、返回时按原 server 还原键。"""
import ipaddress
import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
IN = os.path.join(ROOT, "latency.json")
OUT = os.path.join(ROOT, "purity.json")
CACHE_FILE = os.path.join(ROOT, "ip_cache.json")   # 跨轮结果缓存（.gitignore 忽略）
CACHE_TTL = 24 * 3600      # 同一 IP 的 geo/proxy 判定 24h 内不变
BATCH = 100                # ip-api 免费版 100/批；FFraud 补查同为 100 条/批分组
MAX_WORKERS = 5            # 5 并发 × 各自批（6 批 → 2 轮完成，~8s）
RATE_MAX = 45              # ip-api 免费版 45 req/min 上限
RETRY = 2                  # ip-api 单批失败重试次数（指数退避 1.5s/3s）
FIELDS = "status,message,query,countryCode,proxy,hosting,isp,org,as"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) curl/8.0"}

# ---- 补查层配置：FFraud 公开端点（免 key 免注册，无日上限）----
# 文档（官方）：GET https://api.ffraud.com/public/ip/<IP>，无 key 无 headers；
# 仅 burst 限速 429（无日上限）→ 429 时跳过当批不重试轰炸。
# 响应字段（官方示例）：success/ip/fraud_score/risk/vpn/proxy/tor/hosting/
# is_abuser/ASN/organization/geo:{country,city}——可选字段缺失时直接省略键。
FFRAUD_URL = "https://api.ffraud.com/public/ip/"
FFRAUD_GAP = 0.05          # 单条间隔，防 burst 429（batch 补查需 key，不做）

_tls = threading.local()


class _RateLimiter:
    """滑动窗口限速：60s 内最多 RATE_MAX 次请求。
    并发批数少时无感（全放行）；唯一 IP 变多导致批数膨胀时自动排队到窗口滑出，
    保证任何情况下不超过 ip-api 免费版 45/min，避免整段 IP 被临时封禁。"""

    def __init__(self, max_calls=RATE_MAX, window=60.0):
        self.max_calls = max_calls
        self.window = window
        self._ts = []
        self._lock = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                self._ts = [t for t in self._ts if now - t < self.window]
                if len(self._ts) < self.max_calls:
                    self._ts.append(now)
                    return
                wait = self.window - (now - self._ts[0]) + 0.05
            time.sleep(max(wait, 0.1))


_LIMIT = _RateLimiter()


def _session():
    """线程局部 Session（复用连接，免每批重建 TCP）。"""
    s = getattr(_tls, "sess", None)
    if s is None:
        s = requests.Session()
        s.trust_env = False
        s.mount("http://", HTTPAdapter(pool_connections=2, pool_maxsize=4))
        _tls.sess = s
    return s


# ===================== 跨轮缓存（键=IP，24h TTL） =====================

def _cache_load():
    """读 ip_cache.json。文件不存在→空；JSON 坐坏/结构不对→当空缓存重建，绝不抛。"""
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("缓存根不是对象")
        return data
    except FileNotFoundError:
        return {}
    except Exception as e:  # noqa: BLE001  坏 JSON 不炸：本轮全量外查、结束后覆盖重建
        print(f"  [!] ip_cache.json 损坏，忽略并重建：{str(e)[:60]}", flush=True)
        return {}


def _cache_get(cache, ip):
    """命中且未过期 → info（补回 ip 键，与外查条目同构）；否则 None（零外查的关键）。"""
    ent = cache.get(ip)
    if not isinstance(ent, dict):
        return None
    ts = ent.get("ts")
    if not isinstance(ts, (int, float)) or time.time() - ts >= CACHE_TTL:
        return None
    info = {k: ent.get(k) for k in ("cc", "proxy", "hosting", "isp", "as")}
    info["ip"] = ip
    return info


def _cache_put(cache, ip, info):
    """只写成功条目（带 err 的失败占位不缓存，避免坏数据续命 24h）。"""
    cache[ip] = {"cc": info.get("cc") or "", "proxy": info.get("proxy"),
                 "hosting": info.get("hosting"), "isp": info.get("isp") or "",
                 "as": info.get("as") or "", "ts": int(time.time())}


def _cache_save(cache):
    """原子落盘（tmp + replace）防写一半损坏；失败只打日志不致命。"""
    try:
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
        os.replace(tmp, CACHE_FILE)
    except Exception as e:  # noqa: BLE001  缓存写失败=下轮多查，不影响本轮输出
        print(f"  [!] 缓存写入失败（不致命）：{str(e)[:60]}", flush=True)


# ===================== 层 1：ip-api 主力（原实现保留） =====================

def _one_batch(chunk):
    """查一个 100 条批（限速 + 重试），返回 {server: info}，与原 query_batch 字段一致。"""
    body = [{"query": q} for q in chunk]
    last_err = "unknown"
    for attempt in range(RETRY + 1):
        _LIMIT.acquire()
        try:
            r = _session().post("http://ip-api.com/batch", params={"fields": FIELDS},
                                json=body, timeout=30, headers=UA)
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}"
            else:
                out = {}
                for item in r.json():
                    q = item.get("query")
                    if item.get("status") == "success":
                        out[q] = {
                            "ip": item.get("query"),
                            "cc": item.get("countryCode") or "",
                            "proxy": bool(item.get("proxy")),
                            "hosting": bool(item.get("hosting")),
                            "isp": item.get("isp") or "",
                            "as": item.get("as") or "",
                        }
                    else:
                        out[q] = {"cc": "", "proxy": None, "hosting": None,
                                  "err": item.get("message", "")}
                return out
        except Exception as e:  # noqa: BLE001
            last_err = str(e)[:40]
        # 真指数退避 1.5s/3s；最后一次失败已到循环尽头，不再白等一轮
        if attempt < RETRY:
            time.sleep(1.5 * (2 ** attempt))
    # 重试耗尽：整批填 err 占位（与原串行版异常分支一致）
    return {q: {"cc": "", "proxy": None, "hosting": None, "err": last_err}
            for q in chunk}


# ===================== 层 2：FFraud 免 key 补查 + IPv6 唯一通道 =====================

def _map_ffraud(ip, item):
    """FFraud 响应 → 与 ip-api 同构的 info。
    字段只取官方示例确认存在的，映射到既有输出结构：
      cc ← geo.country；proxy ← proxy(bool)；hosting ← hosting(bool)；
      isp ← organization；as ← "AS{ASN} {organization}"。
    可选字段缺失（官方：省略键）→ 保守 ""/None；success 非真 → err 交下一层。"""
    if not isinstance(item, dict) or not item.get("success"):
        err = "ffraud failed"
        if isinstance(item, dict):
            err = str(item.get("message") or item.get("error") or err)[:60]
        return {"cc": "", "proxy": None, "hosting": None, "err": err}
    geo = item.get("geo")
    geo = geo if isinstance(geo, dict) else {}
    org = item.get("organization") or ""
    asn = item.get("ASN")
    proxy = item.get("proxy")
    hosting = item.get("hosting")
    return {"ip": item.get("ip") or ip,
            "cc": geo.get("country") or "",
            "proxy": bool(proxy) if proxy is not None else None,
            "hosting": bool(hosting) if hosting is not None else None,
            "isp": org,
            "as": f"AS{asn} {org}".strip() if asn is not None else ""}


def _ffraud_one(ip):
    """FFraud 免 key 单条 GET。返回 info；失败返回带 err 的占位。
    不做请求内重试——429 是 burst 限速，重试轰炸只会放大被拒概率，
    429/网络错/非 200 一律放弃该条走下一层（离线 → 占位）。"""
    try:
        r = _session().get(FFRAUD_URL + ip, timeout=20, headers=UA)
    except Exception as e:  # noqa: BLE001  网络错 → 放弃该条
        return {"cc": "", "proxy": None, "hosting": None, "err": str(e)[:60]}
    if r.status_code == 429:
        return {"cc": "", "proxy": None, "hosting": None, "err": "ffraud 429"}
    if r.status_code != 200:
        return {"cc": "", "proxy": None, "hosting": None,
                "err": f"HTTP {r.status_code}"}
    try:
        return _map_ffraud(ip, r.json())
    except Exception:  # noqa: BLE001  响应体坏 → 放弃该条
        return {"cc": "", "proxy": None, "hosting": None, "err": "bad response"}


def _ffraud_fill(chunk):
    """一批（≤100）FFraud 逐条串行补查，返回 {ip: info}（成功与失败都带）。
    每条前间隔 FFRAUD_GAP 防 burst 429；某条收到 429 → 本批剩余直接放弃
    （跳过当批、不重试轰炸），网络错只放弃该条、继续查下一条。"""
    out = {}
    for i, ip in enumerate(chunk):
        time.sleep(FFRAUD_GAP)
        info = _ffraud_one(ip)
        out[ip] = info
        if info.get("err") == "ffraud 429":
            for rest in chunk[i + 1:]:
                out[rest] = {"cc": "", "proxy": None, "hosting": None,
                             "err": "ffraud 429 burst，跳过当批"}
            break
    return out


# ===================== 层 3：离线兜底（留接口，本次不接真实数据） =====================

def _offline_lookup(ip):
    """第三层：离线库本地查询（GeoLite2 / IP2Proxy LITE 思路），零外查零配额。

    接入点（后续接真实数据时改这一个函数即可，调用链/降级顺序不用动）：
      1. GeoLite2-City.mmdb（MaxMind，需免费账号；geo → cc 判非中）
         maxminddb.open_database('GeoLite2-City.mmdb').get(ip)
         → country.iso_code
      2. IP2Proxy-LITE-*.mmdb（PxData，proxy/hosting 判定）
         → ip2proxy 模块查 PROXY/PROXYTYPE/HASHPROXY 等字段
      3. 归属（isp/as）可再配 GeoLite2-ASN.mmdb（autonomous_system_number / isp）
      mmdb 文件放仓库外由 env/缓存注入（任务约定本次不引入真实下载）。

    返回与外查同构的 {ip, cc, proxy, hosting, isp, as}；当前无离线库 → None，
    由调用方保持原 err 占位语义。"""
    return None


def _is_ipv6(ip):
    try:
        return ipaddress.ip_address(ip).version == 6
    except ValueError:
        return False


def _resolve(server):
    """ip 层只认 IP，域名传进去必 fail（invalid query）→ geo 全丢。
    域名先 DNS 解析成 A 记录 IP 再查；解析失败返回原值，让查询层报错占位。
    IPv6 字面量原样返回——FFraud 支持 IPv6 直查，ip-api 免费版不支持（链路里体现）。"""
    try:
        ipaddress.ip_address(server)
        return server          # 已是 IP（v4/v6 字面量）
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(server, None, socket.AF_INET)
        return infos[0][4][0] if infos else server
    except Exception:          # noqa: BLE001  域名解析不了的节点本身也不可用
        return server


def query_batch(servers):
    """三层链查询，返回 {原server: info}（结构与旧版逐字段一致）。
    域名解析成 IP 后按 IP 分组：先查缓存（命中零外查），未命中的走
    ip-api（主力，仅 IPv4）→ FFraud 逐条补查（ip-api 失败批 + 全部 IPv6）
    → 离线占位，逐层降级，最后 err 占位。"""
    # 域名解析并行化（284 个域名串行 ~1min，16 并发 ~5s；IP 直接透传）
    with ThreadPoolExecutor(max_workers=16) as ex:
        ips = list(ex.map(_resolve, servers))
    ip_of = dict(zip(servers, ips))
    servers_of = {}
    for s, ip in ip_of.items():
        servers_of.setdefault(ip, []).append(s)
    uniq = list(servers_of)

    lock = threading.Lock()
    out, final = {}, {}        # out={server: info}；final={ip: 成功 info}
    misses = []
    cache = _cache_load()

    # ---- 缓存分拣：24h 内命中 → 零外查 ----
    for ip in uniq:
        hit = _cache_get(cache, ip)
        if hit:
            for s in servers_of[ip]:
                out[s] = hit
        else:
            misses.append(ip)
    cached = len(uniq) - len(misses)
    if cached:
        print(f"  缓存命中 {cached}/{len(uniq)}（零外查）", flush=True)

    # ---- 层 1：ip-api 主力（只收 IPv4——免费版不支持 IPv6）----
    v4 = [p for p in misses if not _is_ipv6(p)]
    v6 = [p for p in misses if _is_ipv6(p)]
    if v6:
        print(f"  IPv6 {len(v6)} 个：ip-api 免费版不支持 → 直接走 FFraud 单条查询",
              flush=True)
    fail_info = {}              # {ip: err 占位}：层失败也保留原错误语义
    if v4:
        chunks = [v4[i:i + BATCH] for i in range(0, len(v4), BATCH)]
        done = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(_one_batch, c): c for c in chunks}
            for fu in as_completed(futs):
                res = fu.result()          # {ip: info}
                with lock:
                    for ip, info in res.items():
                        if "err" in info:
                            fail_info[ip] = info
                        else:
                            final[ip] = info
                    done += len(futs[fu])
                    print(f"  ip-api {min(done, len(v4))}/{len(v4)}"
                          f"（{len(chunks)} 批，并发 {MAX_WORKERS}，限速 {RATE_MAX}/min）",
                          flush=True)

    # ---- 层 2：FFraud 免 key 逐条补查（ip-api 失败/未查到的 IPv4 + 全部 IPv6）----
    pending = [p for p in v4 if p not in final] + v6
    if pending:
        for ci in range(0, len(pending), BATCH):
            chunk = pending[ci:ci + BATCH]
            res = _ffraud_fill(chunk)     # 批内串行 + 条间隔 FFRAUD_GAP
            for ip, info in res.items():
                if "err" in info:
                    fail_info[ip] = info  # FFraud 也失败 → 占位走离线层
                else:
                    final[ip] = info
            print(f"  FFraud {min(ci + len(chunk), len(pending))}/{len(pending)}"
                  f"（逐条补查，间隔 {FFRAUD_GAP}s，429 跳过当批）", flush=True)

    # ---- 层 3：离线兜底（接口占位）→ 仍拿不到则 err 占位 ----
    missing = [p for p in misses if p not in final]
    for ip in missing:
        off = _offline_lookup(ip)
        if off:
            final[ip] = off

    # ---- 汇总回原 server 键 + 成功条目写缓存（一次原子落盘）----
    for ip, info in final.items():
        _cache_put(cache, ip, info)
        for s in servers_of.get(ip, [ip]):
            out[s] = info
    for ip in misses:
        if ip in final:
            continue
        if _is_ipv6(ip) and ip not in fail_info:
            info = {"cc": "", "proxy": None, "hosting": None,
                    "err": "ipv6: FFraud 未返回且 ip-api 不支持 IPv6"}
        else:
            info = fail_info.get(ip, {"cc": "", "proxy": None,
                                      "hosting": None, "err": "no_source"})
        for s in servers_of.get(ip, [ip]):
            out[s] = info
    _cache_save(cache)

    print(f"  查询完成：缓存 {cached} + 外查成功 {len(final)} + 占位 "
          f"{len(misses) - len(final)}（唯一 IP {len(uniq)}）", flush=True)
    return out


def main():
    if not os.path.exists(IN):
        print(f"[x] 缺 {IN}（先跑 top_latency）")
        return 1
    with open(IN, encoding="utf-8") as f:
        lat = json.load(f)
    nodes = lat["nodes"]
    print(f"输入前 {len(nodes)} 节点，批量查出口 geo+纯净度...")

    servers = list({n["server"] for n in nodes})
    print(f"唯一 server {len(servers)} 个（{(len(servers) + BATCH - 1) // BATCH} 批，"
          f"并发 {MAX_WORKERS}，限速 {RATE_MAX}/min）")
    t0 = time.monotonic()
    info = query_batch(servers)
    print(f"  查询链完成，耗时 {time.monotonic() - t0:.1f}s")

    enriched, geo_dist = [], {}
    for n in nodes:
        inf = info.get(n["server"], {})
        cc = inf.get("cc", "")
        geo_dist[cc or "?"] = geo_dist.get(cc or "?", 0) + 1
        enriched.append({**n,
                         "geo": cc,
                         "exit_ip": inf.get("ip", ""),
                         "is_proxy": inf.get("proxy"),
                         "is_hosting": inf.get("hosting"),
                         "isp": inf.get("isp", ""),
                         "as": inf.get("as", "")})

    # 纯净度信号：非中 + 非已知代理 + 非机房 = 最干净（最可能过 AI）
    non_cn = [e for e in enriched if e["geo"] and e["geo"] != "CN"]
    clean = [e for e in non_cn
             if e["is_proxy"] is False and e["is_hosting"] is False]

    payload = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "input": len(nodes), "geo_dist": geo_dist,
               "non_cn": len(non_cn), "clean_non_cn": len(clean),
               "nodes": enriched}
    # geo 缺失（cc 为空记作 "?"）占比超 20% = 查询链大概率整体失败（三层全断/被封），
    # 下游"非中过滤"会大面积失效——把占比写进摘要并打 warning 让 Actions 可见。
    missing = geo_dist.get("?", 0)
    miss_ratio = round(missing / len(nodes), 3) if nodes else 0.0
    payload["geo_missing_ratio"] = miss_ratio
    if miss_ratio > 0.2:
        print(f"::warning::geo 缺失 {missing}/{len(nodes)}（{miss_ratio:.0%} > 20%）"
              f"——查询链（ip-api→FFraud→占位）可能整体失败，非中过滤与纯净度判断大面积失效",
              flush=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"\n前 {len(nodes)} → 非中 {len(non_cn)} → 非中且非代理非机房(最净) {len(clean)} → {OUT}")
    print("出口国家分布(前15): " +
          ", ".join(f"{k}:{v}" for k, v in
                    sorted(geo_dist.items(), key=lambda x: -x[1])[:15]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
