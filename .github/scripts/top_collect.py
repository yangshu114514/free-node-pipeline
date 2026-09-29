"""top100 ①：读活跃源 → 并发探测订阅URL → 抓取 → 多格式解析（保留完整 raw URI）→ 去重(含非法地址过滤)
→ node_pool.json
节点格式: {"proto","server","port","ident","raw"}  raw=原始完整URI（含 sni/tls/network/path 等参数），
下游 top_latency 转 mihomo 测协议延迟、config.js 转 clash 节点都从 raw 恢复参数。
Actions 海外直连；本机测试: PROXY=http://127.0.0.1:7897 python top_collect.py

【耗时诊断结论（瓶颈定位）】
1) 连接零复用：原 get() 每次新建 Session 用完即 close——122 源 × (1 README + 8 路径) ≈ 1100 次请求
   全部走"全新 TCP + TLS 握手"，所谓 Session 复用根本没生效；单纯把请求并行化只是让 1100 次握手
   同时排队，GH 端连接数/带宽一限流，并发拉满也无收益（1.06min vs 1.0min 的原因）。
2) 尾延迟卡波次：总耗时 ≈ 波数 × 单源最坏耗时，而单源最坏 = 打满超时的挂起请求（GitHub raw 对
   不存在路径是即时 404，真正吃满 12/15s 的全是挂起连接）。源内并行只能压到 max(路径)=超时上限，
   再怎么加并发都无效。
【对应优化（只动"取文本"调度层，解析/去重不变）】
- 全局取文本线程池 + 线程局部 keep-alive Session：连接跨源复用，握手次数 ~1100 → ~192。
- 超时按"404 快、挂起慢"实测权衡收紧：README (3,5)、路径 (4,8)——404 响应 <0.5s 不受影响，
  挂起连接 2~3 倍速放弃，单源尾延迟直接砍。
- 单源预算熔断：SOURCE_BUDGET 内收不齐就 cancel 剩余路径，坏源不再占满整波。
- 每源耗时 + ok/nf/to/err/skip 统计，按耗时倒序输出 top 慢源，供后续按数据继续校准常量。"""
import base64
import json
import os
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout

import requests
from requests.adapters import HTTPAdapter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SOURCES = os.path.join(ROOT, "sources_active.json")
OUT = os.path.join(ROOT, "node_pool.json")
LOCAL_PROXY = os.environ.get("PROXY", "")
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) curl/8.0"}

# ---- 调度层常量（改完看 [诊断]/[最慢源] 输出校准，勿动解析逻辑）----
SOURCE_WORKERS = 48     # 源级并发：总耗时≈波数×单源尾延迟，波数=ceil(122/48)=3
PATH_WORKERS = 192      # 全局取文本线程池：长寿线程复用 keep-alive 连接（跨源共享）
SOURCE_BUDGET = 10.0    # 单源总耗时预算(秒)，超出即熔断放弃剩余路径（原坏源可挂满整波）
T_README = (3, 5)       # README 超时（连接3s/读5s）：只为发现额外订阅URL，慢则快弃
T_PATH = (4, 8)         # 候选路径超时（连接4s/读8s）：404 即时不受影响，挂起源 2~3 倍速放弃

CAND_PATHS = [
    "output/clash.yaml", "output/singbox.json", "output/v2ray-base64.txt",
    "clash.yaml", "sub.txt", "subscription.txt", "all.txt", "nodes.txt",
    "proxies.txt", "AllConfigsSub.txt", "subscriptions/v2ray/all_sub.txt",
    "sub/everything.txt", "sub/top.txt", "sub/verified.txt",
]

# 全局取文本统计（诊断用；lock 保护复合累加）
_GSTAT = {"lock": threading.Lock(), "codes": Counter(),
          "net": 0.0, "netmax": 0.0, "parse": 0.0}
_tls = threading.local()                      # 线程局部 Session → keep-alive 连接复用
_PATH_POOL = ThreadPoolExecutor(max_workers=PATH_WORKERS, thread_name_prefix="fetch")


def _session():
    """线程局部 Session：同线程的后续请求复用同一条 TCP/TLS 连接（原实现每请求
    新建+close，1100 次握手是真瓶颈之一）。连接池给足 per-host 上限。"""
    s = getattr(_tls, "sess", None)
    if s is None:
        s = requests.Session()
        s.trust_env = False
        ad = HTTPAdapter(pool_connections=4, pool_maxsize=8)
        s.mount("https://", ad)
        s.mount("http://", ad)
        _tls.sess = s
    return s


def get(url, timeout=T_PATH):
    """keep-alive 复用取文本。返回 (text, code)；code: ok / empty / nf(非200) / to(超时) / err。"""
    px = {"http": LOCAL_PROXY, "https": LOCAL_PROXY} if LOCAL_PROXY else None
    text, code = None, "err"
    t0 = time.monotonic()
    try:
        r = _session().get(url, proxies=px, timeout=timeout, headers=UA)
        if r.status_code != 200:
            code = "nf"
        elif not r.text.strip():
            code = "empty"
        else:
            code, text = "ok", r.text
    except requests.exceptions.Timeout:
        code = "to"
    except Exception:  # noqa: BLE001
        code = "err"
    finally:
        dt = time.monotonic() - t0
        with _GSTAT["lock"]:
            _GSTAT["codes"][code] += 1
            _GSTAT["net"] += dt
            if dt > _GSTAT["netmax"]:
                _GSTAT["netmax"] = dt
    return text, code


def _b64d(s):
    try:
        d = base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
        return d if d.strip() else None
    except Exception:  # noqa: BLE001
        return None


def _uri_lines(text):
    return re.findall(r"(?:vmess|vless|trojan|ss|ssr|hysteria2|hy2|tuic)://[^\s\"'<>]+",
                      text, re.I)


def _vmess(uri):
    d = _b64d(uri[len("vmess://"):])
    try:
        j = json.loads(d)
        return ("vmess", j.get("add"), str(j.get("port")), j.get("id", ""))
    except Exception:  # noqa: BLE001
        return None


def _std(uri, p):
    m = re.match(rf"{p}://([^@]+)@([^:/?#]+):(\d+)", uri, re.I)
    return (p.lower(), m.group(2), m.group(3), m.group(1)) if m else None


def _ss(uri):
    b = uri[len("ss://"):]
    if "@" in b:
        left, rest = b.split("@", 1)
        hp = rest.split("#")[0].split("?")[0]
        if ":" in hp:
            h, pt = hp.rsplit(":", 1)
            return ("ss", h, pt, _b64d(left) or left)
    dec = _b64d(b.split("#")[0])
    if dec and "@" in dec:
        ident, hp = dec.rsplit("@", 1)
        if ":" in hp:
            h, pt = hp.rsplit(":", 1)
            return ("ss", h, pt, ident)
    return None


def parse_text(text):
    """返回 5 元组列表 (proto, server, port, ident, raw)。raw=原始URI（保全参数）。"""
    if not text:
        return []
    t = text.strip()
    nodes = []
    if "://" not in t[:40] and "proxies" not in t and len(t) > 80:
        dec = _b64d(t.replace("\n", ""))
        if dec and ("://" in dec or "proxies" in dec):
            t = dec
    for uri in _uri_lines(t):
        p = uri.split("://", 1)[0].lower()
        rec = (_vmess(uri) if p == "vmess" else
               _ss(uri) if p == "ss" else
               _std(uri, p) if p in ("vless", "trojan", "hysteria2", "hy2", "tuic") else None)
        if rec and rec[1]:
            nodes.append((rec[0], rec[1], rec[2], rec[3], uri))   # 带 raw
    if not nodes:   # plain IP:port（HTTP/SOCKS 列表）
        for line in t.splitlines():
            line = line.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+", line):
                parts = line.split(":")
                ip, port = parts[0], parts[1]
                ident = parts[2] if len(parts) > 2 else ""
                nodes.append(("http", ip, port, ident, f"http://{ip}:{port}"))
    return nodes


def _bad_server(s):
    """非法 server → True（过滤）：回环 127.x、私有内网、链路本地、保留/多播、localhost。
    非 IP 字面（域名）保留。"""
    import ipaddress
    s = (s or "").strip().lower()
    if not s or s.startswith("localhost"):
        return True
    try:
        ip = ipaddress.ip_address(s.split("%")[0])
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def dedup(nodes):
    """按 (proto,server,port,ident) 去重 + 过滤非法地址；保留完整 raw。"""
    seen, out = set(), []
    for n in nodes:
        if _bad_server(n[1]):
            continue
        key = (n[0], n[1], str(n[2]), n[3])
        if key in seen:
            continue
        seen.add(key)
        out.append({"proto": n[0], "server": n[1], "port": str(n[2]),
                    "ident": n[3][:90], "raw": n[4]})
    return out


def _fetch_one(u):
    """取一个候选路径并解析（在线程池执行，计入 CPU 解析耗时诊断）。"""
    txt, code = get(u, T_PATH)
    tp = time.monotonic()
    nodes = parse_text(txt) if txt else []
    with _GSTAT["lock"]:
        _GSTAT["parse"] += time.monotonic() - tp
    return nodes, code


def probe_repo(repo):
    """单源探测：README + ≤8 个候选路径。
    调度策略：路径全部提交全局取文本池（连接跨源复用），在 SOURCE_BUDGET 预算内收割，
    超时熔断 cancel 未开始的路径；返回 (repo, nodes, stats) 供慢源排行。"""
    t0 = time.monotonic()
    st = Counter()
    urls = []
    rm, code = get(f"https://raw.githubusercontent.com/{repo}/HEAD/README.md", T_README)
    st[code] += 1
    if rm:
        for m in re.finditer(
                r"https?://raw\.githubusercontent\.com/[^\s\)\"'\]]+\.(?:txt|yaml|yml|json|b64)",
                rm, re.I):
            urls.append(m.group(0))
    for p in CAND_PATHS:
        urls.append(f"https://raw.githubusercontent.com/{repo}/HEAD/{p}")
    seen, tried, todo = set(), 0, []
    for u in urls:
        if u in seen or tried >= 8:
            continue
        seen.add(u)
        tried += 1
        todo.append(u)

    nodes = []
    pending = {}
    for u in todo:
        fu = _PATH_POOL.submit(_fetch_one, u)
        pending[fu] = u
    processed = set()

    def _collect(fu):
        """收割一个已完成任务；单任务异常只记 err，不让整个源/整个程序崩。"""
        try:
            got, code = fu.result()
        except Exception:  # noqa: BLE001
            got, code = None, "err"
        st[code] += 1
        if got:
            nodes.extend(got)

    deadline = t0 + SOURCE_BUDGET
    try:
        for fu in as_completed(pending, timeout=max(0.05, deadline - time.monotonic())):
            processed.add(fu)
            _collect(fu)
    except FuturesTimeout:
        # 熔断：先收割已完成后未来得及 yield 的，再放弃所有未完成路径
        #（cancel 得掉的直接取消；已在运行的 requests 无法中断，结果丢弃）
        for fu in pending:
            if fu in processed or not fu.done() or fu.cancelled():
                continue
            processed.add(fu)
            _collect(fu)
        for fu in pending:
            if fu not in processed:
                fu.cancel()
                st["skip"] += 1
    st["elapsed"] = time.monotonic() - t0
    st["nodes"] = len(nodes)
    return repo, nodes, st


def main():
    if not os.path.exists(SOURCES):
        print(f"[x] 缺 {SOURCES}，先跑 collect_sources", flush=True)
        return 1
    with open(SOURCES, encoding="utf-8") as f:
        srcs = json.load(f)["sources"]
    repos = [s["repo"] for s in srcs]
    print(f"活跃源 {len(repos)}，并发探测订阅"
          f"（源级 {SOURCE_WORKERS} / 取文本 {PATH_WORKERS}，单源预算 {SOURCE_BUDGET:.0f}s）...",
          flush=True)

    all_nodes, hit, repo_stats = [], 0, []
    t_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=SOURCE_WORKERS) as ex:   # 源级并发（波数=ceil(n/48)=3）
        futs = {ex.submit(probe_repo, r): r for r in repos}
        done = 0
        for fu in as_completed(futs):
            repo, nodes, st = fu.result()
            done += 1
            repo_stats.append((repo, st))
            if nodes:
                hit += 1
                all_nodes.extend(nodes)
            if done % 20 == 0:
                print(f"  进度 {done}/{len(repos)}（命中 {hit}，累计 {len(all_nodes)}）", flush=True)
    wall = time.monotonic() - t_start

    before = len(all_nodes)
    pool = dedup(all_nodes)
    payload = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "repos": len(repos), "repos_hit": hit,
               "raw": before, "deduped": len(pool), "nodes": pool}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n源 {len(repos)} → 命中 {hit} → 原始 {before} → 去重+过滤 {len(pool)} → {OUT}", flush=True)

    # ---- 每源耗时/结果统计（诊断输出：按耗时倒序看真瓶颈在哪）----
    codes = _GSTAT["codes"]
    total_req = sum(codes.values())
    print(f"[诊断] collect 耗时 {wall:.1f}s | 请求 {total_req}: "
          f"ok={codes['ok']} nf={codes['nf']} empty={codes['empty']} "
          f"to={codes['to']} err={codes['err']} | 熔断取消 {sum(s['skip'] for _, s in repo_stats)}",
          flush=True)
    if total_req:
        print(f"[诊断] 网络累计 {_GSTAT['net']:.1f}s"
              f"（均 {_GSTAT['net'] / total_req:.2f}s，单请求最慢 {_GSTAT['netmax']:.1f}s）"
              f" | 解析累计(CPU) {_GSTAT['parse']:.1f}s"
              f" | 命中率 ok {codes['ok']}/{total_req}", flush=True)
    print("[最慢源 top12]（耗时 | 状态 | 节点）", flush=True)
    for repo, st in sorted(repo_stats, key=lambda x: -x[1]["elapsed"])[:12]:
        print(f"  {st['elapsed']:5.1f}s {repo}  ok={st['ok']} nf={st['nf']} "
              f"to={st['to']} err={st['err']} skip={st['skip']} nodes={st['nodes']}",
              flush=True)
    slow = [s for _, s in repo_stats if s["to"] > 0 or s["elapsed"] >= SOURCE_BUDGET * 0.8]
    print(f"[诊断] 慢源（含超时或耗时≥预算80%）{len(slow)}/{len(repo_stats)} 个——"
          f"若 to 占请求比例高说明 GH raw 挂起连接仍是主因，可再降 T_PATH；"
          f"若慢源集中在少数 repo 可考虑直接移出 sources_active", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
