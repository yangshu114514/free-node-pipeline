"""top100 ②b：协议初筛（独立可重复跑）—— 读 tcp_cands.json → 多 mihomo 实例并行协议测 → latency.json
用节点自己的协议经 mihomo 发真实请求测 delay，淘汰「协议死」的假节点（本步是初筛；
「被墙」由本地再筛）。协议活节点再过「出口证书自证」（CERT_URLS 的 https 目标，
mihomo 校验目标 TLS 证书）剔除出口 MITM/假证书的作恶节点。本步可单独重跑，
复用 top_tcp.py 的结果、不必重跑 TCP。
多实例分片默认 4（MIHOMO_SHARDS 可调），各分片的 -t 预检与启动并行执行；
全起不来时回退 TCP-only（按 tcp_rtt 排序）。
本机: MIHOMO_BIN=... python top_proto.py；Actions: find_mihomo 自动下载 linux alpha。"""
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CANDS = os.path.join(ROOT, "tcp_cands.json")
OUT = os.path.join(ROOT, "latency.json")

TOP_N = 1000          # 最终进入下一阶段的数量
# 云端 TCP 存活可达 15w+（海外无墙，是本机 3w 的 5 倍），全测协议要 15min+；
# 按 tcp_rtt 等距抽样截断——不能只取最快（最快多是 CF 假节点，本机实测活率 0.15%），
# 等距覆盖快中慢才能保住"慢而真"的节点（全量口径活率 4.7%）。
# 抽样上限 3 万的推算：4.7% 活率 × 3w ≈ 1410 协议活，三层漏斗（协议→纯净→非中优选）
# 后约 650 > 100 名额，余量充足；本步是流水线最慢环节，5w→3w 预计整轮再省约 50s。
PROTO_MAX = int(os.environ.get("PROTO_MAX", "30000"))
ALIVE_FLOOR = 100     # 交付下限：进入下一阶段的节点 < 100 视为塌方，error+exit 1
                      #（正常分支即协议活数；回退 TCP-only 分支按交付数判，
                      # 候选充足时不误杀，候选也塌时同样拦住）
SHARDS = int(os.environ.get("MIHOMO_SHARDS", "4"))
CTRL0 = 9097        # 控制端口基址：第 si 片用 CTRL0+si，分片间不重叠（-t 阶段不监听，启动后才绑）
DELAY_TMO = 5000     # 成功节点 delay max=4107ms，5s 无损；原 12s 纯浪费——
                     # 6631 个死节点每个白等 7s，占协议测总耗时九成（11.4min → 5.4min）
TOTAL_DELAY_WORKERS = 512   # 256→512 依据：128→256 曾把 5.4min 砍到 2.7min，历史线性外推
DELAY_URL = "http://www.gstatic.com/generate_204"
# 出口自证（剔除作恶/劣质出口）：对协议活节点追加 https 目标探测。mihomo 对 https delay
# 会验证目标证书链与域名——出口 MITM/假证书直接握手失败返回 503；正常出口拿到响应即过
# （状态码不参与判定，实测 200/403 均 OK）。单靠测速 URL 抓不到劫持者：本地实测
# US-104.129.164.30（给 grok.com 返回 *.myvitamind3.net 假证书）对 gstatic 白名单放行，
# 对这两个目标必 503。两目标互补：cloudflare 覆盖通用劫持，chatgpt 覆盖 AI 站定向劫持。
# 判定：任一目标首测 fail → 同目标复测一次（滤偶发抖动），仍 fail 即剔除；
# 复测通过 = 抖动，不剔（宁可漏检不误杀，与协议测失败语义一致）。
CERT_URLS = ("https://www.cloudflare.com/", "https://chatgpt.com/")
CERT_RETRY_GAP = 2.0   # 首测 fail 后复测前的统一等待（秒）：MASQUE/WARP 抖动窗口是秒级，
                       # 立即复测会把抖动节点双杀（首轮实测 74% 剔除率的根因）
CONC_BASE = "https://api.github.com/repos/MetaCubeX/mihomo/releases"

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32}")


def _is_uuid(s):
    return bool(_UUID_RE.fullmatch(str(s).strip()))


def _dirty(s):
    """含控制字符（除 tab/换行）即 base64 解码错的乱码——认证必死，源头丢省协议测。"""
    return any((ord(c) < 0x20 and c not in "\t\n") or ord(c) == 0x7F for c in str(s))


# ---------------- raw URI → mihomo clash 节点 YAML ----------------
def _q(query):
    out = {}
    for pair in query.split("&"):
        if not pair:
            continue
        ei = pair.find("=")
        k = (pair if ei < 0 else pair[:ei]).lower()
        v = "" if ei < 0 else pair[ei + 1:]
        try:
            v = urllib.parse.unquote(v.replace("+", " "))
        except Exception:  # noqa: BLE001
            pass
        out[k] = v
    return out


def _b64d(s):
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        return ""


def _y(v):
    """YAML 安全字符串化：剥孤立代理项(D800-DFFF)与 astral(>FFFF)——astral 经 ensure_ascii
    会变 U8hex，而 Go yaml.v2 只支持 u4hex 不认 U，会致 mihomo 拒载；再剥控制字符。"""
    s = str(v)
    s = "".join(c for c in s if not (0xD800 <= ord(c) <= 0xDFFF) and ord(c) <= 0xFFFF)
    s = "".join(c for c in s if c in "\t\n" or ord(c) >= 0x20)
    return json.dumps(s, ensure_ascii=True)


def uri_to_clash(raw, name):
    """完整 URI → mihomo 节点 YAML（含 sni/tls/network/path/host/flow/reality）。失败 None。"""
    if not raw or "://" not in raw:
        return None
    proto = raw.split("://", 1)[0].lower()
    body = raw.split("://", 1)[1]
    if "#" in body:
        body, _frag = body.split("#", 1)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    q = _q(query)
    ind = "    "

    if proto == "vmess":
        try:
            jm = json.loads(_b64d(body) or "{}")
        except Exception:  # noqa: BLE001
            return None
        server, port, ident = jm.get("add", ""), str(jm.get("port", "")), jm.get("id", "")
        if not server or not port or not ident or not _is_uuid(ident):
            return None   # vmess id 必须是合法 UUID，否则 mihomo fatal 毁整片
        nw = str(jm.get("net", "tcp")).lower()
        tls = jm.get("tls", "") in ("tls", "reality")
        sni = jm.get("sni") or jm.get("host") or ""
        path, host = jm.get("path", ""), jm.get("host", "")
    else:
        ident = ""
        if "@" in body:
            ident, hp = body.rsplit("@", 1)
        else:
            hp = body
        if ":" not in hp:
            return None
        if ident and _dirty(ident):
            return None   # 乱码 ident：base64 解码错，认证必死，源头丢
        server, port = hp.rsplit(":", 1)
        nw = str(q.get("type", "tcp")).lower()
        sec = str(q.get("security", "")).lower()
        tls = sec in ("tls", "reality", "tls1.3") or proto == "trojan"
        sni = q.get("sni") or q.get("peer") or q.get("servername", "")
        path, host = q.get("path", ""), q.get("host", "")
    if not server or not port:
        return None
    port = str(port).split("/")[0].strip()   # 剥 host:port/path 里的 /path 残留
    if not port.isdigit():
        return None   # 坏端口直接丢，别塞进配置毁整片

    head = (f"  - name: {_y(name)}\n{ind}type: {_y(proto)}\n"
            f"{ind}server: {_y(server)}\n{ind}port: {_y(str(port))}")
    net = ""
    if nw == "ws":
        net += f"\n{ind}network: ws\n{ind}ws-opts:\n{ind}{ind}path: {_y(path or '/')}"
        if host:
            net += f"\n{ind}{ind}headers:\n{ind}{ind}{ind}Host: {_y(host)}"
    elif nw == "grpc":
        net += f"\n{ind}network: grpc\n{ind}grpc-opts:\n{ind}{ind}grpc-service-name: {_y(path)}"
    elif nw in ("http", "h2"):
        net += f"\n{ind}network: http\n{ind}http-opts:\n{ind}{ind}path: {_y(path or '/')}"
        if host:
            net += f"\n{ind}{ind}headers:\n{ind}{ind}{ind}Host: {_y(host)}"
    if str(q.get("security", "")).lower() == "reality":
        tlsblk = (f"\n{ind}tls: true\n{ind}servername: {_y(sni or server)}"
                  f"\n{ind}reality-opts:\n{ind}{ind}public-key: {_y(q.get('pbk', ''))}"
                  + (f"\n{ind}{ind}short-id: {_y(q['sid'])}" if q.get("sid") else ""))
    elif tls:
        tlsblk = (f"\n{ind}tls: true\n{ind}servername: {_y(sni or server)}"
                  f"\n{ind}skip-cert-verify: true")
    else:
        tlsblk = ""
    fp = f"\n{ind}client-fingerprint: {_y(q.get('fp') or 'chrome')}"
    alpn = ""
    if q.get("alpn"):
        items = ", ".join(_y(a.strip()) for a in q["alpn"].split(",") if a.strip())
        alpn = f"\n{ind}alpn: [{items}]"

    if proto == "vless":
        if not ident or not _is_uuid(ident):
            return None   # vless uuid 非法 → mihomo fatal 毁整片
        flow = f"\n{ind}flow: {_y(q['flow'])}" if q.get("flow") else ""
        return f"{head}\n{ind}uuid: {_y(ident)}{flow}{tlsblk}{net}{fp}{alpn}"
    if proto == "trojan":
        if not ident:
            return None
        t = tlsblk or (f"\n{ind}tls: true\n{ind}servername: {_y(sni or server)}"
                       f"\n{ind}skip-cert-verify: true")
        return f"{head}\n{ind}password: {_y(ident)}{t}{net}{fp}{alpn}"
    if proto == "ss":
        if not ident:
            return None
        method, password = "aes-256-gcm", ident
        d = _b64d(ident)
        if d and ":" in d:
            method, password = d.split(":", 1)
        elif ident.count(":") >= 2:
            parts = ident.split(":")
            method, password = parts[0], ":".join(parts[1:])
        elif ident.count(":") == 1 and "-" in ident.split(":")[0]:
            method, password = ident.split(":", 1)
        if not password:
            return None
        rawm = method.strip()
        m2 = rawm.lower()
        # 合法 ss cipher 规范名全小写；含大写即乱码（如 Gw7i）——必须在 lower 前判
        if not m2 or rawm != m2 or not all(c.isalnum() or c == "-" for c in m2):
            return None   # 乱码 cipher：丢，mihomo 会拒载毁整片
        method = m2
        return f"{head}\n{ind}cipher: {_y(method)}\n{ind}password: {_y(password)}{net}\n{ind}udp: true"
    if proto in ("hysteria2", "hy2"):
        if not ident:
            return None
        sni_blk = f"\n{ind}sni: {_y(sni or server)}" if (tls or sni) else ""
        return (head.replace(f"type: {proto}", "type: hysteria2")
                + f"\n{ind}password: {_y(ident)}{sni_blk}\n{ind}skip-cert-verify: true")
    if proto == "http":
        user, pwd = "", ident
        if ident and ":" in ident:
            user, pwd = ident.split(":", 1)
        s = head
        if user:
            s += f"\n{ind}username: {_y(user)}\n{ind}password: {_y(pwd)}"
        elif pwd:
            s += f"\n{ind}password: {_y(pwd)}"
        return f"{s}\n{ind}tls: {'true' if tls else 'false'}"
    if proto in ("socks", "socks5"):
        user, pwd = "", ident
        if ident and ":" in ident:
            user, pwd = ident.split(":", 1)
        s = head.replace(f"type: {proto}", "type: socks5")
        if user:
            s += f"\n{ind}username: {_y(user)}\n{ind}password: {_y(pwd)}"
        elif pwd:
            s += f"\n{ind}password: {_y(pwd)}"
        return f"{s}\n{ind}udp: true"
    return None


# ---------------- mihomo 多实例 ----------------
def find_mihomo():
    env = os.environ.get("MIHOMO_BIN", "").strip()
    if env:
        return env
    import re as _re
    with urllib.request.urlopen(CONC_BASE, timeout=60) as r:
        rel = r.read().decode()
    m = _re.search(r"https://[^\"]*mihomo-linux-amd64-alpha[^\"]*\.gz", rel)
    if not m:
        raise RuntimeError("release 里找不到 mihomo-linux-amd64-alpha")
    dest = os.path.join(tempfile.gettempdir(), "mihomo_top")
    subprocess.run(["curl", "-sL", "-o", dest + ".gz", m.group(0)], check=True, timeout=300)
    subprocess.run(["gunzip", "-f", dest + ".gz"], check=True)
    os.chmod(dest, 0o755)
    return dest


def wait_ready(port, timeout=60):
    """轮询控制端口就绪。timeout=60 是「轮询次数」上限而非秒：失败才 sleep(1)，成功立即返回；
    127.0.0.1 拒连是即时的，实际远小于名义上限。mihomo 冷启动一般 1-2 次内就绪。"""
    url = f"http://127.0.0.1:{port}/version"
    for _ in range(timeout):
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            time.sleep(1)
    return False


def delay_one(name, port, url=DELAY_URL):
    """测单节点经 mihomo 访问 url 的耗时。返回 (delay_ms, err)；失败 delay=0 带原因。
    url 默认测速目标；传 https 目标即出口自证（mihomo 会验证目标 TLS 证书）。"""
    q = urllib.parse.quote(name, safe="")
    api = (f"http://127.0.0.1:{port}/proxies/{q}/delay"
           f"?url={urllib.parse.quote(url, safe='')}&timeout={DELAY_TMO}")
    try:
        with urllib.request.urlopen(api, timeout=DELAY_TMO // 1000 + 15) as r:
            body = json.loads(r.read())
        return int(body.get("delay") or 0), ""
    except urllib.error.HTTPError as e:
        # HTTPError 是类文件的响应对象（走死节点主路径，5 万次里上万次命中）：
        # 读完立即 close 归还连接，不留给 GC 兜底。
        try:
            raw = e.read()
        except Exception:  # noqa: BLE001
            raw = b""
        finally:
            try:
                e.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            msg = json.loads(raw.decode("utf-8", "ignore")).get("message") or str(e)
        except Exception:  # noqa: BLE001
            msg = str(e)
        return 0, str(msg)[:160]
    except Exception as e:  # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}"[:160]


def shard_config(yamls, names, port):
    return (f"mixed-port: 0\nexternal-controller: 127.0.0.1:{port}\nmode: rule\n"
            f"log-level: warning\n\nproxies:\n" + "\n".join(yamls) +
            "\n\nproxy-groups:\n  - name: sel\n    type: select\n    proxies:\n" +
            "\n".join(f"      - {n}" for n in names) +
            "\n\nrules:\n  - MATCH,sel\n")


def test_and_prune(mihomo, cfgp, port, s_yamls, s_names, sub, cap=60):
    """mihomo -t 预检配置；失败则按报错里的 proxy 索引剔除坏节点，重写重测直至通过。
    单个脏节点（乱码 cipher/坏端口/非法字段）不再毁掉整个分片——这是对 uri_to_clash 的兜底。"""
    for _ in range(cap):
        with open(cfgp, "w", encoding="utf-8") as f:
            f.write(shard_config(s_yamls, s_names, port))
        if len(s_yamls) <= 1:
            return
        try:
            # 单轮 -t 上限 45s：正常大配置（几万节点 YAML）解析校验是秒级，45s 是防挂死的
            # 保险值，几乎不会触到；timeout 触发走 except 分支直接交给正式启动暴露日志。
            r = subprocess.run([mihomo, "-t", "-f", cfgp], cwd=sub,
                               capture_output=True, text=True, timeout=45)
        except Exception:  # noqa: BLE001
            return   # -t 本身跑不动就别死磕，交给正式启动
        if r.returncode == 0:
            return
        err = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"proxy (\d+):", err)
        if not m:
            return   # 不是单节点错误（结构性问题），交给启动阶段暴露日志
        gi = int(m.group(1))
        if gi >= len(s_yamls):
            return
        s_yamls.pop(gi)
        s_names.pop(gi)


def protocol_probe(cands):
    """多 mihomo 实例分片并行协议测。返回 ({name: delay}, valid, fails, hijacked)；
    hijacked 为出口自证剔除的节点名集合（假证书/HTTPS 异常）；
    全起不来 → (None, valid, {}, set())。"""
    yamls, names, valid = [], [], []
    for n in cands:
        nm = f"n{len(valid)}"
        y = uri_to_clash(n.get("raw", ""), nm)
        if y:
            yamls.append(y)
            names.append(nm)
            valid.append(n)
    if not yamls:
        return None, valid, {}, set()
    try:
        mihomo = find_mihomo()
        if not os.path.isfile(mihomo):
            return None, valid, {}, set()
    except Exception as e:  # noqa: BLE001
        print(f"  [协议测跳过] {e}", flush=True)
        return None, valid, {}, set()

    n_shards = max(1, min(SHARDS, len(yamls)))
    shard_idx = [list(range(len(yamls)))[i::n_shards] for i in range(n_shards)]
    tmp = tempfile.mkdtemp(prefix="topproto-")
    instances = []

    def _prep_and_start(job):
        """单分片「准备+启动」，供线程池按片并行调用。
        流程与原先串行版逐片一致：建目录 → 切片 → mihomo -t 预检剔坏 → Popen 启动。
        各片资源天然独立（目录 s{si}、端口 CTRL0+si、配置 c.yaml 各一份，-t 阶段不监听
        控制端口），线程安全，可放心并发。
        返回 (port, s_names, proc|None, sub, 剔除数, 错误|None)：单片异常只标记该片，
        不毁掉其它片的启动（最终全起不来才走 TCP-only 回退）。"""
        si, idxs = job
        port = CTRL0 + si
        sub = os.path.join(tmp, f"s{si}")
        try:
            os.makedirs(sub, exist_ok=True)
            s_yamls = [yamls[i] for i in idxs]
            s_names = [names[i] for i in idxs]
            cfgp = os.path.join(sub, "c.yaml")
            before = len(s_yamls)
            test_and_prune(mihomo, cfgp, port, s_yamls, s_names, sub)
            pruned = before - len(s_yamls)   # s_yamls/s_names 在 test_and_prune 里成对 pop，恒等长
            if not s_yamls:
                return port, s_names, None, sub, pruned, None
            with open(os.path.join(sub, "m.log"), "ab") as lf:   # with 即关父进程句柄，子进程持有副本
                proc = subprocess.Popen([mihomo, "-f", cfgp], cwd=sub,
                                        stdout=lf, stderr=subprocess.STDOUT)
            return port, s_names, proc, sub, pruned, None
        except Exception as e:  # noqa: BLE001
            return port, [], None, sub, 0, f"{type(e).__name__}: {e}"

    jobs = [(si, idxs) for si, idxs in enumerate(shard_idx) if idxs]
    try:
        # 分片并行是本步最大提速点：原先逐片串行「跑 mihomo -t（每轮进程启动+解析几秒）
        # 再 Popen」，8 片要串 10-15s×8；并行后墙钟 ≈ 最慢一片（-t 与 spawn 同时铺开）。
        # 打印仍在主线程按片序收口，输出顺序与串行版一致。
        with ThreadPoolExecutor(max_workers=len(jobs) or 1) as pool:
            for port, s_names, proc, sub, pruned, err in pool.map(_prep_and_start, jobs):
                if err:
                    print(f"  [实例 {port} 准备/启动失败 {err}]", flush=True)
                    continue
                if pruned:
                    print(f"  [实例 {port} -t 剔除坏节点 {pruned} 个，剩 {len(s_names)}]", flush=True)
                if proc is None:
                    continue
                instances.append((port, s_names, proc, sub))
        print(f"  起 {len(instances)} 个 mihomo 实例（各 {len(names)//max(len(instances),1)} 节点），等就绪...",
              flush=True)

        def _ready(inst):
            port, _, proc, sub = inst
            return port, wait_ready(port, 60), inst
        ready_ports = []
        with ThreadPoolExecutor(max_workers=len(instances) or 1) as pool:
            for port, ok, inst in pool.map(_ready, instances):
                if ok:
                    ready_ports.append((port, inst[1]))
                else:
                    _, _, proc, sub = inst
                    tail = ""
                    try:
                        with open(os.path.join(sub, "m.log"), encoding="utf-8", errors="replace") as f:
                            tail = "\n".join(f.read().splitlines()[-12:])
                    except Exception:  # noqa: BLE001
                        pass
                    print(f"  [实例 {port} 未就绪 进程{'活' if proc.poll() is None else '死'}]\n{tail}", flush=True)
        if not ready_ports:
            print("  [协议测跳过] 所有 mihomo 实例未就绪", flush=True)
            return None, valid, {}, set()

        tasks = [(port, nm) for port, s_names in ready_ports for nm in s_names]
        print(f"  协议 delay 测 {len(tasks)} 个（{len(ready_ports)} 实例并行, 总并发 {min(TOTAL_DELAY_WORKERS, len(tasks))}）...",
              flush=True)

        def _probe(item):
            port, nm = item
            d, err = delay_one(nm, port)
            return nm, d, err

        results, fails = {}, {}
        with ThreadPoolExecutor(max_workers=min(TOTAL_DELAY_WORKERS, max(1, len(tasks)))) as pool:
            for nm, d, err in pool.map(_probe, tasks):
                results[nm] = d
                if d <= 0:
                    key = err or "unknown"
                    fails[key] = fails.get(key, 0) + 1

        # ---- 出口证书自证：仅对协议活节点追加 https 探测，抓出口 MITM/假证书 ----
        port_of = {nm: port for port, s_names in ready_ports for nm in s_names}
        alive = [nm for nm, d in results.items() if d > 0]
        hijacked = set()
        if alive:
            print(f"  出口自证 {len(alive)} 个 × {len(CERT_URLS)} 目标（https 证书校验）...",
                  flush=True)
            cert_tasks = [(nm, url) for nm in alive for url in CERT_URLS]

            def _cert(item):
                nm, url = item
                d, err = delay_one(nm, port_of[nm], url)
                return nm, url, d, err

            # 首测：任一目标 fail 进复测（复测仅针对失败目标，量级小）
            suspect, cert_errs = [], {}
            with ThreadPoolExecutor(max_workers=min(TOTAL_DELAY_WORKERS, max(1, len(cert_tasks)))) as pool:
                for nm, url, d, err in pool.map(_cert, cert_tasks):
                    if d <= 0:
                        suspect.append((nm, url))
                        k = err or "unknown"
                        cert_errs[k] = cert_errs.get(k, 0) + 1
            if suspect:
                # 复测前统一等一轮：首测 fail 若是 WARP/MASQUE 抖动窗口，立即复测会双杀
                # （首轮实测 74% 剔除率即此坑），间隔让抖动过去再仲裁。
                time.sleep(CERT_RETRY_GAP)
                def _recert(item):
                    nm, url = item
                    d, err = delay_one(nm, port_of[nm], url)
                    return nm, url, d, err
                n_timeout = 0
                with ThreadPoolExecutor(max_workers=min(TOTAL_DELAY_WORKERS, len(suspect))) as pool:
                    for nm, url, d, err in pool.map(_recert, suspect):
                        if d <= 0:
                            # 超时 = 网络抖动不是证书错（假证书是握手快速失败），
                            # 不按劫持踢——宁可漏检不误杀
                            if "timeout" in (err or "").lower() or "timed out" in (err or "").lower():
                                n_timeout += 1
                            else:
                                hijacked.add(nm)   # 复测仍 fail = 确定性证书/握手异常
                for nm in hijacked:
                    results[nm] = 0             # 从协议活里剔除，下游自然收不到
                print(f"  [出口自证] 首测 fail {len(suspect)}，原因 top:",
                      flush=True)
                for k, v in sorted(cert_errs.items(), key=lambda x: -x[1])[:6]:
                    print(f"    {v:5d}  {k}", flush=True)
                print(f"  [出口自证] 复测后剔除 {len(hijacked)}/{len(alive)}"
                      f"（timeout 豁免 {n_timeout} 不踢）", flush=True)
        return results, valid, fails, hijacked
    finally:
        for _, _, proc, _ in instances:
            try:
                proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        time.sleep(1)
        for _, _, proc, _ in instances:
            try:
                if proc.poll() is None:
                    proc.kill()
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if not os.path.exists(CANDS):
        print(f"[x] 缺 {CANDS}（先跑 top_tcp.py）", flush=True)
        return 1
    with open(CANDS, encoding="utf-8") as f:
        data = json.load(f)
    cands = data["nodes"]
    n_full = len(cands)
    if n_full > PROTO_MAX:
        step = n_full / PROTO_MAX
        cands = [cands[int(i * step)] for i in range(PROTO_MAX)]   # cands 已按 rtt 排序
        print(f"协议测输入截断 {n_full} → {PROTO_MAX}（按 tcp_rtt 等距抽样，保快中慢分布）",
              flush=True)
    print(f"读 TCP 候选 {len(cands)} 个 → 【{SHARDS}实例并行】协议初筛", flush=True)

    delays, valid, fails, hijacked = protocol_probe(cands)
    if delays is None:
        print("  协议测不可用 → 回退 TCP-only（按 tcp_rtt 排序）", flush=True)
        top = cands[:TOP_N]
        for n in top:
            n["delay"] = n.get("tcp_rtt", 0)
            n["proto_ok"] = False
    else:
        if hijacked:
            # 样例打印：n{i} → valid[i]，取被剔的前 8 个展示 proto://server:port
            # 外加前 3 个完整 raw URI（截断）——公开日志可直接本机复现验证剔除是否冤枉
            shown, raws = [], []
            ordered = sorted(hijacked, key=lambda s: int(s[1:]) if s[1:].isdigit() else 0)
            for nm in ordered[:8]:
                if nm.startswith("n") and nm[1:].isdigit() and int(nm[1:]) < len(valid):
                    v = valid[int(nm[1:])]
                    shown.append(f"{v.get('proto', '?')}://{v.get('server', '?')}:{v.get('port', '?')}")
                    if len(raws) < 3:
                        raws.append(str(v.get("raw", ""))[:180])
            more = "" if len(hijacked) <= 8 else f" 等 {len(hijacked)} 个"
            print(f"  [出口自证剔除] {'、'.join(shown)}{more}", flush=True)
            for r in raws:
                print(f"  [被剔样例 raw] {r}", flush=True)
        ok = []
        for i, n in enumerate(valid):
            d = delays.get(f"n{i}", 0)
            if d > 0:
                ok.append({**n, "delay": d, "proto_ok": True})
        ok.sort(key=lambda x: x["delay"])
        top = ok[:TOP_N]
        print(f"协议活 {len(ok)}/{len(valid)} → 按协议 delay 取前 {len(top)}"
              + (f"（出口自证剔除 {len(hijacked)}）" if hijacked else ""), flush=True)
        if fails:
            print("  失败原因 top:", flush=True)
            for k, v in sorted(fails.items(), key=lambda x: -x[1])[:12]:
                print(f"    {v:5d}  {k}", flush=True)

    byproto = {}
    for n in top:
        byproto[n["proto"]] = byproto.get(n["proto"], 0) + 1
    payload = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "cands": len(cands), "proto_filter": delays is not None,
               "shards": SHARDS, "selected": len(top),
               "cert_kicked": len(hijacked) if delays is not None else 0,
               "by_proto": byproto, "nodes": top}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    mode = f"协议初筛({SHARDS}实例)" if delays is not None else "TCP-only(协议测不可用)"
    print(f"\n[{mode}] 候选 {len(cands)} → 前 {len(top)} → {OUT}", flush=True)
    print(f"协议: {byproto}", flush=True)
    if top:
        ds = [n.get("delay", 0) for n in top]
        print(f"delay: min={min(ds)} med={sorted(ds)[len(ds)//2]} max={max(ds)}", flush=True)
    if len(top) < ALIVE_FLOOR:
        # 文件已落盘供诊断，但拒绝交付给下一阶段——100 名额都凑不齐的轮次必须红
        print(f"::error::协议筛后仅 {len(top)} 个 < 下限 {ALIVE_FLOOR}，疑似本轮塌方"
              f"（{OUT} 已写供诊断）", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
