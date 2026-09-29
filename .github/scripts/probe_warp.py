#!/usr/bin/env python3
"""实测 57 个 WARP MASQUE 接入点的真实可用性与延迟 → 产出 warp-endpoints.json。

规格 A §4.5。流程：
  1. cf_kv.kv_get("warp:device") 拿 WARP 凭据（privateKey/peerPublicKey/ipv4/ipv6）
  2. 生成 57 个 masque 节点 + mihomo 配置骨架（url-test 组全量，lazy: false）
  3. 启动 mihomo（Linux runner 自动下载 alpha amd64；MIHOMO_BIN 给路径则直接用，
     兼容 macOS/本机调试），等 external-controller 就绪
  4. delay API 逐节点测（并发 8）
  5. 写 JSON；ok=true 按 delay 升序在前，picked = 前 12 个名字（可用 < 4 时置空）
  6. 失败降级：mihomo 下载失败/起不来/0 个节点可用 → 不写 KV，打印原因，exit 0
     （KV 里旧数据继续有效，不让流水线红掉）

节点命名与 worker/src/config.js 的 entryName() 逐字节一致：
  v4 162.159.198.1:443  -> 198.1-443
  v6 2606:4700:103::1   -> v6-103-1-443   （按 JS split(":") 推）
  官方域名节点 -> 官方域名（固定名，带 SNI）
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cf_kv  # noqa: E402

# --- 接入点清单（照抄 worker/src/config.js，不要改） ---
V4 = ["162.159.198.1", "162.159.198.2", "162.159.199.1", "162.159.199.2"]
V6 = ["2606:4700:103::1", "2606:4700:103::2",
      "2606:4700:104::1", "2606:4700:104::2"]
PORTS = [443, 500, 1701, 4500, 4443, 8443, 8095]
OFFICIAL_SNI = "zt-masque.cloudflareclient.com"
SNI_NODE = ("162.159.198.1", 443)

DELAY_URL = "https://www.gstatic.com/generate_204"
DELAY_CONCURRENCY = 8
PROBE_REPEAT = 5   # 每接入点重复探测次数——单次通只是机房瞬时口径；
                   # MASQUE 底座 UDP 抖动是偶发的，必须重复采样才暴露
CONC_BASE = "https://api.github.com/repos/MetaCubeX/mihomo/releases"
CONTROLLER = "http://127.0.0.1:9090"


def degrade(reason: str) -> None:
    """失败降级：不写 KV，打印原因，exit 0。"""
    print(f"[probe_warp] 跳过写 KV: {reason}")
    print("[probe_warp] KV 里的旧 warp:endpoints 继续有效，本轮不影响订阅。")
    sys.exit(0)


def entry_name(ip: str, port: int) -> str:
    """与 worker/src/config.js entryName() 逐字节一致。"""
    if ":" in ip:
        parts = ip.split(":")
        return f"v6-{parts[2]}-{parts[-1]}-{port}"
    return ".".join(ip.split(".")[2:]) + f"-{port}"


def masque_node_yaml(name: str, ip: str, port: int, priv: str, pub: str,
                    v4: str, v6: str, sni: str = "") -> str:
    srv = f'"{ip}"' if ":" in ip else ip
    extra = f"\n    sni: {sni}" if sni else ""
    return (f"  - name: {name}\n"
            f"    type: masque\n"
            f"    server: {srv}\n"
            f"    port: {port}{extra}\n"
            f"    private-key: {priv}\n"
            f"    public-key: {pub}\n"
            f"    ip: {v4}\n"
            f"    ipv6: {v6}\n"
            f"    mtu: 1280\n"
            f"    udp: true\n"
            f"    remote-dns-resolve: true\n"
            f"    dns: [1.1.1.1, 2606:4700:4700::1111]")


def build_nodes(priv: str, pub: str, v4: str, v6: str):
    nodes = []
    for ip in V4 + V6:
        for port in PORTS:
            nodes.append({"name": entry_name(ip, port), "server": ip,
                         "port": port, "family": 6 if ":" in ip else 4,
             "sni": ""})
    nodes.append({"name": "官方域名", "server": SNI_NODE[0],
                  "port": SNI_NODE[1], "family": 4, "sni": OFFICIAL_SNI})
    return [masque_node_yaml(n["name"], n["server"], n["port"], priv, pub,
                             v4, v6, n["sni"]) for n in nodes], nodes


def build_config(node_yamls: list, all_names: list) -> str:
    return (
        "mixed-port: 7891\n"
        "external-controller: 127.0.0.1:9090\n"
        "mode: rule\n"
        "log-level: warning\n"
        "\n"
        "proxies:\n"
        + "\n".join(node_yamls)
        + "\n\n"
        "proxy-groups:\n"
        "  - name: auto\n"
        "    type: url-test\n"
        "    url: http://www.gstatic.com/generate_204\n"
        "    interval: 30\n"
        "    lazy: false\n"
        "    proxies:\n"
        + "\n".join(f"      - {n}" for n in all_names)
        + "\n\n"
        "rules:\n"
        "  - MATCH,DIRECT\n"
    )


def find_mihomo() -> str:
    """mihomo 可执行文件路径：MIHOMO_BIN 优先，否则 Linux 自动下载。"""
    env_bin = os.environ.get("MIHOMO_BIN", "").strip()
    if env_bin:
        if not os.path.isfile(env_bin) or not os.access(env_bin, os.X_OK):
            degrade(f"MIHOMO_BIN={env_bin} 不是可执行文件")
        return env_bin

    if sys.platform != "linux":
        degrade("未设 MIHOMO_BIN 且非 Linux runner（本机调试请设 MIHOMO_BIN）")

    url = subprocess.run(
        ["curl", "-sL", CONC_BASE],
        capture_output=True, text=True, timeout=60).stdout
    m = re.search(r"https://[^\"]*mihomo-linux-amd64-alpha[^\"]*\.gz", url)
    if not m:
        degrade("GitHub releases 找不到 mihomo-linux-amd64-alpha 下载地址")
    dest = os.path.join(tempfile.gettempdir(), "mihomo")
    print(f"下载 mihomo: {m.group(0)}")
    r = subprocess.run(["curl", "-sL", "-o", dest + ".gz", m.group(0)],
                       timeout=300)
    if r.returncode != 0 or not os.path.isfile(dest + ".gz"):
        degrade("mihomo 下载失败")
    subprocess.run(["gunzip", "-f", dest + ".gz"], check=True)
    os.chmod(dest, 0o755)
    return dest


def wait_ready() -> bool:
    for _ in range(20):
        try:
            with urllib.request.urlopen(f"{CONTROLLER}/version", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            time.sleep(1)
    return False


def probe_one(node: dict) -> dict:
    """重复探测 PROBE_REPEAT 次，全部成功才算稳定可用。

    返回 {delay(成功轮中位), ok(=全过), attempts(实际轮数), flaky(先成后败=抖动)}。
    任一轮失败即判负并提前退出——picked 白名单只收 5/5 全过的接入点，
    偶发抖动的（单次测通过、实际使用中会断 TLS）直接出局。
    """
    q = urllib.parse.quote(node["name"], safe="")
    api = f"{CONTROLLER}/proxies/{q}/delay?url={DELAY_URL}&timeout=5000"
    delays: list[int] = []
    for i in range(PROBE_REPEAT):
        try:
            with urllib.request.urlopen(api, timeout=15) as r:
                body = json.loads(r.read())
            delay = int(body.get("delay") or 0)
            ok_i = r.status == 200 and delay > 0
        except Exception:  # noqa: BLE001
            ok_i, delay = False, 0
        if not ok_i:
            # 有过成功记录才失败 = 抖动；首挂 = 真不可用
            return {"delay": 0, "ok": False, "attempts": i + 1,
                    "flaky": i > 0}
        delays.append(delay)
    delays.sort()
    mid = delays[len(delays) // 2] if delays else 0
    return {"delay": mid, "ok": True, "attempts": PROBE_REPEAT, "flaky": False}


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "dist/warp-endpoints.json"

    # 1. 拿 WARP 凭据
    try:
        raw = cf_kv.kv_get("warp:device")
    except Exception as e:  # noqa: BLE001
        degrade(f"读 KV warp:device 失败: {e}")
    if not raw:
        degrade("KV warp:device 为空")
    try:
        dev = json.loads(raw)
        priv = dev["privateKey"]
        pub = dev["peerPublicKey"]
        v4 = dev["ipv4"]
        v6 = dev["ipv6"]
    except Exception as e:  # noqa: BLE001
        degrade(f"KV warp:device 解析失败: {e}")

    # 2. 生成配置
    node_yamls, nodes = build_nodes(priv, pub, v4, v6)
    assert len(nodes) == 57, f"节点数 {len(nodes)} != 57"
    names = [n["name"] for n in nodes]
    cfg = build_config(node_yamls, names)

    # 3. 启动 mihomo
    mihomo = find_mihomo()
    tmpdir = tempfile.mkdtemp(prefix="probe-warp-")
    proc = None
    log_path = os.path.join(tmpdir, "mihomo.log")
    try:
        cfg_path = os.path.join(tmpdir, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(cfg)
        with open(log_path, "ab") as logf:
            # 只用 -f，不用 -d：实测 mihomo 的 -d 目录模式会生成/加载自己的
            # 初始配置，覆盖我们 -f 里的 mixed-port / external-controller，
            # 导致 9090 起不来。cwd 设为 tmpdir，日志/geodata 都落在里面。
            proc = subprocess.Popen(
                [mihomo, "-f", cfg_path],
                cwd=tmpdir, stdout=logf, stderr=logf)
        if not wait_ready():
            tail = ""
            try:
                with open(log_path, encoding="utf-8", errors="replace") as f:
                    tail = "\n".join(f.read().splitlines()[-10:])
            except Exception:  # noqa: BLE001
                pass
            alive = proc.poll() is None
            degrade(f"mihomo 20s 内 /version 未就绪"
                    f"（进程{'仍在跑' if alive else '已退出'}）；日志尾部:\n{tail}")

        # 4. 逐节点测延迟（并发 8）
        print(f"测 {len(nodes)} 个接入点延迟（并发 {DELAY_CONCURRENCY}）")
        t0 = datetime.now(timezone.utc)
        with ThreadPoolExecutor(max_workers=DELAY_CONCURRENCY) as pool:
            results = list(pool.map(probe_one, nodes))
        elapsed = (datetime.now(timezone.utc) - t0).total_seconds()

        # 5. 组装输出（ok = 5/5 全过；抖动剔除单独统计便于观察 UDP 质量）
        rows = []
        for n, r in zip(nodes, results):
            rows.append({"name": n["name"], "server": n["server"],
                         "port": n["port"], "family": n["family"],
                         "delay": r["delay"], "ok": r["ok"],
                         "attempts": r.get("attempts", 0),
                         "flaky": r.get("flaky", False)})
        ok_rows = [r for r in rows if r["ok"]]
        bad_rows = [r for r in rows if not r["ok"]]
        flaky_n = sum(1 for r in bad_rows if r["flaky"])
        ok_rows.sort(key=lambda r: r["delay"])
        picked = [r["name"] for r in ok_rows[:12]] if len(ok_rows) >= 4 else []

        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "runner": os.environ.get("RUNNER_DESCRIPTION",
                                     "GitHub Actions / ubuntu-latest"),
            "total": len(rows),
            "available": len(ok_rows),
            "list": ok_rows + bad_rows,
            "picked": picked,
        }
        d = os.path.dirname(out_path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        print(f"完成: {len(ok_rows)}/{len(rows)} 可用（{PROBE_REPEAT} 次全过），"
              f"抖动剔除 {flaky_n}，耗时 {elapsed:.0f}s")
        for r in ok_rows[:5]:
            print(f"  {r['name']:>12}  {r['server']:>22}  {r['port']:<5}  {r['delay']}ms")
        print(f"picked: {picked if picked else '(可用<4，置空，Worker 回退硬编码全量)'}")
        print(f"输出: {out_path}（本机不落 KV，KV 写入由 workflow 做）")
        if not ok_rows:
            print("注意: 0 个节点可用 —— 本次产物 picked 为空，"
                  "Worker 侧将回退到硬编码全量。")
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
