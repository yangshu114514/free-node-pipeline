"""top100 ④：读 purity.json → 过滤非中 + 打分（仅纯净度档；延迟只当 DELAY_CAP 及格线）→ top100 → 写 KV
KV 键 top100:nodes（Worker 读的节点数组）；另存 detail/summary 供查。
env: CLOUDFLARE_API_TOKEN / CF_ACCOUNT_ID / CF_KV_NAMESPACE_ID（缺则跳过写KV，只出文件）
本机测可设 PROXY=http://127.0.0.1:7897 让 CF API 走代理。"""
import json
import os
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
IN = os.path.join(ROOT, "purity.json")
DETAIL = os.path.join(ROOT, "top100_detail.json")
SUMMARY = os.path.join(ROOT, "top100_summary.json")
KV_KEY = "top100:nodes"
TOP_N = 100
MIN_TOP = 30         # 空数据门槛：最终选中不足 30 视为塌方，拒写 KV（宁可旧数据续命）
DROP_RATIO = 0.5     # 骤降保护：较上轮 selected 跌幅 >50% 同样拒写（上游整批故障常见）
MAX_PER_SERVER = 3   # 档内密度配额：同一 server 最多入榜数（防单一出口刷屏）
MAX_PER_AS = 8       # 档内密度配额：同一 AS（isp/as 字段）最多入榜数
DELAY_CAP = 2000   # 可用性及格线（ms）。协议测天然超时 5000；曾拍 800 发现
                   # 机房口径下系统性误杀亚洲（机房→亚洲 150ms+ 起步且波动，
                   # 两轮近华池 83→4 震荡），放宽到 2000 只踢极端慢节点。
PROXY = os.environ.get("PROXY", "")


def score(n):
    """只按纯净度打分（0/10/20 三档）。机房测的延迟不参与排名——
    GitHub 机房离加拿大近，按它排会把榜单推向对国内不友好的地区；
    延迟只在 DELAY_CAP 当及格线用（踢明显不可用的），同档保持上游顺序。"""
    pure = 0
    if n.get("is_proxy") is False:
        pure += 1
    if n.get("is_hosting") is False:
        pure += 1
    return pure * 10


def put_kv(ns, acc, token, key, value):
    """写 KV，失败自动重试 1 次（网络抖动不重跑整条流水线）。返回 (ok, msg)。"""
    url = (f"https://api.cloudflare.com/client/v4/accounts/{acc}"
           f"/storage/kv/namespaces/{ns}/values/"
           f"{requests.utils.quote(key, safe='')}")
    s = requests.Session()
    s.trust_env = False
    px = {"http": PROXY, "https": PROXY} if PROXY else None
    msg = "unknown"
    try:
        for attempt in range(2):
            try:
                r = s.put(url, headers={"Authorization": f"Bearer {token}"},
                          data=value.encode("utf-8"), proxies=px, timeout=30)
                if r.status_code == 200:
                    return True, "ok"
                msg = r.text[:200]
            except Exception as e:  # noqa: BLE001
                msg = str(e)[:120]
            if attempt == 0:
                time.sleep(1.5)   # 退避后重试一次
        return False, msg
    finally:
        s.close()


def prev_selected(token, acc, ns):
    """读 KV 里现役 top100:nodes 的长度，当"上轮 selected"用
    （top100_summary.json 是运行产物不入库，checkout 里没有上轮值）。
    读不到（404/网络/env 缺）返回 None —— 骤降保护无从比较时跳过，不误伤。"""
    url = (f"https://api.cloudflare.com/client/v4/accounts/{acc}"
           f"/storage/kv/namespaces/{ns}/values/"
           f"{requests.utils.quote(KV_KEY, safe='')}")
    s = requests.Session()
    s.trust_env = False
    px = {"http": PROXY, "https": PROXY} if PROXY else None
    try:
        r = s.get(url, headers={"Authorization": f"Bearer {token}"},
                  proxies=px, timeout=15)
        if r.status_code != 200:
            return None
        arr = r.json()
        return len(arr) if isinstance(arr, list) else None
    except Exception:  # noqa: BLE001
        return None
    finally:
        s.close()


def main():
    if not os.path.exists(IN):
        print(f"[x] 缺 {IN}（先跑 top_purity）")
        return 1
    with open(IN, encoding="utf-8") as f:
        pur = json.load(f)
    nodes = pur["nodes"]

    # 过滤：出口非中且 geo 已知；delay 只当可用性及格线（DELAY_CAP 内才进候选），不进排名
    non_cn = [n for n in nodes if n.get("geo") and n["geo"] != "CN"
              and (n.get("delay") or 1e9) <= DELAY_CAP]
    # 诊断：入口 geo vs 门槛后池 geo（定位亚洲节点是死在上游还是被门槛踢的）
    NEAR = {"JP", "HK", "KR", "TW", "SG"}
    in_geo = {}
    for n in nodes:
        g = n.get("geo") or "?"
        in_geo[g] = in_geo.get(g, 0) + 1
    print("入口1000 geo 前15:",
          dict(sorted(in_geo.items(), key=lambda kv: -kv[1])[:15]),
          f"| 近华合计 {sum(v for k, v in in_geo.items() if k in NEAR)}",
          f"| CN {in_geo.get('CN', 0)}")
    # 诊断：候选池 geo 分布（看池子本身是不是被某一地区垄断，而不是排名问题）
    pool_geo = {}
    for n in non_cn:
        pool_geo[n["geo"]] = pool_geo.get(n["geo"], 0) + 1
    print("候选池 geo 前15:",
          dict(sorted(pool_geo.items(), key=lambda kv: -kv[1])[:15]),
          f"| 近华合计 {sum(v for k, v in pool_geo.items() if k in NEAR)}")
    for n in non_cn:
        n["score"] = round(score(n), 3)
    # 优先级：可用性（DELAY_CAP 及格线，在池子层）> 纯度档（绝对）> 上游顺序。
    # 机房测速不参与排名（口径错位）；稳定排序保证同档保持上游顺序。
    # 排序：纯度档降序，同档保持上游顺序（稳定排序，中性）。
    # 不按 geo 偏好——链式下实测物理距离不代表节点质量（本机→WARP接入点是
    # anycast 与节点 geo 无关，第二跳走 CF 骨干；实测 US 267ms 快于 SG 378），
    # 选点交给客户端 url-test 本机实测。
    non_cn.sort(key=lambda x: -x["score"])

    # 档内密度配额（在纯度档排序之后、同档上游顺序之上贪心跳过）：
    # 同 server ≤3、同 AS ≤8，防单一出口商/机房把榜单刷满；不碰 geo、不碰测速边界。
    top, kicked = [], {"server": 0, "as": 0}
    seen_srv, seen_as = {}, {}
    for n in non_cn:
        if len(top) >= TOP_N:
            break
        srv = n.get("server") or ""
        asn = (n.get("as") or "").strip()
        if seen_srv.get(srv, 0) >= MAX_PER_SERVER:
            kicked["server"] += 1
            continue
        if asn and seen_as.get(asn, 0) >= MAX_PER_AS:
            kicked["as"] += 1
            continue
        seen_srv[srv] = seen_srv.get(srv, 0) + 1
        if asn:
            seen_as[asn] = seen_as.get(asn, 0) + 1
        top.append(n)
    # Worker 读的最小格式（geo 供 Worker 拼节点名"地区-IP"）
    kv_nodes = [{"proto": n["proto"], "server": n["server"],
                 "port": n["port"], "ident": n["ident"],
                 "geo": n.get("geo") or "",
                 "raw": n.get("raw", "")} for n in top]

    geo_d, proto_d = {}, {}
    for n in top:
        geo_d[n["geo"]] = geo_d.get(n["geo"], 0) + 1
        proto_d[n["proto"]] = proto_d.get(n["proto"], 0) + 1

    summary = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "input": len(nodes), "non_cn": len(non_cn),
               "selected": len(top), "geo": geo_d, "proto": proto_d,
               "quota_kicked": kicked}

    print(f"前 {len(nodes)} → 非中 {len(non_cn)} → 选 top {len(top)}")
    print(f"top geo: {geo_d}")
    print(f"top proto: {proto_d}")

    # 写 KV 前先过两道闸：空数据门槛 + 骤降保护（任一触发拒写，让 KV 旧数据续命）
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    # 账号与命名空间一律从 env 取，不在代码里兜底（避免凭据标识入库）
    acc = os.environ.get("CF_ACCOUNT_ID", "")
    ns = os.environ.get("CF_KV_NAMESPACE_ID", "")
    gate = ""
    if len(top) < MIN_TOP:
        gate = f"选中 {len(top)} < 空数据门槛 {MIN_TOP}，疑似本轮数据塌方"
    else:
        prev = prev_selected(token, acc, ns) if (token and acc and ns) else None
        if prev is not None and prev > 0 and len(top) < prev * DROP_RATIO:
            gate = (f"选中 {len(top)} 较上轮 {prev} 跌幅 "
                    f"{100 * (1 - len(top) / prev):.0f}% > 50%，疑似上游整批故障")

    code = 0
    if gate:
        print(f"::error::top100 拒写 KV：{gate}（KV 保留旧数据，摘要仍落盘供诊断）")
        summary.update(kv_written=False, gate=gate)
        code = 1
    elif token and acc and ns:
        ok, msg = put_kv(ns, acc, token, KV_KEY, json.dumps(kv_nodes, ensure_ascii=False))
        summary["kv_written"] = ok
        if ok:
            print(f"写 KV {KV_KEY}: 成功")
        else:
            print(f"::error::写 KV {KV_KEY} 失败：{msg}（订阅将停留旧数据）")
            code = 1
    else:
        print(f"缺 env（token/account/ns），跳过写 KV，仅出文件（共 {len(kv_nodes)} 节点）")

    # 两文件无条件落盘：gate/写失败时靠它诊断，也供骤降保护读上轮 selected
    with open(DETAIL, "w", encoding="utf-8") as f:
        json.dump(top, f, ensure_ascii=False, indent=2)
    with open(SUMMARY, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
