"""top100 ②a：TCP 粗筛（独立可重复跑）—— asyncio 高并发版
读 node_pool.json → asyncio 并发 TCP 可达+RTT → 全部存活进 tcp_cands.json
协议初筛在 top_proto.py 单独跑（读本文件结果），验证协议测时不必重跑 TCP。
并发模型：线程版 1000 线程 × 1.5s 超时 = 667 次/s 数学上限，实测正好卡死在那；
asyncio 单事件循环可开 5 万并发（TCP_CONC 可调），瓶颈回到网络超时本身。
Actions 海外直连；本机无需代理（TCP 直连测可达性）。"""
import asyncio
import json
import os
import random
import socket
import struct
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
POOL = os.path.join(ROOT, "node_pool.json")
OUT = os.path.join(ROOT, "tcp_cands.json")

SAMPLE_CAP = int(os.environ.get("TCP_SAMPLE", "0"))   # 0=全量；>0 随机抽样（对照实验用）
TCP_TOP = 0           # 0=TCP 存活全进协议初筛；>0 按 rtt 截断
TCP_TIMEOUT = 1.5    # 不要为了"提速"降它：pacer 限速下耗时=数量÷PACE 与超时无关；
                     # 且协议活节点 rtt 中位数 955ms、500ms 内仅 46%，收紧会砍掉真节点
                     #（快节点多是 CF 假节点，最快 2000 个协议活率仅 0.15%，全量 4.7%）
# 「并发数」与「发送速率」解耦——瓶颈是出口 pps（本机 conntrack / 网卡 tx 队列 /
# 上游 NAT 限速 / 对端 ingress 限速），不是 socket 数量，换 Rust/C 也快不过它：
#   TCP_PACE = 每秒新建连接数（真正节流点，pacer 严格均匀放行，无 burst）
#   TCP_CONC = 同时挂起的连接上限（保险丝；稳态 ≈ PACE x 平均耗时）
# 同 6 万样本阶梯实测存活率：700/s=5.95%（基线）, 1000=5.50%, 1400=3.69%, 2500=1.02%
# → 家宽出口安全上限 ≈ 700；Actions 机房出口质量高，top100.yml 里单独调到 3000。
# 洪峰式 12000 瞬发实测把出口打崩（存活 1199 vs 平滑 29944，全 timeout 无 RST=丢包）。
TCP_PACE = float(os.environ.get("TCP_PACE", "700"))
TCP_CONC = int(os.environ.get("TCP_CONC", "6000"))

# SO_LINGER=0 → close 发 RST 直接释放，不进 TIME_WAIT（默认 120s 占端口，
# 43w 连接会把 16384 端口耗干）。Windows linger 结构 8 字节，POSIX 4 字节。
_LINGER = struct.pack("ii", 1, 0) if os.name == "nt" else struct.pack("hh", 1, 0)

_FAILS = {}   # 失败原因计数：timeout 是死节点常态；OSError errno>0 则是本地端口耗尽要警惕。
              # 多协程并发读写但不用加锁：asyncio 单事件循环里 `d[k] = d.get(k, 0) + 1`
              # 这类赋值语句中间没有 await 点，不可能被其它协程插队（协程只在 await 处让出）。


def _norm(node):
    """规范化 (host, port)；坏数据返回 None 直接跳过。"""
    host, port = node.get("server"), node.get("port")
    if not host:
        return None
    try:
        port = int(str(port).split("/")[0].strip())
    except Exception:  # noqa: BLE001
        return None
    if not (0 < port < 65536):
        return None
    return host, port


async def _probe(host, port):
    """单连接握手测 RTT；成功返回 ms，失败 None。失败按类型计数供事后诊断。"""
    t0 = time.monotonic()
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        rtt = int((time.monotonic() - t0) * 1000)
        try:   # RST 关闭，端口立即复用不进 TIME_WAIT
            s = w.get_extra_info("socket")
            if s is not None:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER)
        except Exception:  # noqa: BLE001
            pass
        w.close()
        try:
            await w.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return rtt
    except asyncio.TimeoutError:
        # 超时的 open_connection 任务已被 wait_for 取消，asyncio 在取消路径里负责关 transport，
        # 无残留句柄；TCP_TIMEOUT=1.5s 的来由见文件头注释（协议活节点 rtt 中位数 955ms，不能降）。
        _FAILS["timeout(超时)"] = _FAILS.get("timeout(超时)", 0) + 1
        return None
    except OSError as e:
        k = f"OSError errno={getattr(e, 'errno', '?')}(本地端口/bind 问题看这里)"
        _FAILS[k] = _FAILS.get(k, 0) + 1
        return None
    except Exception as e:  # noqa: BLE001
        k = type(e).__name__
        _FAILS[k] = _FAILS.get(k, 0) + 1
        return None


class _Pacer:
    """均匀放行新连接：严格按 1/TCP_PACE 间隔发令牌，把「并发数」与「SYN 速率」解耦。
    节流点在建连速率而非 socket 数——出口 pps（conntrack/网卡 tx 队列/上游 NAT/
    对端 ingress）才是丢包源头。"""
    __slots__ = ("iv", "_t")

    def __init__(self, rate):
        self.iv = 1.0 / max(rate, 0.1)
        self._t = time.monotonic()

    async def acquire(self):
        # 不需要锁：asyncio 单事件循环里到 sleep 为止的临界区没有 await 点，
        # 协程只在 await 处让出，天然互斥——原 asyncio.Lock 每次发放都要挂起/唤醒
        # 一串等待者，是纯开销，移除后行为完全一致。
        now = time.monotonic()
        if self._t < now:
            self._t = now      # 追平，不积累令牌（避免攒一波 burst）
        w = self._t - now
        self._t += self.iv
        if w > 0:
            await asyncio.sleep(w)  # sleep 让出事件循环，别的 worker 可继续取令牌


async def _run(pool, alive):
    """恒定并发窗口 + pacer 节流：TCP_CONC 个 worker 持续领任务，每个先等令牌再建连。
    按 (host,port) 聚合——TCP 握手与协议无关，同端口只测一次、结果回填组内全部条目
    （实测池 43.7w → 唯一端点 38.3w，省 12.6% 连接）。"""
    groups = {}
    for node in pool:
        np = _norm(node)
        if np:
            groups.setdefault(np, []).append(node)
    items = list(groups.items())          # [((host, port), [node, ...]), ...]
    total = len(items)
    # 任务发放用游标而不是 asyncio.Queue：取号语句没有 await 点，单事件循环下天然
    # 原子（同 _FAILS 的理由），省掉 38w+ 元素入队的双份引用与 Queue 内部结构。
    nxt = 0
    pacer = _Pacer(TCP_PACE)
    done = 0
    t0 = time.time()
    print(f"asyncio 窗口 {TCP_CONC} + 节流 {TCP_PACE:g} 连接/s，"
          f"唯一端点 {total}（池 {len(pool)} 条目去重回填）", flush=True)

    async def worker():
        nonlocal done, nxt
        while True:
            if nxt >= total:
                return
            (host, port), nodes = items[nxt]
            nxt += 1
            await pacer.acquire()
            rtt = await _probe(host, port)
            if rtt is not None:
                for nd in nodes:
                    alive.append({**nd, "tcp_rtt": rtt})
            done += 1
            if done % 20000 == 0:
                print(f"  TCP {done}/{total} | 存活 {len(alive)} | {time.time()-t0:.0f}s", flush=True)

    await asyncio.gather(*(worker() for _ in range(min(TCP_CONC, total))))
    return total, time.time() - t0


def main():
    if not os.path.exists(POOL):
        print(f"[x] 缺 {POOL}（先跑 top_collect.py）", flush=True)
        return 1
    with open(POOL, encoding="utf-8") as f:
        pool = json.load(f)["nodes"]
    full = len(pool)
    if SAMPLE_CAP and full > SAMPLE_CAP:
        random.seed(42)
        pool = random.sample(pool, SAMPLE_CAP)
    total = len(pool)
    tag = f"抽样 {total}" if total != full else f"全量 {total}"
    print(f"去重池 {full} → {tag}，TCP 粗筛（超时 {TCP_TIMEOUT}s）", flush=True)

    alive = []
    tested, elapsed = asyncio.run(_run(pool, alive))
    alive.sort(key=lambda x: x["tcp_rtt"])
    cands = alive[:TCP_TOP] if TCP_TOP else alive
    payload = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "pool_full": full, "sampled": total,
               "tcp_alive": len(alive), "cands": len(cands), "nodes": cands}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    rate = tested / max(elapsed, 0.001)
    print(f"\n{tag} → TCP 存活 {len(alive)} → {len(cands)} 进协议初筛 → {OUT}", flush=True)
    print(f"耗时 {elapsed:.0f}s（{rate:.0f} 连接/s，线程版上限 667）", flush=True)
    if _FAILS:
        print("失败分布: " + ", ".join(f"{k}={v}" for k, v in
                                       sorted(_FAILS.items(), key=lambda x: -x[1])), flush=True)
    if cands:
        r = [n["tcp_rtt"] for n in cands]
        print(f"tcp_rtt: min={min(r)} med={sorted(r)[len(r)//2]} max={max(r)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
