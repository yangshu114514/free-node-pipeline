"""top_proto.py 单元测试 —— 任务清单第 3 项（盲区 G11：等距抽样 / 分片 / ALIVE_FLOOR）。

覆盖：
  - main 里按 tcp_rtt 的等距抽样：n 与 PROTO_MAX，无越界、无重复索引
  - 分片 [i::n_shards]：余数均分、无空片、索引覆盖完整
  - ALIVE_FLOOR 闸门：协议筛后不足 100 → exit 非 0（回退分支与正常分支都拦）
  - 出口证书自证：https 目标稳定 fail → 剔除；复测通过（抖动）→ 不剔

协议测的外部依赖（mihomo 进程 / wait_ready / delay_one / network）全部 mock，
测试不联网、不启真实 mihomo。
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _loader  # noqa: E402

_UUID = "11111111-2222-3333-4444-555555555555"


def make_cands(n):
    """构造 n 个 TCP 候选（idx 用于反查等距抽样命中的原始下标）。"""
    return [{"idx": i, "proto": "vless", "server": f"10.0.0.{i % 250}",
             "port": 443, "tcp_rtt": i, "ident": f"id-{i}"}
            for i in range(n)]


class ProtoMainBase(unittest.TestCase):
    """公共执行器：临时 tcp_cands.json + mock protocol_probe + 读回 latency.json。"""

    def _run_main(self, cands, probe):
        mod = _loader.load("top_proto")
        with tempfile.TemporaryDirectory() as td:
            p_cands = os.path.join(td, "tcp_cands.json")
            with open(p_cands, "w", encoding="utf-8") as f:
                json.dump({"nodes": cands}, f)
            p_out = os.path.join(td, "latency.json")
            with mock.patch.object(mod, "CANDS", p_cands), \
                 mock.patch.object(mod, "OUT", p_out), \
                 mock.patch.object(mod, "protocol_probe", probe), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = mod.main()
            payload = None
            if os.path.exists(p_out):
                with open(p_out, encoding="utf-8") as f:
                    payload = json.load(f)
        return rc, payload


class TestG11EquidistantSample(ProtoMainBase):
    """G11a：PROTO_MAX 等距抽样（main 内联逻辑）。"""

    def test_等距抽样_无越界无重复且回退后不足下限拒交付(self):
        captured = {}

        def probe(cs):                     # 协议测不可用 → main 走 TCP-only 回退
            captured["c"] = list(cs)
            return None, [], {}, set()

        mod = _loader.load("top_proto")
        with tempfile.TemporaryDirectory() as td:
            p_cands = os.path.join(td, "tcp_cands.json")
            with open(p_cands, "w", encoding="utf-8") as f:
                json.dump({"nodes": make_cands(25)}, f)
            p_out = os.path.join(td, "latency.json")
            with mock.patch.object(mod, "CANDS", p_cands), \
                 mock.patch.object(mod, "OUT", p_out), \
                 mock.patch.object(mod, "PROTO_MAX", 10), \
                 mock.patch.object(mod, "protocol_probe", probe), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = mod.main()
            with open(p_out, encoding="utf-8") as f:
                payload = json.load(f)

        ids = [n["idx"] for n in captured["c"]]
        self.assertEqual(len(ids), 10)                  # 截断到 PROTO_MAX
        self.assertEqual(len(set(ids)), 10)             # 无重复索引
        self.assertTrue(all(0 <= i < 25 for i in ids))  # 无越界
        # 等距语义：step = n / PROTO_MAX = 2.5，取 int(i * step)
        self.assertEqual(ids, [int(i * 2.5) for i in range(10)])
        # 回退分支交付 10 个 < ALIVE_FLOOR(100) → 拒交付；文件仍落盘供诊断
        self.assertNotEqual(rc, 0)
        self.assertEqual(payload["selected"], 10)
        self.assertFalse(payload["proto_filter"])

    def test_输入不超过PROTO_MAX时不抽样(self):
        captured = {}

        def probe(cs):
            captured["c"] = list(cs)
            return None, [], {}, set()

        mod = _loader.load("top_proto")
        with tempfile.TemporaryDirectory() as td:
            p_cands = os.path.join(td, "tcp_cands.json")
            with open(p_cands, "w", encoding="utf-8") as f:
                json.dump({"nodes": make_cands(25)}, f)
            with mock.patch.object(mod, "CANDS", p_cands), \
                 mock.patch.object(mod, "OUT", os.path.join(td, "latency.json")), \
                 mock.patch.object(mod, "PROTO_MAX", 100), \
                 mock.patch.object(mod, "protocol_probe", probe), \
                 contextlib.redirect_stdout(io.StringIO()):
                mod.main()
        self.assertEqual([n["idx"] for n in captured["c"]], list(range(25)))


class TestG11AliveFloor(ProtoMainBase):
    """G11b：ALIVE_FLOOR=100 交付下限闸门。"""

    @staticmethod
    def _all_alive_probe(cs):
        # 每个候选协议测全活，delay=100+i（按枚举序）；出口自证无人被剔
        return ({f"n{i}": 100 + i for i in range(len(cs))}, list(cs), {}, set())

    def test_协议活不足100_正常分支退出非0(self):
        rc, payload = self._run_main(make_cands(50), self._all_alive_probe)
        self.assertNotEqual(rc, 0)          # 50 < 100 → 拒交付
        self.assertEqual(payload["selected"], 50)
        self.assertTrue(payload["proto_filter"])
        # 文件已落盘供诊断（不因闸门丢弃）
        self.assertEqual(len(payload["nodes"]), 50)

    def test_协议活恰好ALIVE_FLOOR_退出0且按delay升序(self):
        # 100 个协议活 == ALIVE_FLOOR(100)：边界值不拦（闸门是 < 才拦）
        rc, payload = self._run_main(make_cands(100), self._all_alive_probe)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["selected"], 100)
        delays = [n["delay"] for n in payload["nodes"]]
        self.assertEqual(delays, sorted(delays))    # 按协议 delay 升序
        self.assertEqual(delays[0], 100)
        self.assertTrue(all(n["proto_ok"] for n in payload["nodes"]))

    def test_协议活充足_退出0且全量入榜(self):
        # TOP_N=1000：150 个活节点全入（未触顶），仍 ≥ ALIVE_FLOOR → 放行
        rc, payload = self._run_main(make_cands(150), self._all_alive_probe)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["selected"], 150)
        self.assertEqual(len(payload["nodes"]), 150)


class TestG11Sharding(unittest.TestCase):
    """G11c：protocol_probe 的 [i::n_shards] 分片——余数均分、无空片。"""

    def test_10节点分4片_余数均分无空片无遗漏(self):
        mod = _loader.load("top_proto")
        cands = [{"raw": f"vless://{_UUID}@10.0.0.{i}:443?type=tcp&security=tls",
                  "proto": "vless", "server": f"10.0.0.{i}", "port": 443,
                  "ident": "id"} for i in range(10)]
        shard_sizes = []          # 记录每片收到的 yaml 数（test_and_prune 是分片切面）

        def fake_prune(mihomo, cfgp, port, s_yamls, s_names, sub, cap=60):
            shard_sizes.append((port, len(s_yamls)))

        class FakeProc:
            def poll(self):
                return None

            def terminate(self):
                pass

            def kill(self):
                pass

        with mock.patch.object(mod, "SHARDS", 4), \
             mock.patch.object(mod, "find_mihomo", lambda: sys.executable), \
             mock.patch.object(mod, "test_and_prune", fake_prune), \
             mock.patch.object(mod, "wait_ready",
                               lambda port, timeout=60: True), \
             mock.patch.object(mod, "delay_one",
                               lambda name, port, url=None: (50, "")), \
             mock.patch.object(mod.subprocess, "Popen",
                               lambda *a, **k: FakeProc()), \
             mock.patch("time.sleep"), \
             contextlib.redirect_stdout(io.StringIO()):
            results, valid, fails, hijacked = mod.protocol_probe(cands)

        sizes = [s for _, s in shard_sizes]
        self.assertEqual(len(sizes), 4)                   # min(SHARDS, 10) = 4 片
        self.assertEqual(sorted(sizes), [2, 2, 3, 3])     # 余数均分（差 ≤1）
        self.assertEqual(sum(sizes), 10)                  # 索引覆盖完整无遗漏
        self.assertTrue(all(s > 0 for s in sizes))        # 无空片
        self.assertEqual(sorted(p for p, _ in shard_sizes),
                         [9097, 9098, 9099, 9100])        # 分片端口不重叠
        # 下游结果完整：10 个节点全拿到 delay，valid 全量回传、无失败统计
        self.assertEqual(len(results), 10)
        self.assertTrue(all(v == 50 for v in results.values()))
        self.assertEqual(len(valid), 10)
        self.assertEqual(fails, {})
        self.assertEqual(hijacked, set())      # 全干净 → 出口自证无人被剔

    def test_SHARDS大于节点数时退化为单片不产生空片(self):
        mod = _loader.load("top_proto")
        cands = [{"raw": f"vless://{_UUID}@10.0.1.{i}:443?type=tcp&security=tls",
                  "proto": "vless", "server": f"10.0.1.{i}", "port": 443}
                 for i in range(3)]
        shard_sizes = []

        def fake_prune(mihomo, cfgp, port, s_yamls, s_names, sub, cap=60):
            shard_sizes.append(len(s_yamls))

        class FakeProc:
            def poll(self):
                return None

            def terminate(self):
                pass

            def kill(self):
                pass

        with mock.patch.object(mod, "SHARDS", 8), \
             mock.patch.object(mod, "find_mihomo", lambda: sys.executable), \
             mock.patch.object(mod, "test_and_prune", fake_prune), \
             mock.patch.object(mod, "wait_ready",
                               lambda port, timeout=60: True), \
             mock.patch.object(mod, "delay_one",
                               lambda name, port, url=None: (50, "")), \
             mock.patch.object(mod.subprocess, "Popen",
                               lambda *a, **k: FakeProc()), \
             mock.patch("time.sleep"), \
             contextlib.redirect_stdout(io.StringIO()):
            results, valid, _, hijacked = mod.protocol_probe(cands)
        # n_shards = max(1, min(8, 3)) = 3 → range(3)[i::3] 每片恰好 1 个，无空片
        self.assertEqual(len(shard_sizes), 3)
        self.assertEqual(shard_sizes, [1, 1, 1])
        self.assertEqual(len(results), 3)


class TestCertKick(unittest.TestCase):
    """出口证书自证（CERT_URLS）：假证书出口剔除、首败复测过的抖动不剔、timeout 豁免不踢。

    delay_one 被 mock：url=None/测速目标 → 协议测全活；https 自证目标按脚本分派——
    n2 对 chatgpt 恒 fail 确定性握手错（模拟出口 MITM 假证书）、n3 对 cloudflare
    首败复测过（模拟偶发抖动）、n4 对 cloudflare 恒 Timeout（网络抖动非证书错，
    豁免不踢）、其余全过。"""

    def _run_probe(self):
        mod = _loader.load("top_proto")
        cands = [{"raw": f"vless://{_UUID}@10.0.2.{i}:443?type=tcp&security=tls",
                  "proto": "vless", "server": f"10.0.2.{i}", "port": 443,
                  "ident": "id"} for i in range(6)]
        seen = {}                       # (name, url) → 第几次调用，驱动首败复测语义

        def fake_delay(name, port, url=None):
            if url is None or url == mod.DELAY_URL:
                return 50, ""           # 协议测速阶段：全活
            k = (name, url)
            seen[k] = seen.get(k, 0) + 1
            if name == "n2" and "chatgpt" in url:
                return 0, "An error occurred in the delay test"   # 稳定握手错 → 踢
            if name == "n3" and "cloudflare" in url and seen[k] == 1:
                return 0, "An error occurred in the delay test"   # 首败复测过 → 不剔
            if name == "n4" and "cloudflare" in url:
                return 0, "Timeout"     # 超时抖动：豁免不踢
            return 300, ""

        class FakeProc:
            def poll(self):
                return None

            def terminate(self):
                pass

            def kill(self):
                pass

        with mock.patch.object(mod, "SHARDS", 3), \
             mock.patch.object(mod, "find_mihomo", lambda: sys.executable), \
             mock.patch.object(mod, "test_and_prune",
                               lambda m, c, p, ys, ns, s, cap=60: None), \
             mock.patch.object(mod, "wait_ready",
                               lambda port, timeout=60: True), \
             mock.patch.object(mod, "delay_one", fake_delay), \
             mock.patch.object(mod.subprocess, "Popen",
                               lambda *a, **k: FakeProc()), \
             mock.patch("time.sleep"), \
             contextlib.redirect_stdout(io.StringIO()) as buf:
            out = mod.protocol_probe(cands)
        return out, buf.getvalue()

    def test_稳定假证书出口被剔除且计为hijacked(self):
        (results, valid, fails, hijacked), _log = self._run_probe()
        self.assertEqual(hijacked, {"n2"})
        self.assertEqual(results["n2"], 0)             # 从协议活剔除，下游收不到
        self.assertEqual(len(valid), 6)                # valid 不变（只是延迟置 0）
        # 其余 5 个不受影响
        self.assertTrue(all(results[f"n{i}"] == 50
                            for i in range(6) if i != 2))

    def test_首败复测通过的抖动不剔(self):
        (results, _valid, _fails, hijacked), _log = self._run_probe()
        self.assertNotIn("n3", hijacked)               # cloudflare 首败复测过
        self.assertEqual(results["n3"], 50)

    def test_timeout恒失败豁免不踢(self):
        (results, _valid, _fails, hijacked), log = self._run_probe()
        self.assertNotIn("n4", hijacked)               # Timeout = 抖动非证书错
        self.assertEqual(results["n4"], 50)
        self.assertIn("timeout 豁免", log)             # 日志记录豁免数

    def test_自证剔除日志与payload计数一致(self):
        (results, valid, _fails, hijacked), log = self._run_probe()
        self.assertIn("出口自证", log)
        # main 的 payload.cert_kicked 取 len(hijacked)（此处直验语义来源）
        self.assertEqual(len(hijacked), 1)
        self.assertEqual(results["n2"], 0)


if __name__ == "__main__":
    unittest.main()
