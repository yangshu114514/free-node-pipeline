"""top_select.py 单元测试 —— 任务清单第 1 项（盲区 G9：写 KV 三重闸 + 档内密度配额）。

覆盖：
  - 选中数 < MIN_TOP → 拒写 KV（put_kv 零调用）且 exit 非 0
  - 较上轮跌幅 > 50% → 拒写 KV 且 exit 非 0
  - 正常数据 → exit 0 且 put_kv 恰好一次
  - put_kv 返回失败 / 抛异常 → exit 非 0
  - 密度配额：同 server ≤3、同 AS ≤8

所有网络 IO（put_kv / prev_selected）均 mock，测试不联网。
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

# 写 KV 需要的三元 env；patch.dict 只覆盖这三键，不破坏其余环境
_ENV = {"CLOUDFLARE_API_TOKEN": "test-token",
        "CF_ACCOUNT_ID": "test-account",
        "CF_KV_NAMESPACE_ID": "test-ns"}


def make_nodes(n, start=0, **over):
    """构造 n 个能通过「非中 + delay ≤ DELAY_CAP」门槛的候选节点。

    默认 server/as/ident 逐个唯一（不触发密度配额）；
    over 覆盖指定字段即可构造同 server / 同 AS 的刷屏场景。
    """
    out = []
    for i in range(start, start + n):
        d = {"proto": "vless", "server": f"srv-{i}", "port": 443,
             "ident": f"id-{i}", "geo": "US", "delay": 100,
             "is_proxy": False, "is_hosting": False, "as": f"AS-{i}",
             "raw": "vless://raw"}
        d.update(over)
        out.append(d)
    return out


class TopSelectGateBase(unittest.TestCase):
    """公共执行器：临时 purity.json + mock 网络函数 + 捕获产出文件。"""

    def _run(self, nodes, prev=None, put_result=(True, "ok"), put_exc=None):
        mod = _loader.load("top_select")
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            p_in = os.path.join(td, "purity.json")
            with open(p_in, "w", encoding="utf-8") as f:
                json.dump({"nodes": nodes}, f, ensure_ascii=False)
            p_detail = os.path.join(td, "top100_detail.json")
            p_summary = os.path.join(td, "top100_summary.json")
            put = mock.Mock(return_value=put_result)
            if put_exc is not None:
                put.side_effect = put_exc
            prev_mock = mock.Mock(return_value=prev)
            with mock.patch.object(mod, "IN", p_in), \
                 mock.patch.object(mod, "DETAIL", p_detail), \
                 mock.patch.object(mod, "SUMMARY", p_summary), \
                 mock.patch.object(mod, "prev_selected", prev_mock), \
                 mock.patch.object(mod, "put_kv", put), \
                 mock.patch.dict(os.environ, _ENV), \
                 contextlib.redirect_stdout(buf):
                rc = mod.main()
            detail = self._read(p_detail)
            summary = self._read(p_summary)
        return {"rc": rc, "put": put, "prev": prev_mock, "detail": detail,
                "summary": summary, "out": buf.getvalue()}

    @staticmethod
    def _read(path):
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)


class TestG9Gates(TopSelectGateBase):
    """G9：写 KV 前的空数据闸 / 骤降闸 / 写失败处理。"""

    def test_选中不足MIN_TOP拒写KV且退出非0(self):
        # 10 个合格节点 < MIN_TOP(30) → 塌方闸命中
        r = self._run(make_nodes(10), prev=None)
        self.assertNotEqual(r["rc"], 0)            # exit 非 0
        r["put"].assert_not_called()               # put_kv 零调用
        self.assertEqual(r["prev"].call_count, 0)   # 闸1命中不再读上轮
        self.assertFalse(r["summary"]["kv_written"])
        self.assertIn("空数据门槛", r["summary"]["gate"])
        self.assertIn("拒写 KV", r["out"])
        # 摘要/明细仍无条件落盘供诊断
        self.assertIsNotNone(r["detail"])
        self.assertIsNotNone(r["summary"])

    def test_跌幅超50pct拒写KV且退出非0(self):
        # 40 ≥ MIN_TOP(30) 不触发闸1；上轮 100 → 40 < 100×0.5 触发骤降闸
        r = self._run(make_nodes(40), prev=100)
        self.assertNotEqual(r["rc"], 0)            # exit 非 0
        r["put"].assert_not_called()               # put_kv 零调用
        self.assertEqual(r["prev"].call_count, 1)   # 走到了读上轮 selected
        self.assertFalse(r["summary"]["kv_written"])
        self.assertIn("跌幅", r["summary"]["gate"])
        self.assertIn("50%", r["summary"]["gate"])

    def test_上轮读不到时跳过骤降保护不误伤(self):
        # prev_selected 返回 None（404/网络/env 缺）→ 无从比较则不拦，正常写
        r = self._run(make_nodes(40), prev=None)
        self.assertEqual(r["rc"], 0)
        self.assertEqual(r["put"].call_count, 1)
        self.assertNotIn("gate", r["summary"])

    def test_正常数据写KV恰一次且退出0(self):
        r = self._run(make_nodes(120), prev=50)
        self.assertEqual(r["rc"], 0)               # exit 0
        self.assertEqual(r["put"].call_count, 1)   # put_kv 恰好一次
        args = r["put"].call_args.args             # put_kv(ns, acc, token, key, value)
        self.assertEqual(args[0], _ENV["CF_KV_NAMESPACE_ID"])
        self.assertEqual(args[3], "top100:nodes")
        self.assertEqual(len(json.loads(args[4])), 100)   # TOP_N 截断
        self.assertTrue(r["summary"]["kv_written"])
        self.assertNotIn("gate", r["summary"])

    def test_put_kv返回失败退出非0(self):
        r = self._run(make_nodes(40), prev=None, put_result=(False, "boom"))
        self.assertNotEqual(r["rc"], 0)            # 写失败 → exit 非 0
        self.assertEqual(r["put"].call_count, 1)
        self.assertFalse(r["summary"]["kv_written"])
        self.assertIn("写 KV", r["out"])

    def test_put_kv抛异常向外传播进程退出非0(self):
        # main 不捕获 put_kv 异常 → 异常穿透到脚本入口 → 进程以非 0 退出码终止
        with self.assertRaises(RuntimeError):
            self._run(make_nodes(40), prev=None, put_exc=RuntimeError("boom"))


class TestG9Quota(TopSelectGateBase):
    """G9 附：档内密度配额（同 server ≤3、同 AS ≤8）。"""

    def test_同server最多入榜3个(self):
        # 60 个同 server「srvA」打头 + 60 个唯一节点；候选 120，贪心选中 63
        # （as 是 Python 关键字，覆盖该字段只能走字典展开）
        nodes = (make_nodes(60, **{"server": "srvA", "as": "AS-A"})
                 + make_nodes(60, start=500))
        r = self._run(nodes, prev=None)
        self.assertEqual(r["rc"], 0)               # 63 ≥ MIN_TOP，正常写
        self.assertEqual(r["put"].call_count, 1)
        cnt_srv, cnt_as = {}, {}
        for n in r["detail"]:
            cnt_srv[n["server"]] = cnt_srv.get(n["server"], 0) + 1
            cnt_as[n["as"]] = cnt_as.get(n["as"], 0) + 1
        self.assertEqual(cnt_srv.get("srvA"), 3)   # 同 server 恰好卡在 3
        self.assertEqual(max(cnt_srv.values()), 3)
        self.assertLessEqual(cnt_as.get("AS-A"), 8)
        self.assertEqual(len(r["detail"]), 63)     # 3（srvA）+ 60（唯一）全入

    def test_同AS最多入榜8个(self):
        # 30 个 server 各异但同 AS「ASBIG」打头 + 80 个唯一节点
        nodes = make_nodes(30, **{"as": "ASBIG"}) + make_nodes(80, start=700)
        r = self._run(nodes, prev=None)
        self.assertEqual(r["rc"], 0)
        cnt_srv, cnt_as = {}, {}
        for n in r["detail"]:
            cnt_srv[n["server"]] = cnt_srv.get(n["server"], 0) + 1
            cnt_as[n["as"]] = cnt_as.get(n["as"], 0) + 1
        self.assertEqual(cnt_as.get("ASBIG"), 8)   # 同 AS 恰好卡在 8
        self.assertLessEqual(max(cnt_as.values()), 8)
        self.assertLessEqual(max(cnt_srv.values()), 3)
        self.assertEqual(len(r["detail"]), 88)     # 8（ASBIG）+ 80（唯一）全入


if __name__ == "__main__":
    unittest.main()
