"""top_tcp.py 单元测试 —— 任务清单第 4 项（盲区 G12：_norm 端口/地址规范化）。

覆盖 _norm 对坏数据的兜底行为：
  - "443/"（host:port/path 残留）→ 剥路径取 443
  - 0 / 70000（越界端口）→ None 不抛
  - 正常值 → (host, port) 透传
  - 非法字符串 / 缺字段 / 空 host → None 不抛

纯函数测试，无网络、不启动 asyncio 探测。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _loader  # noqa: E402


class TestG12Norm(unittest.TestCase):
    def setUp(self):
        self.mod = _loader.load("top_tcp")
        self.norm = self.mod._norm

    def test_正常端口整数透传(self):
        self.assertEqual(self.norm({"server": "1.2.3.4", "port": 443}),
                         ("1.2.3.4", 443))

    def test_正常端口字符串透传(self):
        self.assertEqual(self.norm({"server": "1.2.3.4", "port": "8443"}),
                         ("1.2.3.4", 8443))

    def test_端口带斜杠路径残留_剥掉斜杠后取端口(self):
        self.assertEqual(self.norm({"server": "1.2.3.4", "port": "443/"}),
                         ("1.2.3.4", 443))
        self.assertEqual(self.norm({"server": "1.2.3.4", "port": "443/http"}),
                         ("1.2.3.4", 443))

    def test_端口0返回None不抛(self):
        self.assertIsNone(self.norm({"server": "1.2.3.4", "port": 0}))

    def test_端口70000返回None不抛(self):
        self.assertIsNone(self.norm({"server": "1.2.3.4", "port": 70000}))

    def test_端口65536返回None不抛(self):
        # 上界开区间：0 < port < 65536，65536 本身越界
        self.assertIsNone(self.norm({"server": "1.2.3.4", "port": 65536}))

    def test_端口65535合法(self):
        self.assertEqual(self.norm({"server": "1.2.3.4", "port": 65535}),
                         ("1.2.3.4", 65535))

    def test_坏数据返回None不抛(self):
        self.assertIsNone(self.norm({"server": "1.2.3.4", "port": "abc"}))
        self.assertIsNone(self.norm({"server": "1.2.3.4", "port": None}))
        self.assertIsNone(self.norm({"server": "", "port": 443}))
        self.assertIsNone(self.norm({"server": None, "port": 443}))
        self.assertIsNone(self.norm({}))          # 双缺字段也不抛
        self.assertIsNone(self.norm({"port": 443}))


if __name__ == "__main__":
    unittest.main()
