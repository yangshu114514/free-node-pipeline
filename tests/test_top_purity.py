"""top_purity.py 单元测试 —— 任务清单第 2 项（盲区 G10：_resolve 解析与重试退避）。

覆盖：
  - _resolve：IPv4 透传（不触发 DNS）/ mock getaddrinfo 域名解析 /
    IPv6 字面量透传 / 解析失败回原值 / getaddrinfo 返回空回原值
  - _one_batch 指数退避序列 1.5s → 3s，最后一次失败不再 sleep；
    成功路径的字段映射

所有网络 IO（_session().post / socket.getaddrinfo / 限速器）均 mock，测试不联网。
"""
import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _loader  # noqa: E402


class TestResolve(unittest.TestCase):
    """_resolve：ip-api 只认 IP，域名先解析、坏数据回原值。"""

    def setUp(self):
        self.mod = _loader.load("top_purity")

    def test_IPV4字面量透传且不触发DNS(self):
        with mock.patch.object(self.mod.socket, "getaddrinfo") as ga:
            self.assertEqual(self.mod._resolve("8.8.8.8"), "8.8.8.8")
        ga.assert_not_called()          # 已是 IP，ipaddress 直接放行

    def test_IPV6字面量透传且不触发DNS(self):
        with mock.patch.object(self.mod.socket, "getaddrinfo") as ga:
            self.assertEqual(self.mod._resolve("2001:db8::1"), "2001:db8::1")
        ga.assert_not_called()          # ipaddress 认得 IPv6，不必走 AF_INET 解析

    def test_域名经getaddrinfo解析为A记录(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        with mock.patch.object(self.mod.socket, "getaddrinfo",
                               return_value=fake) as ga:
            self.assertEqual(self.mod._resolve("example.com"), "93.184.216.34")
        ga.assert_called_once_with("example.com", None, socket.AF_INET)

    def test_域名解析失败回原值(self):
        err = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        with mock.patch.object(self.mod.socket, "getaddrinfo", side_effect=err):
            self.assertEqual(self.mod._resolve("dead.example.com"),
                             "dead.example.com")   # 回原值，让 ip-api 报错占位

    def test_getaddrinfo返回空列表回原值(self):
        with mock.patch.object(self.mod.socket, "getaddrinfo", return_value=[]):
            self.assertEqual(self.mod._resolve("weird.example.com"),
                             "weird.example.com")


class TestRetryBackoff(unittest.TestCase):
    """_one_batch：单批失败的指数退避重试（RETRY=2）。"""

    def setUp(self):
        self.mod = _loader.load("top_purity")

    def _run_batch(self, chunk, post):
        """在全 mock 环境下跑一次 _one_batch，返回 (out, sleep_mock, sess)。"""
        sess = mock.Mock()
        sess.post = post
        limit = mock.Mock()            # _LIMIT.acquire 直接放行，不做真实限速
        with mock.patch.object(self.mod, "_session", mock.Mock(return_value=sess)), \
             mock.patch.object(self.mod, "_LIMIT", limit), \
             mock.patch("time.sleep") as sleep_mock:
            out = self.mod._one_batch(chunk)
        return out, sleep_mock, sess

    def test_指数退避序列1点5和3秒且最后一次失败不再sleep(self):
        post = mock.Mock(side_effect=ConnectionError("net down"))
        out, sleep_mock, sess = self._run_batch(["1.2.3.4"], post)
        # RETRY=2 → 共尝试 3 次；退避间隔 1.5×2^0=1.5、1.5×2^1=3.0
        self.assertEqual(sess.post.call_count, 3)
        sleep_mock.assert_has_calls([mock.call(1.5), mock.call(3.0)])
        self.assertEqual(sleep_mock.call_count, 2)   # 最后一次失败后不再 sleep
        # 重试耗尽 → 整批填 err 占位，不抛异常
        self.assertEqual(set(out), {"1.2.3.4"})
        self.assertIsNone(out["1.2.3.4"]["proxy"])
        self.assertIsNone(out["1.2.3.4"]["hosting"])
        self.assertTrue(out["1.2.3.4"]["err"])

    def test_单批成功_字段映射与失败项占位(self):
        resp = mock.Mock(status_code=200)
        resp.json.return_value = [
            {"status": "success", "query": "1.1.1.1", "countryCode": "AU",
             "proxy": False, "hosting": False, "isp": "ISP", "as": "AS1"},
            {"status": "fail", "query": "2.2.2.2", "message": "invalid query"},
        ]
        post = mock.Mock(return_value=resp)
        out, sleep_mock, _ = self._run_batch(["1.1.1.1", "2.2.2.2"], post)
        self.assertEqual(post.call_count, 1)
        sleep_mock.assert_not_called()             # 成功不退避
        self.assertEqual(out["1.1.1.1"]["cc"], "AU")
        self.assertIs(out["1.1.1.1"]["proxy"], False)
        self.assertEqual(out["1.1.1.1"]["as"], "AS1")
        self.assertEqual(out["2.2.2.2"]["err"], "invalid query")
        self.assertEqual(out["2.2.2.2"]["cc"], "")


if __name__ == "__main__":
    unittest.main()
