"""cf_kv.py 单元测试 —— 任务清单第 5 项（盲区 G13：显式 urllib.error 导入 / 缺 env 失败）。

覆盖：
  - 源码显式 `import urllib.error` 存在性（_request_with_retry 的 except 分支依赖）
  - 缺任一必填 env → RuntimeError（直接调用，抛在建连之前）
  - 缺 env 时 CLI 子进程退出码非 0（subprocess 验证）

子进程与直调都在 urlopen 之前抛错，测试不联网。
"""
import os
import pathlib
import subprocess
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _loader  # noqa: E402

_ENV_KEYS = ("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN", "CF_KV_NAMESPACE_ID")


class TestG13UrllibErrorImport(unittest.TestCase):
    def test_源码显式导入urllib_error且模块内可寻址(self):
        mod = _loader.load("cf_kv")
        src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
        # 源码必须显式 `import urllib.error`（_request_with_retry 用它做 except 分支）
        self.assertIn("import urllib.error", src)
        # 运行期 urllib.error 可寻址且就是标准库那个
        self.assertIs(mod.urllib.error, urllib.error)
        self.assertTrue(hasattr(mod.urllib.error, "HTTPError"))
        self.assertTrue(hasattr(mod.urllib.error, "URLError"))


class TestG13MissingEnv(unittest.TestCase):
    def setUp(self):
        self.mod = _loader.load("cf_kv")

    def test_全部env缺失_直调各入口抛RuntimeError(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                self.mod._account_id()
            with self.assertRaises(RuntimeError):
                self.mod._token()
            with self.assertRaises(RuntimeError):
                self.mod._url("k")
            # kv_get/kv_put 在构造 Request（发请求之前）就抛
            with self.assertRaises(RuntimeError):
                self.mod.kv_get("k")
            with self.assertRaises(RuntimeError):
                self.mod.kv_put("k", "v")

    def test_缺CF_KV_NAMESPACE_ID_报对应变量名(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as cm:
                self.mod._url("k")
        self.assertIn("CF_KV_NAMESPACE_ID", str(cm.exception))

    def test_缺API_TOKEN_报对应变量名且不联网(self):
        # account/ns 齐、只缺 token → _url 通过，_token() 在建连前抛
        env = {"CLOUDFLARE_ACCOUNT_ID": "acc", "CF_KV_NAMESPACE_ID": "ns"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(
                    self.mod.urllib.request, "urlopen") as urlopen:  # 兜底：绝不许真联网
                with self.assertRaises(RuntimeError) as cm:
                    self.mod.kv_get("k")
            urlopen.assert_not_called()
        self.assertIn("CLOUDFLARE_API_TOKEN", str(cm.exception))

    def test_缺env时CLI子进程退出码非0(self):
        env = os.environ.copy()
        for k in _ENV_KEYS:
            env.pop(k, None)
        env["PYTHONIOENCODING"] = "utf-8"   # 断言中文输出前统一子进程编码
        p = subprocess.run(
            [sys.executable, self.mod.__file__, "get", "some-key"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, timeout=60, cwd=os.path.dirname(self.mod.__file__))
        self.assertNotEqual(p.returncode, 0)          # 缺 env → exit 非 0
        self.assertIn("KV 操作失败", p.stderr)          # 走 main 的统一异常兜底
        self.assertIn("CF_KV_NAMESPACE_ID", p.stderr)  # 报出真正缺的变量


if __name__ == "__main__":
    unittest.main()
