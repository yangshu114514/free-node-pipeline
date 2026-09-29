#!/usr/bin/env python3
"""Cloudflare KV REST 读写 + CLI（只依赖标准库 urllib）。

规格 A §4.1。环境变量：
  CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN  必填
  CF_KV_NAMESPACE_ID                            必填

CLI（workflow 用）：
  python3 cf_kv.py get <key> [输出文件]
  python3 cf_kv.py put <key> <输入文件>

同时导出函数供其他脚本 import：
  kv_get(key) -> str | None   （404 返回 None）
  kv_put(key, value: str|bytes) -> None
"""
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 30
RETRY = 3


def _request_with_retry(req, method=None, data=None, key=""):
    """对 HTTP 请求做有限重试（代理抖动 / 连接被重置时重试，4xx 不重试）。"""
    last = None
    for i in range(1, RETRY + 1):
        try:
            if method:
                resp = urllib.request.urlopen(req, data=data, timeout=TIMEOUT)
            else:
                resp = urllib.request.urlopen(req, timeout=TIMEOUT)
            return resp
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if e.code == 404:
                return None
            if 400 <= e.code < 500:
                print(f"KV {key} 失败（不重试）: HTTP {e.code} {body[:500]}", file=sys.stderr)
                raise
            last = e
        except Exception as ex:  # noqa: BLE001
            last = ex
            if i < RETRY:
                import time as _t
                _t.sleep(2 * i)
    print(f"KV {key} 重试 {RETRY} 次仍失败: {last}", file=sys.stderr)
    if isinstance(last, urllib.error.HTTPError):
        raise last
    raise RuntimeError(f"KV {key} 网络失败: {last}")


def _account_id():
    acct = os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    if not acct:
        raise RuntimeError("缺 CLOUDFLARE_ACCOUNT_ID 环境变量")
    return acct


def _token():
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        raise RuntimeError("缺 CLOUDFLARE_API_TOKEN 环境变量")
    return token


def _url(key: str) -> str:
    ns = os.environ.get("CF_KV_NAMESPACE_ID")
    if not ns:
        raise RuntimeError("缺 CF_KV_NAMESPACE_ID 环境变量")
    # key 含 ':'（如 top100:nodes）必须 urlencode 成 %3A
    return (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{_account_id()}/storage/kv/namespaces/{ns}/values/{urllib.parse.quote(key, safe='')}"
    )


def kv_get(key: str) -> str | None:
    req = urllib.request.Request(_url(key), headers={"Authorization": f"Bearer {_token()}"})
    resp = _request_with_retry(req, key=key)
    if resp is None:
        return None
    return resp.read().decode("utf-8")


def kv_put(key: str, value: str | bytes) -> None:
    if isinstance(value, str):
        value = value.encode("utf-8")
    req = urllib.request.Request(
        _url(key),
        data=value,
        method="PUT",
        headers={
            "Authorization": f"Bearer {_token()}",
            "Content-Type": "application/octet-stream",
        },
    )
    resp = _request_with_retry(req, method="PUT", key=key)


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("get", "put"):
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    cmd, key = sys.argv[1], sys.argv[2]
    try:
        if cmd == "get":
            val = kv_get(key)
            if val is None:
                print(f"KV 键 {key} 不存在 (404)")
                sys.exit(1)
            if len(sys.argv) >= 4:
                path = sys.argv[3]
                with open(path, "w", encoding="utf-8") as f:
                    f.write(val)
                print(f"已写入 {path} ({len(val)} 字节)")
            else:
                sys.stdout.write(val)
        else:  # put
            src = sys.argv[3]
            with open(src, "rb") as f:
                kv_put(key, f.read())
            print(f"KV 键 {key} 已更新（来源 {src}）")
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')}", file=sys.stderr)
        sys.exit(1)
    except Exception as ex:  # noqa: BLE001
        print(f"KV 操作失败: {ex}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
