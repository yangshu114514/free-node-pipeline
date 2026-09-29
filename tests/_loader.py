"""按路径加载 .github/scripts/ 下的单文件脚本。

这些脚本不是包（无 __init__.py、目录带点），无法直接 import；
统一用 importlib.util.spec_from_file_location 按绝对路径加载，
并缓存进 sys.modules（key 前缀 uut_），保证多测试文件共享同一模块实例，
mock.patch.object 的补丁生命周期由各测试的 with 上下文管理。
"""
import importlib.util
import os
import sys

_SCRIPTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 os.pardir, ".github", "scripts"))


def load(name):
    """加载 .github/scripts/<name>.py，返回模块对象（带 sys.modules 缓存）。"""
    key = "uut_" + name
    mod = sys.modules.get(key)
    if mod is not None:
        return mod
    path = os.path.join(_SCRIPTS_DIR, name + ".py")
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法按路径加载脚本: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod
