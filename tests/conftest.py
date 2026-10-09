# -*- coding: utf-8 -*-
"""
技术库测试路径注入（conftest.py）
==================================

jwt_auth 包实体位于项目根（jwt_auth_lib 的同级），而 pytest 以
jwt_auth_lib 为根目录收集测试，sys.path 不含项目根 —— 不注入则
tests/*.py 顶层 `from jwt_auth import ...` 全部 ModuleNotFoundError。
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]  # jwt_auth_lib/tests -> 项目根
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
