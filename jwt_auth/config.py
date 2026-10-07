"""
JWT 认证技术库 —— 配置模块

所有可调参数集中于此，支持通过环境变量覆盖（生产环境建议通过环境变量注入密钥）。
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class JWTSettings:
    # ---- 令牌核心参数 ----
    # 生产环境务必通过环境变量 JWT_SECRET_KEY 注入固定密钥；
    # 未注入时自动生成随机密钥（进程重启后失效，仅适合开发/演示）。
    secret_key: str = field(
        default_factory=lambda: os.getenv("JWT_SECRET_KEY") or secrets.token_hex(32)
    )
    algorithm: str = "HS256"  # 加密算法
    access_token_expire_minutes: int = 60  # 访问令牌有效期（分钟）
    refresh_token_expire_days: int = 7  # 刷新令牌有效期（天）
    token_type: str = "bearer"  # 令牌类型

    # ---- Cookie 相关参数（兼容原项目"登录后写 HttpOnly Cookie"的做法）----
    cookie_key: str = "access_token"  # Cookie 名
    cookie_httponly: bool = True  # 禁止 JS 读取，防 XSS 窃取
    cookie_secure: bool = False  # 仅 HTTPS 下传输；生产环境置 True
    cookie_samesite: str = "lax"  # CSRF 防护：lax / strict / none

    # ---- 令牌载荷字段 ----
    subject_field: str = "sub"  # 承载用户标识的字段名（JWT 标准为 sub）
    token_type_field: str = "type"  # 区分 access / refresh 的字段名

    # ---- 便捷属性 ----
    @property
    def access_token_expire_delta(self) -> timedelta:
        return timedelta(minutes=self.access_token_expire_minutes)

    @property
    def refresh_token_expire_delta(self) -> timedelta:
        return timedelta(days=self.refresh_token_expire_days)
