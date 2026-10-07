"""
JWT 认证技术库 —— 数据模型模块（Pydantic）

与原始项目 auth/schemas.py 的对应关系：
- LoginMessage   ->  LoginRequest（登录请求）
- Token          ->  TokenResponse（令牌响应）
- 新增：RefreshRequest（刷新请求）、TokenPayload（解码后的载荷）
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class LoginRequest(BaseModel):
    """登录请求体：用户名 + 密码。"""
    username: str
    password: str


class TokenResponse(BaseModel):
    """令牌响应：访问令牌 + 令牌类型 + 有效期（秒）。"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # 有效期（秒）


class RefreshRequest(BaseModel):
    """刷新令牌请求体。"""
    refresh_token: str


class TokenPayload(BaseModel):
    """解码后的令牌载荷（业务层可继续扩展字段）。"""
    sub: str  # 用户标识
    exp: Optional[int] = None  # 过期时间（Unix 时间戳）
    type: Optional[str] = None  # access / refresh

    @property
    def is_access(self) -> bool:
        return self.type == "access"
