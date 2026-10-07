"""
JWT 认证技术库 —— 安全核心模块

职责：
1. 令牌创建（access / refresh）与校验（解码、过期判断、类型校验）
2. 密码哈希与校验（基于 passlib + bcrypt，替代原项目的明文存储）

与原始项目 auth/services.py 的对应关系：
- SECRET_KEY / ALGORITHM / ACCESS_TOKEN_EXPIRE_MINUTES  ->  JWTSettings
- create_token()                                          ->  create_access_token() / create_refresh_token()
- 新增：decode_token() / verify_password() / hash_password()
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import JWTSettings

# 密码哈希上下文：bcrypt 是当前推荐方案（原项目为明文存储，本库默认启用哈希）
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# 密码哈希
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """对明文密码做 bcrypt 哈希，返回可直接入库的密文。"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """校验明文密码与库中密文是否匹配。"""
    return pwd_context.verify(plain_password, hashed_password)


# ---------------------------------------------------------------------------
# 令牌创建
# ---------------------------------------------------------------------------
def _create_token(
    data: dict,
    settings: JWTSettings,
    expires_delta: timedelta,
    token_type: str,
) -> str:
    """内部统一令牌生成：载荷 = 业务数据 + 过期时间 + 令牌类型。"""
    to_encode = dict(data)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update(
        {
            "exp": expire,
            settings.token_type_field: token_type,
        }
    )
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_access_token(
    data: dict,
    settings: JWTSettings,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    创建访问令牌（access token）。

    参数:
        data: 业务载荷，如 {"sub": "username"}。sub 为标准用户标识字段。
        settings: JWT 配置。
        expires_delta: 自定义有效期；缺省使用配置的 access_token_expire_minutes。

    兼容原始项目 create_token(data, expires_delta) 的调用方式。
    """
    delta = expires_delta or settings.access_token_expire_delta
    return _create_token(data, settings, delta, token_type="access")


def create_refresh_token(
    data: dict,
    settings: JWTSettings,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """创建刷新令牌（refresh token），有效期默认按 refresh_token_expire_days。"""
    delta = expires_delta or settings.refresh_token_expire_delta
    return _create_token(data, settings, delta, token_type="refresh")


# ---------------------------------------------------------------------------
# 令牌校验
# ---------------------------------------------------------------------------
def decode_token(token: str, settings: JWTSettings) -> dict:
    """
    解码并校验令牌。

    校验项：签名、算法、exp 过期时间。
    失败（签名错误 / 已过期 / 被篡改）统一抛 JWTError，由调用方（依赖层）转为 401。
    """
    payload = jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.algorithm],
    )
    return payload


def get_subject(token: str, settings: JWTSettings) -> Optional[str]:
    """从令牌中提取用户标识（sub），校验失败或缺失返回 None。"""
    try:
        payload = decode_token(token, settings)
    except JWTError:
        return None
    subject = payload.get(settings.subject_field)
    return subject if isinstance(subject, str) else None


def is_token_of_type(payload: dict, token_type: str, settings: JWTSettings) -> bool:
    """校验令牌类型（防止拿 refresh token 当 access token 用）。"""
    return payload.get(settings.token_type_field) == token_type
