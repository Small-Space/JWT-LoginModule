"""
JWT 认证技术库 —— 依赖注入模块（FastAPI 认证依赖）

与原始项目 auth/routers.py 的对应关系：
- oauth2_scheme（OAuth2PasswordBearer）            ->  create_auth_deps 内部的 oauth2_scheme
- protected_route（header/cookie 双通道 + 解码校验） ->  get_current_identity / get_current_user

核心设计（解耦点）：
- 本库【不依赖任何业务模型】。用户查询函数由调用方注入（见 get_current_user）。
- 令牌提取支持双通道：Authorization: Bearer <token> 优先，缺失时回退读取 HttpOnly Cookie。
- 校验失败统一返回 HTTP 401。
"""
from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from .config import JWTSettings
from .schemas import TokenPayload
from .security import decode_token


class AuthDeps:
    """一组可注入的认证依赖（由 create_auth_deps 工厂构建）。"""

    def __init__(
        self,
        settings: JWTSettings,
        oauth2_scheme: OAuth2PasswordBearer,
        get_token: Callable,
        get_current_identity: Callable,
        get_current_user: Callable,
    ):
        self.settings = settings
        self.oauth2_scheme = oauth2_scheme
        # FastAPI 依赖函数（闭包，已绑定本实例的配置）
        self.get_token = get_token
        self.get_current_identity = get_current_identity
        self.get_current_user = get_current_user


def create_auth_deps(
    settings: Optional[JWTSettings] = None,
    token_url: str = "/auth/login",
) -> AuthDeps:
    """
    创建认证依赖工厂（闭包模式，保证每个实例绑定自己的配置与 OAuth2 方案）。

    参数:
        settings: JWT 配置；缺省使用 JWTSettings()（自动生成随机密钥，仅适合开发）。
        token_url: OAuth2 密码流文档地址（Swagger "Authorize" 按钮使用）。
    """
    settings = settings or JWTSettings()
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl=token_url, auto_error=False)

    # ------------------------------------------------------------------
    # 令牌解码 + 类型校验（仅放行 access 令牌）
    # ------------------------------------------------------------------
    def _verify_access_token(token: str) -> dict:
        try:
            payload = decode_token(token, settings)
        except JWTError:
            raise HTTPException(status_code=401, detail="无效的令牌") from None
        sub = payload.get(settings.subject_field)
        if not isinstance(sub, str) or not sub:
            raise HTTPException(status_code=401, detail="无效的令牌")
        if payload.get(settings.token_type_field) != "access":
            raise HTTPException(status_code=401, detail="令牌类型无效")
        return payload

    # ------------------------------------------------------------------
    # 令牌提取：Authorization Header 优先，其次 HttpOnly Cookie
    # ------------------------------------------------------------------
    def get_token(request: Request, token: Optional[str] = Depends(oauth2_scheme)) -> str:
        token = token or request.cookies.get(settings.cookie_key)
        if not token:
            raise HTTPException(status_code=401, detail="未提供令牌")
        return token

    # ------------------------------------------------------------------
    # 校验并返回身份标识（轻量，不查数据库）
    # 等价于原项目 protected_route；返回 TokenPayload 而非 {"username": ...}
    # ------------------------------------------------------------------
    def get_current_identity(token: str = Depends(get_token)) -> TokenPayload:
        payload = _verify_access_token(token)
        return TokenPayload(
            sub=payload[settings.subject_field],
            exp=payload.get("exp"),
            type=payload.get(settings.token_type_field),
        )

    # ------------------------------------------------------------------
    # 校验并返回完整用户对象（业务注入用户查询函数）
    # 用法：Depends(auth_deps.get_current_user(get_user_by_name))
    # get_user: Callable[[str], Awaitable[Any] | Any] —— 通过用户标识 sub 查询用户
    # ------------------------------------------------------------------
    def get_current_user(get_user: Callable[[str], Awaitable[Any] | Any]):
        async def dependency(token: str = Depends(get_token)) -> Any:
            payload = _verify_access_token(token)
            sub: str = payload[settings.subject_field]

            user = get_user(sub)
            if inspect.isawaitable(user):  # 兼容 async / sync 查询函数
                user = await user
            if user is None:
                raise HTTPException(status_code=401, detail="用户不存在或已被禁用")
            return user

        return dependency

    return AuthDeps(
        settings=settings,
        oauth2_scheme=oauth2_scheme,
        get_token=get_token,
        get_current_identity=get_current_identity,
        get_current_user=get_current_user,
    )


# 模块级默认实例：快速接入时直接 import 使用
default_auth_deps = create_auth_deps()
