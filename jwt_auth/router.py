"""
JWT 认证技术库 —— 内置认证路由模块

与原始项目 auth/routers.py 的对应关系：
- POST /login      ->  校验用户名密码 + 签发令牌 + 写入 HttpOnly Cookie
- POST /logout     ->  清除 Cookie
- GET  /protected  ->  GET /me（当前用户信息，受保护示例）

设计说明：
- 路由与业务解耦：登录时的"用户认证函数"（authenticate）由调用方注入。
- 兼容双端风格：返回体携带 access_token（供前端存内存使用），同时写入 HttpOnly Cookie
  （原项目前端依赖 Cookie 自动携带，二者可共存）。
"""
from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from jose import JWTError

from .config import JWTSettings
from .deps import AuthDeps
from .schemas import LoginRequest, RefreshRequest, TokenResponse
from .security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    is_token_of_type,
)

# 认证函数签名：authenticate(username, password) -> 用户对象 | None
AuthenticateFunc = Callable[[str, str], Awaitable[Any] | Any]


def _set_access_token_cookie(response: Response, token: str, settings: JWTSettings) -> None:
    """将访问令牌写入 HttpOnly Cookie（参数全部来自配置）。"""
    response.set_cookie(
        key=settings.cookie_key,
        value=token,
        httponly=settings.cookie_httponly,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=int(settings.access_token_expire_delta.total_seconds()),
    )


def create_auth_router(
    authenticate: AuthenticateFunc,
    auth_deps: Optional[AuthDeps] = None,
    prefix: str = "/auth",
    tags: Optional[list[str]] = None,
) -> APIRouter:
    """
    创建内置认证路由。

    参数:
        authenticate: 登录认证函数，由业务实现（查库 + 校验密码），
                      返回用户对象则登录成功，返回 None 则 401。
        auth_deps:   认证依赖实例（与业务路由共用同一份配置）；
                      缺省使用 create_auth_deps()。
        prefix:      路由前缀，默认 /auth。
        tags:        OpenAPI 分组标签。
    """
    auth_deps = auth_deps or _default_deps()
    settings = auth_deps.settings
    router = APIRouter(prefix=prefix, tags=tags or ["认证"])

    @router.post("/login", response_model=TokenResponse, summary="登录并签发令牌")
    async def login(response: Response, user: LoginRequest):
        db_user = authenticate(user.username, user.password)
        if inspect.isawaitable(db_user):  # 兼容 async / sync 认证函数
            db_user = await db_user
        if db_user is None:
            raise HTTPException(status_code=401, detail="用户名或密码错误")

        sub = getattr(db_user, "name", None) or user.username  # 兼容不同用户模型
        access_token = create_access_token(
            data={settings.subject_field: sub}, settings=settings
        )
        refresh_token = create_refresh_token(
            data={settings.subject_field: sub}, settings=settings
        )
        # 写入 HttpOnly Cookie（兼容原项目前端自动携带 Cookie 的模式）
        _set_access_token_cookie(response, access_token, settings)
        return TokenResponse(
            access_token=access_token,
            token_type=settings.token_type,
            expires_in=int(settings.access_token_expire_delta.total_seconds()),
        )

    @router.post("/logout", summary="退出登录（清除 Cookie）")
    async def logout(response: Response):
        response.delete_cookie(
            key=settings.cookie_key,
            httponly=settings.cookie_httponly,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
        )
        return {"message": "退出登录成功"}

    @router.get("/me", summary="获取当前登录用户（受保护接口示例）")
    async def me(
        identity: Any = Depends(auth_deps.get_current_identity),
    ):
        return {"username": identity.sub, "token_type": identity.type}

    @router.post("/refresh", response_model=TokenResponse, summary="用刷新令牌换取新访问令牌")
    async def refresh(response: Response, body: RefreshRequest):
        try:
            payload = decode_token(body.refresh_token, settings)
        except JWTError:
            raise HTTPException(status_code=401, detail="刷新令牌无效或已过期") from None

        sub = payload.get(settings.subject_field)
        if not isinstance(sub, str) or not sub or not is_token_of_type(payload, "refresh", settings):
            raise HTTPException(status_code=401, detail="刷新令牌无效")

        new_access = create_access_token(data={settings.subject_field: sub}, settings=settings)
        _set_access_token_cookie(response, new_access, settings)
        return TokenResponse(
            access_token=new_access,
            token_type=settings.token_type,
            expires_in=int(settings.access_token_expire_delta.total_seconds()),
        )

    return router


def _default_deps() -> AuthDeps:
    """延迟创建默认依赖实例，避免模块加载时的循环导入。"""
    from .deps import create_auth_deps

    return create_auth_deps()
