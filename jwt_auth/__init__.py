"""
JWT 认证技术库
==============

一个与业务解耦、开箱即用的 FastAPI JWT 认证组件。

从「fastapi-management-system」项目的 auth 模块剥离并重构而来：
- 令牌创建/校验          -> jwt_auth.security
- Header/Cookie 双通道依赖 -> jwt_auth.deps
- 登录/登出/刷新路由       -> jwt_auth.router
- 配置项                 -> jwt_auth.config
- Pydantic 数据模型       -> jwt_auth.schemas

典型用法：:

    from jwt_auth import create_auth_deps, create_auth_router
    from jwt_auth.config import JWTSettings

    settings = JWTSettings(secret_key="your-secret")
    auth_deps = create_auth_deps(settings=settings)

    async def authenticate(username, password):
        user = await db.get_user(username)
        if user and verify_password(password, user.pwd):
            return user
        return None

    app.include_router(create_auth_router(authenticate, auth_deps))
    # 业务路由中保护接口：
    # Depends(auth_deps.get_current_identity)  仅校验身份
    # Depends(auth_deps.get_current_user(get_user))  校验并注入完整用户对象
"""
from .config import JWTSettings
from .deps import AuthDeps, create_auth_deps, default_auth_deps
from .router import create_auth_router
from .schemas import LoginRequest, RefreshRequest, TokenPayload, TokenResponse
from .security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_subject,
    hash_password,
    is_token_of_type,
    verify_password,
)

__version__ = "1.0.0"

__all__ = [
    "JWTSettings",
    "AuthDeps",
    "create_auth_deps",
    "default_auth_deps",
    "create_auth_router",
    "LoginRequest",
    "RefreshRequest",
    "TokenPayload",
    "TokenResponse",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "get_subject",
    "hash_password",
    "verify_password",
    "is_token_of_type",
    "__version__",
]
