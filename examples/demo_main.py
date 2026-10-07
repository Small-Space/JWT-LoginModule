"""
JWT 认证技术库 —— 可运行示例

内存用户存储，不依赖任何数据库。演示：
1. 密码哈希注册（内存）
2. 登录（返回 access_token + 写 HttpOnly Cookie）
3. 受保护接口（Header Bearer / Cookie 双通道）
4. 刷新令牌
5. 登出

运行方式（在 jwt_auth_lib 目录下）:
    python examples/demo_main.py
    # 或
    uvicorn examples.demo_main:app --reload
然后访问 http://127.0.0.1:8000/docs 交互调试。
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# 保证可直接 python examples/demo_main.py 运行
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import Depends, FastAPI  # noqa: E402

from jwt_auth import (  # noqa: E402
    JWTSettings,
    create_auth_deps,
    create_auth_router,
    hash_password,
    verify_password,
)

# ---------------------------------------------------------------------------
# 1. 内存"用户表"（业务层：真实项目换成 Tortoise/SQLAlchemy 查询即可）
# ---------------------------------------------------------------------------
memory_users: dict[str, dict] = {}


def get_user(username: str) -> Optional[dict]:
    """业务注入的用户查询函数：通过 sub（用户名）查用户。"""
    return memory_users.get(username)


async def authenticate(username: str, password: str) -> Optional[dict]:
    """登录认证函数：查库 + 校验密码（本库已提供 verify_password）。"""
    user = get_user(username)
    if user and verify_password(password, user["pwd_hash"]):
        return user
    return None


# ---------------------------------------------------------------------------
# 2. 组装应用：配置 -> 依赖 -> 路由
# ---------------------------------------------------------------------------
# 示例固定密钥（仅演示；生产用环境变量 JWT_SECRET_KEY 注入）
settings = JWTSettings(secret_key="demo-secret-key-do-not-use-in-prod")
auth_deps = create_auth_deps(settings=settings)

app = FastAPI(title="JWT Auth 技术库示例")
app.include_router(create_auth_router(authenticate, auth_deps))


# ---------------------------------------------------------------------------
# 3. 业务路由示例：两种保护方式
# ---------------------------------------------------------------------------
@app.post("/demo/register", summary="注册（密码哈希入库）")
async def register(username: str, password: str):
    if username in memory_users:
        return {"message": "用户已存在"}
    memory_users[username] = {"name": username, "pwd_hash": hash_password(password)}
    return {"message": "注册成功"}


@app.get("/demo/profile", summary="受保护：仅校验身份（等价原项目 /protected）")
async def profile(identity=Depends(auth_deps.get_current_identity)):
    return {"message": "身份校验通过", "username": identity.sub}


@app.get("/demo/me", summary="受保护：校验并注入完整用户对象")
async def me(user: dict = Depends(auth_deps.get_current_user(get_user))):
    return {"name": user["name"], "has_password_hash": bool(user["pwd_hash"])}


if __name__ == "__main__":
    import uvicorn

    # 预置一个演示账号
    memory_users["admin"] = {"name": "admin", "pwd_hash": hash_password("123456")}
    uvicorn.run(app, host="127.0.0.1", port=8000)
