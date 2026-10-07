"""JWT 技术库测试：内置路由（登录/登出/me/刷新 全流程）。"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from jwt_auth import create_auth_deps, create_auth_router, hash_password, verify_password
from jwt_auth.config import JWTSettings

SETTINGS = JWTSettings(secret_key="test-secret-key", cookie_key="access_token")
auth_deps = create_auth_deps(settings=SETTINGS)

# 内存用户表
USERS = {"alice": {"name": "alice", "pwd_hash": hash_password("pass123")}}


def get_user(sub: str):
    return USERS.get(sub)


def authenticate(username: str, password: str):
    user = get_user(username)
    if user and verify_password(password, user["pwd_hash"]):
        return user
    return None


app = FastAPI()
app.include_router(create_auth_router(authenticate, auth_deps))

# 业务路由：同时演示 get_current_user 注入
from fastapi import Depends  # noqa: E402

@app.get("/auth/me_full")
def me_full(user: dict = Depends(auth_deps.get_current_user(get_user))):
    return {"name": user["name"]}


client = TestClient(app)


def test_login_success_returns_token_and_cookie():
    r = client.post("/auth/login", json={"username": "alice", "password": "pass123"})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600
    # 响应里种了 HttpOnly Cookie
    set_cookie = r.headers.get("set-cookie", "")
    assert "access_token=" in set_cookie
    assert "HttpOnly" in set_cookie


def test_login_wrong_password_401():
    r = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


def test_login_unknown_user_401():
    r = client.post("/auth/login", json={"username": "ghost", "password": "x"})
    assert r.status_code == 401


def test_me_with_token_ok():
    login = client.post("/auth/login", json={"username": "alice", "password": "pass123"})
    token = login.json()["access_token"]
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_me_without_token_401():
    # 使用全新客户端，避免前面登录测试种下的 Cookie 被自动携带
    clean_client = TestClient(app)
    r = clean_client.get("/auth/me")
    assert r.status_code == 401


def test_me_via_cookie_only():
    """登录后不带 Authorization，仅靠 Cookie 也能访问受保护接口（原项目行为）。"""
    login = client.post("/auth/login", json={"username": "alice", "password": "pass123"})
    cookie = login.cookies.get("access_token")
    assert cookie
    r = client.get("/auth/me", cookies={"access_token": cookie})
    assert r.status_code == 200


def test_me_full_injects_user():
    login = client.post("/auth/login", json={"username": "alice", "password": "pass123"})
    token = login.json()["access_token"]
    r = client.get("/auth/me_full", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["name"] == "alice"


def test_refresh_exchanges_new_access_token():
    from jwt_auth import create_refresh_token

    refresh = create_refresh_token(data={"sub": "alice"}, settings=SETTINGS)
    r = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    assert r.json()["access_token"]
    assert r.json()["token_type"] == "bearer"


def test_refresh_with_access_token_rejected_401():
    login = client.post("/auth/login", json={"username": "alice", "password": "pass123"})
    access = login.json()["access_token"]
    r = client.post("/auth/refresh", json={"refresh_token": access})
    assert r.status_code == 401


def test_async_authenticate_supported():
    """回归：authenticate 为 async 实现时也必须正常工作（demo 即此类）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    async def async_authenticate(username: str, password: str):
        user = get_user(username)
        if user and verify_password(password, user["pwd_hash"]):
            return user
        return None

    app_async = FastAPI()
    app_async.include_router(create_auth_router(async_authenticate, auth_deps))
    c = TestClient(app_async)
    r = c.post("/auth/login", json={"username": "alice", "password": "pass123"})
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_logout_clears_cookie():
    login = client.post("/auth/login", json={"username": "alice", "password": "pass123"})
    cookie = login.cookies.get("access_token")
    r = client.post("/auth/logout", cookies={"access_token": cookie})
    assert r.status_code == 200
    # set-cookie 指示过期清除
    assert "access_token=" in r.headers.get("set-cookie", "")
