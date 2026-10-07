"""JWT 技术库测试：依赖注入（Header / Cookie 双通道、401 场景）。"""
from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from jwt_auth import create_auth_deps, create_access_token, create_refresh_token
from jwt_auth.config import JWTSettings

SETTINGS = JWTSettings(secret_key="test-secret-key", cookie_key="access_token")
auth_deps = create_auth_deps(settings=SETTINGS, token_url="/auth/login")

app = FastAPI()


@app.get("/protected")
def protected(identity=Depends(auth_deps.get_current_identity)):
    return {"username": identity.sub}


client = TestClient(app)


def _access_token(sub: str = "alice") -> str:
    return create_access_token(data={"sub": sub}, settings=SETTINGS)


# ---------------------------------------------------------------------------
# 双通道提取
# ---------------------------------------------------------------------------
def test_header_bearer_token_ok():
    r = client.get("/protected", headers={"Authorization": f"Bearer {_access_token()}"})
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_cookie_token_ok():
    r = client.get("/protected", cookies={"access_token": _access_token()})
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_header_priority_over_cookie():
    """Header 与 Cookie 同时存在时，以 Header 为准。"""
    r = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {_access_token('from-header')}"},
        cookies={"access_token": _access_token("from-cookie")},
    )
    assert r.status_code == 200
    assert r.json()["username"] == "from-header"


# ---------------------------------------------------------------------------
# 401 场景
# ---------------------------------------------------------------------------
def test_missing_token_401():
    r = client.get("/protected")
    assert r.status_code == 401


def test_garbage_token_401():
    r = client.get("/protected", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401


def test_expired_token_401():
    from datetime import timedelta

    token = create_access_token(
        data={"sub": "alice"}, settings=SETTINGS, expires_delta=timedelta(seconds=-1)
    )
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_refresh_token_not_allowed_on_access_endpoint_401():
    token = create_refresh_token(data={"sub": "alice"}, settings=SETTINGS)
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_get_current_user_injects_user_object():
    """get_current_user：校验通过后把业务用户对象注入路由。"""
    store = {"alice": {"name": "alice", "level": 9}}

    def get_user(sub: str):
        return store.get(sub)

    app2 = FastAPI()

    @app2.get("/me")
    def me(user: dict = Depends(auth_deps.get_current_user(get_user))):
        return user

    c2 = TestClient(app2)
    r = c2.get("/me", headers={"Authorization": f"Bearer {_access_token('alice')}"})
    assert r.status_code == 200
    assert r.json()["level"] == 9

    # 用户不存在 -> 401
    r = c2.get("/me", headers={"Authorization": f"Bearer {_access_token('ghost')}"})
    assert r.status_code == 401
