"""
JWT 认证技术库 —— 真实服务冒烟测试脚本

前置：先启动 demo 服务（默认 127.0.0.1:8010）：
    python examples/demo_main.py            # 端口 8000
    或自定义端口启动后再指定 BASE_URL。

用法：
    python scripts/smoke_test.py [BASE_URL]
"""
from __future__ import annotations

import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8010"
PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    mark = "PASS" if cond else "FAIL"
    if cond:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{mark}] {name} {detail}")


def main() -> None:
    client = httpx.Client(base_url=BASE_URL, timeout=10)

    # 1. 注册
    r = client.post("/demo/register", params={"username": "tom", "password": "abc123"})
    check("注册", r.status_code == 200, f"-> {r.status_code}")

    # 2. 错误密码登录 -> 401
    r = client.post("/auth/login", json={"username": "tom", "password": "wrong"})
    check("错误密码登录 401", r.status_code == 401, f"-> {r.status_code}")

    # 3. 正确登录 -> token + HttpOnly Cookie
    r = client.post("/auth/login", json={"username": "tom", "password": "abc123"})
    check("登录成功 200", r.status_code == 200, f"-> {r.status_code}")
    body = r.json()
    check("返回 access_token", bool(body.get("access_token")))
    check("返回 expires_in=3600", body.get("expires_in") == 3600, f"-> {body.get('expires_in')}")
    set_cookie = r.headers.get("set-cookie", "")
    check("种下 HttpOnly Cookie", "access_token=" in set_cookie and "HttpOnly" in set_cookie)
    token = body["access_token"]

    # 4. Header Bearer 访问受保护接口
    r = client.get("/demo/profile", headers={"Authorization": f"Bearer {token}"})
    check("Header 受保护接口", r.status_code == 200 and r.json()["username"] == "tom",
          f"-> {r.status_code} {r.text[:60]}")

    # 5. Cookie 访问受保护接口
    r = client.get("/demo/me", cookies={"access_token": token})
    check("Cookie 受保护接口", r.status_code == 200 and r.json()["name"] == "tom",
          f"-> {r.status_code} {r.text[:60]}")

    # 6. 无令牌 -> 401（用全新 client，避免 cookie jar 污染）
    clean_client = httpx.Client(base_url=BASE_URL, timeout=10)
    r = clean_client.get("/demo/profile")
    check("无令牌 401", r.status_code == 401, f"-> {r.status_code}")

    # 7. 刷新令牌
    from jwt_auth import create_refresh_token
    from jwt_auth.config import JWTSettings

    refresh = create_refresh_token(data={"sub": "tom"}, settings=JWTSettings(secret_key="demo-secret-key-do-not-use-in-prod"))
    r = client.post("/auth/refresh", json={"refresh_token": refresh})
    check("刷新令牌换新 access", r.status_code == 200 and bool(r.json().get("access_token")),
          f"-> {r.status_code}")

    # 8. 登出
    r = client.post("/auth/logout")
    check("登出", r.status_code == 200, f"-> {r.status_code}")

    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
