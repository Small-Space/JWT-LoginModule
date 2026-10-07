"""JWT 技术库测试：安全核心（令牌创建/校验/过期/篡改、密码哈希）。"""
from __future__ import annotations

from datetime import timedelta

import pytest
from jose import JWTError, jwt

from jwt_auth.config import JWTSettings
from jwt_auth.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_subject,
    hash_password,
    is_token_of_type,
    verify_password,
)

SETTINGS = JWTSettings(secret_key="test-secret-key")


# ---------------------------------------------------------------------------
# 密码哈希
# ---------------------------------------------------------------------------
def test_hash_and_verify_password():
    hashed = hash_password("my-pass")
    assert hashed != "my-pass"  # 不允许明文入库
    assert verify_password("my-pass", hashed)
    assert not verify_password("wrong-pass", hashed)


# ---------------------------------------------------------------------------
# 令牌创建与解码
# ---------------------------------------------------------------------------
def test_create_and_decode_access_token():
    token = create_access_token(data={"sub": "alice"}, settings=SETTINGS)
    payload = decode_token(token, SETTINGS)
    assert payload["sub"] == "alice"
    assert payload["type"] == "access"
    assert "exp" in payload


def test_token_custom_expiry():
    token = create_access_token(
        data={"sub": "alice"}, settings=SETTINGS, expires_delta=timedelta(minutes=5)
    )
    payload = decode_token(token, SETTINGS)
    assert payload["type"] == "access"


def test_refresh_token_marked_as_refresh():
    token = create_refresh_token(data={"sub": "alice"}, settings=SETTINGS)
    payload = decode_token(token, SETTINGS)
    assert is_token_of_type(payload, "refresh", SETTINGS)
    assert not is_token_of_type(payload, "access", SETTINGS)


def test_get_subject_ok_and_missing():
    token = create_access_token(data={"sub": "bob"}, settings=SETTINGS)
    assert get_subject(token, SETTINGS) == "bob"
    # 缺少 sub 的令牌
    token_no_sub = create_access_token(data={"foo": 1}, settings=SETTINGS)
    assert get_subject(token_no_sub, SETTINGS) is None


# ---------------------------------------------------------------------------
# 异常场景
# ---------------------------------------------------------------------------
def test_tampered_token_rejected():
    token = create_access_token(data={"sub": "alice"}, settings=SETTINGS)
    head, _, sig = token.rsplit(".", 2)
    tampered = f"{head}.{sig[:-1] + ('A' if sig[-1] != 'A' else 'B')}"
    with pytest.raises(JWTError):
        decode_token(tampered, SETTINGS)


def test_expired_token_rejected():
    token = create_access_token(
        data={"sub": "alice"},
        settings=SETTINGS,
        expires_delta=timedelta(seconds=-10),  # 已过期
    )
    with pytest.raises(JWTError):
        decode_token(token, SETTINGS)


def test_wrong_secret_rejected():
    token = create_access_token(data={"sub": "alice"}, settings=SETTINGS)
    other = JWTSettings(secret_key="another-secret")
    with pytest.raises(JWTError):
        decode_token(token, other)


def test_wrong_algorithm_rejected():
    # 用其他算法签发的 token，本库按 HS256 校验应失败
    token = jwt.encode({"sub": "alice"}, SETTINGS.secret_key, algorithm="HS256")
    bad_settings = JWTSettings(secret_key=SETTINGS.secret_key, algorithm="RS256")
    with pytest.raises(JWTError):
        decode_token(token, bad_settings)
