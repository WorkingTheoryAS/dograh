"""
Tests for the SantaClues fork's JWT auth dependency.

Pure-Python unit tests — mocks Redis + db_client so they don't need
postgres/redis to run. Run with:

    pytest api/tests/test_santaclues_auth.py -v

Covers the security-critical edge cases:
  - missing/empty Authorization header → 401
  - wrong scheme (not "Bearer ") → 401
  - expired token → 401
  - tampered signature → 401
  - wrong audience → 401 (cross-token substitution defense)
  - wrong issuer → 401
  - algorithm confusion (alg=none) → 401
  - missing required claims (no jti) → 401
  - sub is not a UUID → 401
  - replay (same jti twice) → 401 on second call
  - happy path → returns a UserModel with selected_organization_id set
  - rotation: previous-key signed token accepted
  - missing signing key in env → 401 fail-closed
"""

import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import HTTPException


# ---------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------

_CURRENT_KEY = "test-current-key-" + "0" * 32
_PREVIOUS_KEY = "test-previous-key-" + "0" * 32


def _mint(
    sub: str = None,
    *,
    key: str = _CURRENT_KEY,
    aud: str = "dograh-engine",
    iss: str = "santaclues",
    exp_offset: int = 60,
    iat_offset: int = 0,
    jti: str = None,
    algorithm: str = "HS256",
    drop_claims: tuple[str, ...] = (),
) -> str:
    """Mint a JWT for testing; tweak claims to test failure modes."""
    now = int(time.time())
    payload = {
        "iss": iss,
        "aud": aud,
        "sub": sub or str(uuid.uuid4()),
        "jti": jti or str(uuid.uuid4()),
        "iat": now + iat_offset,
        "exp": now + exp_offset,
    }
    for claim in drop_claims:
        payload.pop(claim, None)
    return jwt.encode(payload, key, algorithm=algorithm)


@pytest.fixture
def patched_keys():
    """Patch the signing keys in the santaclues module."""
    with patch(
        "api.services.auth.santaclues.SANTACLUES_JWT_SIGNING_KEY", _CURRENT_KEY
    ), patch(
        "api.services.auth.santaclues.SANTACLUES_JWT_PREVIOUS_KEY", _PREVIOUS_KEY
    ):
        yield


@pytest.fixture
def mock_redis():
    """Mock Redis SETNX to always succeed (no replay)."""
    redis_mock = AsyncMock()
    redis_mock.set = AsyncMock(return_value=True)
    with patch(
        "api.services.auth.santaclues._get_redis", return_value=redis_mock
    ):
        yield redis_mock


@pytest.fixture
def mock_db():
    """Mock db_client to return a fake user + org."""
    fake_user = MagicMock()
    fake_user.id = 42
    fake_user.selected_organization_id = None
    fake_org = MagicMock()
    fake_org.id = 99

    with patch(
        "api.services.auth.santaclues.db_client.get_or_create_user_by_provider_id",
        new=AsyncMock(return_value=(fake_user, True)),
    ), patch(
        "api.services.auth.santaclues.db_client.get_or_create_organization_by_provider_id",
        new=AsyncMock(return_value=(fake_org, True)),
    ), patch(
        "api.services.auth.santaclues.db_client.update_user_selected_organization",
        new=AsyncMock(),
    ):
        yield fake_user, fake_org


# ---------------------------------------------------------------------
# Negative tests: every failure must return 401 with the SAME message
# ---------------------------------------------------------------------

GENERIC = "auth failed"


@pytest.mark.asyncio
async def test_missing_authorization_returns_401(patched_keys, mock_redis, mock_db):
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth(None)
    assert exc.value.status_code == 401
    assert exc.value.detail == GENERIC


@pytest.mark.asyncio
async def test_empty_authorization_returns_401(patched_keys, mock_redis, mock_db):
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth("")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_wrong_scheme_returns_401(patched_keys, mock_redis, mock_db):
    """Basic auth scheme is rejected — only Bearer JWT is accepted."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth("Basic c2FudGE6Y2x1ZXM=")
    assert exc.value.status_code == 401
    assert exc.value.detail == GENERIC


@pytest.mark.asyncio
async def test_bearer_with_empty_token_returns_401(patched_keys, mock_redis, mock_db):
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth("Bearer    ")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_expired_token_returns_401(patched_keys, mock_redis, mock_db):
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    # Token expired 2 minutes ago, beyond the 30s leeway.
    token = _mint(exp_offset=-120)
    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth(f"Bearer {token}")
    assert exc.value.status_code == 401
    assert exc.value.detail == GENERIC


@pytest.mark.asyncio
async def test_tampered_signature_returns_401(patched_keys, mock_redis, mock_db):
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    token = _mint(key="completely-different-key-" + "0" * 32)
    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth(f"Bearer {token}")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_wrong_audience_returns_401(patched_keys, mock_redis, mock_db):
    """Defense against cross-token substitution — OSS_JWT, etc."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    token = _mint(aud="some-other-service")
    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth(f"Bearer {token}")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_wrong_issuer_returns_401(patched_keys, mock_redis, mock_db):
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    token = _mint(iss="attacker")
    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth(f"Bearer {token}")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_alg_none_returns_401(patched_keys, mock_redis, mock_db):
    """Classic algorithm-confusion attack — alg=none should never verify."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    # PyJWT refuses to encode with alg=none unless explicitly enabled —
    # mimic an attacker-crafted token by encoding then stripping sig.
    payload = {
        "iss": "santaclues",
        "aud": "dograh-engine",
        "sub": str(uuid.uuid4()),
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
    }
    forged = jwt.encode(payload, "", algorithm="none")
    # PyJWT's decode with algorithms=["HS256"] will refuse alg=none.
    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth(f"Bearer {forged}")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_missing_jti_returns_401(patched_keys, mock_redis, mock_db):
    """Required-claims enforcement — no jti = no replay protection = reject."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    token = _mint(drop_claims=("jti",))
    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth(f"Bearer {token}")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_sub_not_uuid_returns_401(patched_keys, mock_redis, mock_db):
    """Engine refuses to look up tenants by anything other than UUID."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    token = _mint(sub="not-a-uuid")
    with pytest.raises(HTTPException) as exc:
        await handle_santaclues_jwt_auth(f"Bearer {token}")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_replay_returns_401_on_second_call(patched_keys, mock_db):
    """SETNX collision = replay = 401."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    # First call succeeds (set returns True), second collides (None).
    redis_mock = AsyncMock()
    redis_mock.set = AsyncMock(side_effect=[True, None])

    with patch("api.services.auth.santaclues._get_redis", return_value=redis_mock):
        token = _mint(sub=str(uuid.uuid4()))
        user1 = await handle_santaclues_jwt_auth(f"Bearer {token}")
        assert user1.id == 42

        # Re-use the same token — different second call.
        with pytest.raises(HTTPException) as exc:
            await handle_santaclues_jwt_auth(f"Bearer {token}")
        assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_missing_signing_key_fails_closed(mock_redis, mock_db):
    """If env is misconfigured, refuse all auth — never default to weak key."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    with patch("api.services.auth.santaclues.SANTACLUES_JWT_SIGNING_KEY", None):
        token = _mint()
        with pytest.raises(HTTPException) as exc:
            await handle_santaclues_jwt_auth(f"Bearer {token}")
        assert exc.value.status_code == 401


# ---------------------------------------------------------------------
# Happy path + rotation
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_token_returns_user(patched_keys, mock_redis, mock_db):
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    fake_user, fake_org = mock_db
    token = _mint()
    user = await handle_santaclues_jwt_auth(f"Bearer {token}")
    assert user is fake_user
    assert user.selected_organization_id == fake_org.id


@pytest.mark.asyncio
async def test_previous_key_accepted_during_rotation(patched_keys, mock_redis, mock_db):
    """Token signed with previous key still verifies during the rotation window."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    token = _mint(key=_PREVIOUS_KEY)
    user = await handle_santaclues_jwt_auth(f"Bearer {token}")
    assert user is not None


@pytest.mark.asyncio
async def test_request_state_populated(patched_keys, mock_redis, mock_db):
    """Auth dependency stamps org_uuid + jti on request.state for the audit middleware."""
    from api.services.auth.santaclues import handle_santaclues_jwt_auth

    org_id = str(uuid.uuid4())
    jti = str(uuid.uuid4())
    token = _mint(sub=org_id, jti=jti)

    # Mimic the Request object with a `state` attribute (Starlette's Request.state is a SimpleNamespace).
    class FakeState:
        pass

    class FakeRequest:
        state = FakeState()

    request = FakeRequest()
    await handle_santaclues_jwt_auth(f"Bearer {token}", request=request)
    assert request.state.org_uuid == org_id
    assert request.state.jti == jti


# ---------------------------------------------------------------------
# Defense in depth: confirm 410 routes reject when AUTH_PROVIDER=santaclues
# (tested by structural check — actual route behavior covered in integration tests)
# ---------------------------------------------------------------------


def test_410_helper_in_auth_router():
    """Sanity check: the 410 helper exists and the signup/login routes call it."""
    import inspect

    from api.routes import auth as auth_routes

    src = inspect.getsource(auth_routes)
    assert "_reject_if_santaclues_mode" in src
    assert 'status_code=410' in src
    # Both routes must call it
    signup_src = inspect.getsource(auth_routes.signup)
    login_src = inspect.getsource(auth_routes.login)
    assert "_reject_if_santaclues_mode()" in signup_src
    assert "_reject_if_santaclues_mode()" in login_src


def test_410_helper_in_api_keys_route():
    """API-key creation must 410 in santaclues mode."""
    import inspect

    from api.routes import user as user_routes

    src = inspect.getsource(user_routes.create_api_key)
    assert 'status_code=410' in src
    assert 'santaclues' in src.lower()
