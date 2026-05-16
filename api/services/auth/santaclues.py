"""
SantaClues fork: per-request JWT authentication mode.

Replaces the per-org user/org/API-key bootstrap (signup → org-create →
issue API key) with a stateless model where the SantaClues server signs
a short-lived JWT per request containing the SantaClues organization
UUID as ``sub``. The engine verifies the signature + audience + expiry,
replay-checks ``jti`` against Redis, then resolves the engine-side org
by ``provider_id == jwt.sub`` (creating the row on first request) and a
deterministic per-org system user.

Threat model + design notes live in the SantaClues plan at
``~/.claude/plans/encapsulated-cuddling-flamingo.md``. Key invariants:

* JWT verification is **fail-closed**: missing key, wrong algorithm, or
  any decode error → 401 with generic ``"auth failed"`` (no oracle).
* JTI replay protection via Redis ``SETNX`` with 120s TTL. A second
  request with the same JTI within the window → 401 ``replay_detected``.
* Algorithm pin (``HS256``) AND issuer pin (``santaclues``) AND audience
  pin (``dograh-engine``) — defends against JWT algorithm confusion +
  cross-token substitution.
* Two-key rotation: ``SANTACLUES_JWT_SIGNING_KEY`` is the current key;
  ``SANTACLUES_JWT_PREVIOUS_KEY`` (optional) lets us accept tokens
  signed with the previous key for 24h after rotation. Engine tries
  current first, then previous.

Only activated when ``AUTH_PROVIDER == "santaclues"`` (set in env on
the render droplet). Stack Auth and OSS email/password paths are
untouched.
"""

import re
from typing import Optional

import jwt
import redis.asyncio as aioredis
from fastapi import HTTPException, Request
from loguru import logger

from api.constants import (
    REDIS_URL,
    SANTACLUES_JWT_PREVIOUS_KEY,
    SANTACLUES_JWT_SIGNING_KEY,
)
from api.db import db_client
from api.db.models import UserModel

# Token reuse window — defense against captured-token replay.
# 120s comfortably exceeds the 60s expiry SantaClues stamps so a tight
# back-to-back request from a different client (replay) reliably trips
# the SETNX even after the original token has expired.
JTI_REPLAY_TTL_SEC = 120

# Generic 401 message — never expose the failure reason to the caller.
# Specific reason goes only to engine audit logs + Loki.
_GENERIC_AUTH_ERROR = "auth failed"

# UUID v4 regex — SantaClues organization IDs. Reject anything else
# before any DB round-trip: a malformed sub is always a bug or an attack.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Single shared Redis client for replay checks; lazily initialized so
# importing this module doesn't open a connection at engine startup
# before lifespan() runs.
_redis_client: Optional[aioredis.Redis] = None


def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


def _verify_jwt(token: str) -> dict:
    """
    Verify a SantaClues-issued JWT. Tries current key first, then the
    previous key (for the 24h rotation window).

    Returns the decoded claims on success. Raises HTTPException(401) on
    any failure — caller MUST NOT echo the underlying reason to the
    response body.
    """
    if not SANTACLUES_JWT_SIGNING_KEY:
        # Fail-closed: never accept tokens when the signing key is unset.
        # Avoids the trap where a missing env defaults to a weak key.
        logger.error("santaclues auth: SANTACLUES_JWT_SIGNING_KEY not set; rejecting")
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_ERROR)

    candidate_keys = [SANTACLUES_JWT_SIGNING_KEY]
    if SANTACLUES_JWT_PREVIOUS_KEY:
        candidate_keys.append(SANTACLUES_JWT_PREVIOUS_KEY)

    last_error: Exception | None = None
    for key in candidate_keys:
        try:
            return jwt.decode(
                token,
                key,
                algorithms=["HS256"],
                audience="dograh-engine",
                issuer="santaclues",
                leeway=30,
                options={
                    # Reject tokens missing any required claim — defends
                    # against attacker-crafted tokens that strip aud/iss.
                    "require": ["exp", "iat", "jti", "sub", "aud", "iss"],
                },
            )
        except jwt.InvalidTokenError as err:
            last_error = err
            continue

    logger.warning(f"santaclues auth: JWT verification failed ({last_error})")
    raise HTTPException(status_code=401, detail=_GENERIC_AUTH_ERROR)


async def _check_jti_replay(jti: str) -> None:
    """
    Atomic single-use enforcement via Redis SETNX. Returns silently if
    this jti has not been seen in the replay window; raises 401 if it
    has.
    """
    redis = _get_redis()
    key = f"engine:jwt:jti:{jti}"
    # set(..., nx=True, ex=TTL) returns True on success, None on collision.
    acquired = await redis.set(key, "1", nx=True, ex=JTI_REPLAY_TTL_SEC)
    if not acquired:
        logger.warning(f"santaclues auth: replay detected jti={jti}")
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_ERROR)


async def handle_santaclues_jwt_auth(
    authorization: str | None, request: Request | None = None
) -> UserModel:
    """
    Entry point called from ``services/auth/depends.get_user`` when
    ``AUTH_PROVIDER == "santaclues"``.

    Returns a UserModel with ``selected_organization_id`` set so the
    rest of the codebase (which expects ``user.selected_organization_id``)
    keeps working unchanged.

    If ``request`` is provided, sets ``request.state.org_uuid`` and
    ``request.state.jti`` so the audit/rate-limit middleware can attribute
    requests. Skipped (silently) when called from WebSocket auth paths
    where Request isn't injectable.

    Flow:
      1. Parse Bearer token
      2. Verify JWT (sig + aud + iss + exp + iat + required claims)
      3. Replay-check jti
      4. Validate sub is a UUID
      5. Resolve/create engine-side Org by provider_id == jwt.sub
      6. Resolve/create per-org system User (provider_id == 'santaclues-sys-<orgUuid>')
      7. Attach selected_organization_id and return
    """
    if not authorization:
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_ERROR)

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_ERROR)

    token = authorization[len("Bearer ") :].strip()
    if not token:
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_ERROR)

    claims = _verify_jwt(token)

    jti = claims["jti"]
    org_uuid = claims["sub"]

    # Set request state BEFORE the replay check so even a replay-401
    # gets attribution in the audit log (operators investigating an
    # attack want to know which org the attacker was impersonating).
    if request is not None:
        request.state.org_uuid = org_uuid
        request.state.jti = jti

    await _check_jti_replay(jti)

    if not _UUID_RE.match(org_uuid):
        logger.warning(f"santaclues auth: sub is not a UUID: {org_uuid!r}")
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_ERROR)

    # Resolve engine-side org. provider_id is unique; the helper does
    # INSERT ... ON CONFLICT DO NOTHING then SELECT — race-safe.
    # We need a placeholder user_id for the helper signature; we'll
    # immediately create the system user next and map it.
    org_provider_id = org_uuid

    # Step 1: ensure a system user exists for this org. The system user
    # acts as the FK target for any legacy `created_by` column on
    # SantaClues-managed tables. provider_id is namespaced so it can
    # never collide with a Stack Auth or OSS user id.
    sys_user_provider_id = f"santaclues-sys-{org_uuid}"
    user_model, _user_was_created = await db_client.get_or_create_user_by_provider_id(
        sys_user_provider_id
    )

    # Step 2: ensure the org row exists; helper also adds the user to
    # the org's membership association table (organization_users).
    organization, _org_was_created = (
        await db_client.get_or_create_organization_by_provider_id(
            org_provider_id=org_provider_id, user_id=user_model.id
        )
    )

    # Step 3: make sure the system user's `selected_organization_id`
    # reflects this org (helper sets it on first link; here we
    # idempotently confirm).
    if user_model.selected_organization_id != organization.id:
        await db_client.update_user_selected_organization(
            user_model.id, organization.id
        )
        user_model.selected_organization_id = organization.id

    return user_model
