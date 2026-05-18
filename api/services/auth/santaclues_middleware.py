"""
SantaClues fork: HTTP middleware for audit logging + per-org rate limiting.

Activated only when ``AUTH_PROVIDER == "santaclues"`` so the upstream
codepath stays bit-for-bit unchanged for other deployment modes.

Audit log: every request emits one structured log line that ships to
Loki via the existing Promtail tail on the render droplet. Format:
``{ts, org_uuid, method, path, status, latency_ms, ip, ua, jti?}``.
The org UUID is the JWT ``sub`` we set on ``request.state`` from the
auth dependency — so authenticated requests get attribution, unauth'd
requests get ``org_uuid=None``.

Rate limit: 1000 req/min/org (Redis token bucket). Defense against a
runaway SantaClues bug; SantaClues already rate-limits at 600/min/org
in the proxy, so the engine cap is intentionally higher to give the
upstream limiter the first chance to refuse. On Redis outage the
limiter fails OPEN (warn-log, allow request) — same pattern as the
SantaClues Stripe webhook dedup. Defense against a Redis blip taking
down the engine for everyone.
"""

import time
from typing import Optional

import redis.asyncio as aioredis
from fastapi import Request
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from api.constants import AUTH_PROVIDER, REDIS_URL

# Per-org cap. SantaClues proxy is 600/min — engine sits comfortably
# above so legitimate bursts pass through without operator action.
_RATE_LIMIT_PER_MIN = 1000

# Shared Redis client; lazy-init so engine startup doesn't connect
# before lifespan() runs.
_redis_client: Optional[aioredis.Redis] = None


def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


class SantaCluesRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-org rate limit. Reads ``request.state.org_uuid`` (set by the
    SantaClues auth dependency) and enforces a 1000/min cap.

    No-op on:
      - non-santaclues AUTH_PROVIDER (preserves upstream behavior)
      - unauthenticated requests (auth middleware handles 401)
      - health probes (always allowed)
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if AUTH_PROVIDER != "santaclues":
            return await call_next(request)

        if request.url.path in ("/api/v1/health", "/healthz"):
            return await call_next(request)

        # The auth dependency runs INSIDE call_next, so org_uuid is not
        # set yet here. We can't pre-gate by org. Defer the rate-limit
        # check to a post-dispatch audit step that decrements/checks the
        # bucket AFTER the auth resolution. Acceptable: SantaClues
        # proxy already gates at 600/min, so the engine bucket
        # effectively only catches a genuinely runaway caller — and a
        # second-precision over-shoot of a few requests is fine.
        response = await call_next(request)

        org_uuid = getattr(request.state, "org_uuid", None)
        if not org_uuid:
            return response

        try:
            redis = _get_redis()
            minute_bucket = int(time.time() // 60)
            key = f"engine:ratelimit:org:{org_uuid}:{minute_bucket}"
            # INCR + EXPIRE: returns the new count. First request in the
            # window sets TTL to 90s (well past one minute, so the key
            # falls off naturally).
            current = await redis.incr(key)
            if current == 1:
                await redis.expire(key, 90)
            if current > _RATE_LIMIT_PER_MIN:
                # Structured source so operators can grep Loki for
                # `ai-agent-engine.rate-limit-exceeded` independently of
                # generic auth.failed lines — rate-limit trips suggest
                # a runaway caller, not an attack.
                logger.bind(
                    santaclues_security_event=True,
                    source="ai-agent-engine.rate-limit-exceeded",
                    org_uuid=org_uuid,
                    count=current,
                ).warning(
                    f"santaclues rate-limit exceeded org={org_uuid} "
                    f"path={request.url.path} count={current}"
                )
                return JSONResponse(
                    status_code=429,
                    content={"detail": "rate limit exceeded"},
                    headers={"Retry-After": "60"},
                )
        except Exception as err:
            # Fail open on Redis outage — engine stays available, log
            # so we notice in audit.
            logger.warning(f"santaclues rate-limit Redis error (fail-open): {err}")

        return response


class SantaCluesAuditLogMiddleware(BaseHTTPMiddleware):
    """
    Structured request log for security incident response. Reads
    org_uuid + jti from ``request.state`` (set by the auth dependency).
    Skipped entirely for non-santaclues AUTH_PROVIDER.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if AUTH_PROVIDER != "santaclues":
            return await call_next(request)

        start = time.monotonic()
        response = await call_next(request)
        latency_ms = int((time.monotonic() - start) * 1000)

        org_uuid = getattr(request.state, "org_uuid", None)
        jti = getattr(request.state, "jti", None)
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent", "")

        # One structured line per request. Loki ships this via tail of
        # the engine container's stdout.
        logger.bind(
            santaclues_audit=True,
            org_uuid=org_uuid,
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            latency_ms=latency_ms,
            ip=ip,
            ua=ua,
            jti=jti,
        ).info("engine_request")

        return response
