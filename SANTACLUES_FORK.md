# SantaClues Fork

This branch (`santaclues`) is the SantaClues platform's long-lived fork of
`dograh-hq/dograh`, pinned to upstream release **`dograh-v1.29.0`**.

The fork replaces the per-org bootstrap (signup → org-create → API-key
issuance) with a **stateless per-request JWT auth** model. The SantaClues
server mints a 60-second JWT per engine call containing the SantaClues
organization UUID as `sub`; the engine verifies the signature + audience
+ expiry, replay-checks the `jti` against Redis, then resolves the
engine-side org by `provider_id == jwt.sub` (auto-creating on first
request) and a deterministic per-org system user.

## Diff scope (kept minimal for rebase pain)

| File | Change |
|---|---|
| `api/constants.py` | Add `SANTACLUES_JWT_SIGNING_KEY` + `SANTACLUES_JWT_PREVIOUS_KEY` env reads |
| `api/services/auth/santaclues.py` | **NEW** — JWT verify + replay + org/user resolution |
| `api/services/auth/santaclues_middleware.py` | **NEW** — audit log + per-org rate limit middleware |
| `api/services/auth/depends.py` | Add `if AUTH_PROVIDER == "santaclues":` branch at top of `get_user` |
| `api/app.py` | Mount the two new middleware (both self-disable when AUTH_PROVIDER != santaclues) |
| `api/routes/auth.py` | 410 Gone the `/auth/signup` + `/auth/login` routes when in santaclues mode |
| `api/routes/user.py` | 410 Gone the `POST /user/api-keys` route in santaclues mode |
| `api/tests/test_santaclues_auth.py` | **NEW** — JWT verify + replay + rotation + 410 route tests |
| `.github/workflows/build-santaclues-api.yml` | **NEW** — GHCR image build on push to `santaclues` |
| `SANTACLUES_FORK.md` | **NEW** — this file |

Nothing else is touched. Every other deployment mode (`local`,
`stack`) is bit-for-bit identical to upstream.

## Activation

Set `AUTH_PROVIDER=santaclues` + populate the new env vars:

```
AUTH_PROVIDER=santaclues
SANTACLUES_JWT_SIGNING_KEY=<256-bit-hex; generated via `openssl rand -hex 32`>
# Optional during 24h rotation windows:
SANTACLUES_JWT_PREVIOUS_KEY=<previous 256-bit-hex>
```

In any other mode, the new code paths are dormant.

## Rebase cadence

**Quarterly** against upstream `main`:

```bash
git fetch upstream
git checkout santaclues
git rebase upstream/dograh-v<next-tag>
# Resolve conflicts (expect none outside the files listed above)
git push --force-with-lease origin santaclues
```

If a rebase reveals upstream has refactored `services/auth/depends.py`
or `routes/auth.py`, redo the small edits by hand. The diff is
intentionally small to keep this painless.

## Threat model

See `~/.claude/plans/encapsulated-cuddling-flamingo.md` (SantaClues
repo) for the full security architecture. Key invariants:

1. JWT verification is **fail-closed**: missing key, wrong algorithm,
   any decode error → 401 with generic `"auth failed"`.
2. JTI replay-protected via Redis SETNX (120s TTL).
3. Algorithm pin (`HS256`) + issuer pin (`santaclues`) + audience pin
   (`dograh-engine`) — defends against algorithm-confusion + cross-token
   substitution.
4. Two-key rotation: engine accepts current OR previous key.
5. SantaClues organization UUID is validated as UUID v4 before any DB
   round-trip — reject malformed `sub` immediately.
6. Per-org rate limit (1000/min) defends against runaway caller.
7. Audit log structured + ships to Loki for incident forensics.

## Image build & deploy

GitHub Actions on push to `santaclues` builds and pushes
`ghcr.io/morten202020/santaclues-dograh-api:<latest|sha>`. Pull on the
render droplet's `docker-compose.override.yml` pins to a specific SHA.

## Tests

```bash
cd api
pytest tests/test_santaclues_auth.py -v
```

Tests mock Redis + db_client; no infra required.
