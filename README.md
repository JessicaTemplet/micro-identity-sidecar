# Micro-Identity Sidecar

A lightweight, local-first OAuth 2.1 / OIDC authorization server that runs
as a background daemon next to your application — the same architectural
pattern as a service mesh sidecar (Envoy) or a local feature-flag daemon.
Your application never implements auth: it either asks the sidecar
"is this token good?" over localhost, or verifies tokens itself against the
sidecar's published public keys. Either way, OAuth/OIDC/JWT/crypto logic
never lives in your app's codebase.

Pure Go standard library — no third-party dependencies. `go build ./...`
just works, anywhere Go runs.

## Why a sidecar, and not a library?

- **Decoupling.** Auth logic upgrades independently of the app. Rotate
  algorithms, tune token lifetimes, or swap the session backend without
  touching or redeploying application code.
- **Polyglot.** Any language that can make an HTTP request to `127.0.0.1`
  gets full OAuth 2.1/OIDC support — no auth SDK per language.
- **Local-first.** Binds to loopback by default. It's not a shared
  multi-tenant identity provider; it's a per-workload daemon, like a
  feature-flag evaluator or a secrets-agent sidecar.

## Architecture

```
cmd/sidecar/            daemon entrypoint — wires everything below together
internal/jwtutil/       dependency-free JWT sign/verify (RS256 + EdDSA)
internal/keys/          key generation, background rotation, JWKS publishing
internal/pkce/          RFC 7636 PKCE verification (S256 only)
internal/session/       the stateless/stateful session bridge (see below)
internal/oidc/          the authorization server: discovery, /authorize,
                         /token, /revoke, /userinfo, client + user registries
internal/config/        env-var configuration with local-first defaults
examples/middleware/    how an application validates sidecar-minted tokens
examples/exampleapp/    a minimal resource server using that middleware
```

### 1. OIDC Token Minting Engine

`internal/oidc` implements an Authorization Server conforming to **OAuth
2.1**:

- **PKCE is mandatory** for every authorization code request — `code_challenge`
  and `code_challenge_method=S256` are required, not optional, for public
  *and* confidential clients. Missing or `plain`-method requests are
  rejected with `invalid_request` before a login form is even shown.
- **The implicit grant is banned.** `response_type` must be exactly `code`;
  anything else (`token`, `id_token token`, ...) is rejected with
  `unsupported_response_type`. The discovery document only ever advertises
  `"response_types_supported": ["code"]`.
- **Authorization codes are single-use.** A code is deleted from the store
  the instant it's presented to `/token`, whether or not the exchange
  succeeds — replaying a code (e.g. from a leaked redirect log) always
  fails with `invalid_grant`.
- **Refresh tokens rotate.** Each use of a refresh token revokes it and
  issues a new one, so a stolen-and-reused refresh token is detectable
  (the legitimate client's next refresh fails).
- Standard discovery at `GET /.well-known/openid-configuration`.

### 2. Cryptographic Session Key Rotation

`internal/keys.Manager` runs a background goroutine (`StartRotation`) that:

- Mints a new active signing key (RS256 or Ed25519/EdDSA — configurable)
  on a timer (`SIDECAR_KEY_ROTATE_EVERY`, default 24h).
- Demotes the previous key to "retired but still verifiable" for a grace
  period (`SIDECAR_KEY_GRACE_PERIOD`, default 48h) — so tokens signed right
  before a rotation don't suddenly fail verification.
- Publishes every key still in its grace window (active + retired) as a
  standard JWKS at `GET /.well-known/jwks.json`, each with a distinct `kid`
  so verifiers know exactly which key to use.

Verified live in testing: after one rotation, JWKS correctly listed all 3
keys (1 active, 2 retired-in-grace); after the grace period, retired keys
are pruned and dropped from the published set.

### 3. Stateful vs. Stateless Session Bridge

`internal/session` is a single `Store` interface with two backends,
selectable **per client** (`Client.SessionMode` in the client registry) or
per-request via `session.Bridge`:

| | Stateless (`JWTStore`) | Stateful (`OpaqueStore`) |
|---|---|---|
| Token shape | Signed JWT | Random 256-bit opaque string |
| Validation cost | Pure crypto check, zero I/O | One table lookup |
| Revocation | **Not possible** before expiry — this is the fundamental trade-off, not a missing feature. Keep TTLs short (default 5 min). | **Instant and global** — delete the row, the session is dead everywhere on the very next request |
| Storage | None (self-contained) | Pluggable `Backend`: in-memory or file-backed today |

`session.Bridge.RevokeAllForSubject` does exactly what it says for every
*stateful* session a subject holds — a real "log out everywhere" button.
Stateless sessions for that subject remain valid until they individually
expire, which is why anything security-sensitive should default to the
stateful backend, and why access tokens default to short-TTL stateless
JWTs paired with a stateful, rotatable refresh token for longer-lived login
state — exactly what `/token` issues.

**On the SQLite ask specifically:** the storage layer is defined by a
`session.Backend` interface (`Put`/`Get`/`Delete`/`DeleteWhereSubject`/`Sweep`)
with two working implementations shipped — `MemoryBackend` and a durable
`FileBackend` (atomic snapshot journal, survives restarts, zero
dependencies). This build's sandbox couldn't reach the Go module proxy to
fetch a SQLite driver, so a `SQLiteBackend` isn't compiled in, but the
interface is exactly what a `database/sql` + `modernc.org/sqlite`
implementation would satisfy — see the comment atop `backend.go` for the
schema. Swapping it in is a ~50-line addition; happy to build it if/when
this project has normal network access.

## Running it

```bash
go build -o sidecar ./cmd/sidecar
./sidecar
# 2026/.. listening on http://127.0.0.1:9091
```

Or with Docker Compose (sidecar + a demo app sharing a network namespace,
the actual sidecar deployment pattern):

```bash
docker compose up --build
```

### Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `SIDECAR_LISTEN_ADDR` | `127.0.0.1:9091` | HTTP bind address |
| `SIDECAR_ISSUER` | `http://127.0.0.1:9091` | `iss` claim / discovery base URL |
| `SIDECAR_KEY_ALG` | `EdDSA` | `EdDSA` or `RS256` |
| `SIDECAR_KEY_ROTATE_EVERY` | `24h` | Signing key rotation interval |
| `SIDECAR_KEY_GRACE_PERIOD` | `48h` | How long retired keys stay verifiable |
| `SIDECAR_STATELESS_TTL` | `5m` | JWT access token lifetime |
| `SIDECAR_STATEFUL_TTL` | `12h` | Opaque access token lifetime |
| `SIDECAR_SWEEP_EVERY` | `1m` | Expired stateful-row cleanup interval |
| `SIDECAR_SESSION_BACKEND` | `memory` | `memory` or `file` |
| `SIDECAR_SESSION_FILE` | `sessions.db` | Path used when backend is `file` |
| `SIDECAR_AUTHCODE_TTL` | `60s` | Authorization code lifetime |
| `SIDECAR_REFRESH_TTL` | `720h` (30d) | Refresh token lifetime |

Demo clients and users are registered in `cmd/sidecar/main.go` — replace
`oidc.NewDemoUserStore()` with an implementation of `oidc.UserStore` backed
by your real identity source, and register your real clients via
`clients.Register(...)`.

## Full walkthrough (verified against a running instance)

```bash
# 1. Generate a PKCE pair (S256)
python3 -c "
import hashlib, base64, secrets
v = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
print('verifier:', v); print('challenge:', c)
"

# 2. Log in (demo users: alice/bob, password: password123) and get a code
curl -i -X POST http://127.0.0.1:9091/authorize \
  --data-urlencode "username=alice" \
  --data-urlencode "password=password123" \
  --data-urlencode "client_id=demo-spa" \
  --data-urlencode "redirect_uri=http://127.0.0.1:9091/demo/callback" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid profile email offline_access" \
  --data-urlencode "state=xyz" \
  --data-urlencode "code_challenge=<challenge from step 1>" \
  --data-urlencode "code_challenge_method=S256"
# -> 302 Location: .../demo/callback?code=XXXX&state=xyz

# 3. Exchange the code for tokens
curl -X POST http://127.0.0.1:9091/token \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=XXXX" \
  --data-urlencode "redirect_uri=http://127.0.0.1:9091/demo/callback" \
  --data-urlencode "client_id=demo-spa" \
  --data-urlencode "code_verifier=<verifier from step 1>"
# -> { "access_token": "...", "id_token": "...", "refresh_token": "...", ... }

# 4. Use the access token
curl http://127.0.0.1:9091/userinfo -H "Authorization: Bearer <access_token>"

# 5. Revoke it (only takes effect for stateful tokens/refresh tokens)
curl -X POST http://127.0.0.1:9091/revoke --data-urlencode "token=<token>"
```

## Endpoint reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/.well-known/jwks.json` | GET | Current public keyset |
| `/authorize` | GET, POST | Authorization endpoint (login + code issuance) |
| `/token` | POST | `authorization_code` and `refresh_token` grants |
| `/revoke` | POST | RFC 7009 token revocation |
| `/userinfo` | GET | OIDC UserInfo (accepts either session mode) |
| `/healthz` | GET | Liveness check |

## What was cut, deliberately

- **Resource Owner Password Credentials grant** — removed in OAuth 2.1, not
  implemented here.
- **Implicit grant** — same; actively rejected, not just unsupported.
- **`plain` PKCE method** — rejected; `S256` only.
- **Dynamic client registration** — clients are registered in code/config,
  not self-service, which matches a sidecar's "one trusted app" deployment
  model.
