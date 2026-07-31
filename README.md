# auth-service

[![CI](https://github.com/MehulChamoli/auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/MehulChamoli/auth-service/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.24-blue)](https://golang.org/dl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A full authentication microservice built in Go. I started this to get a proper understanding of auth flows — JWTs, refresh token rotation, MFA, OAuth — by actually building them rather than dropping in a library.

It covers most of what you'd need in a real app: register/login, email verification, password reset, TOTP-based MFA, Google and GitHub OAuth, RBAC, sessions, and some infrastructure stuff like rate limiting and webhook delivery.

---

## What's in here

**Auth core**
- Register, verify email, login, logout
- Password reset flow
- RS256 JWTs with a JWKS endpoint so downstream services can validate tokens without touching the private key
- Refresh token rotation — if a token gets reused, the whole family is revoked
- Progressive account lockout after too many failed attempts
- HIBP password check using k-anonymity (only the first 5 chars of the SHA-1 hash get sent)

**MFA**
- TOTP setup with QR code
- 10 SHA-256 hashed backup codes on enrollment
- MFA secrets are encrypted at rest with AES-256-GCM

**OAuth2**
- Google and GitHub
- State param CSRF check — if Redis is down, the callback is rejected rather than skipped
- Accounts get linked if the email already exists

**Infrastructure**
- Redis-backed rate limiting with `X-RateLimit-*` headers
- Idempotency middleware using atomic `SET NX` to stop duplicate mutations on retries
- OpenTelemetry traces exported to Jaeger
- Prometheus metrics at `/metrics`
- gRPC server for `ValidateToken`, `GetUser`, `CheckPermission`
- Transactional outbox for async notification delivery
- HMAC-SHA256 signed webhooks

---

## Stack

| | |
|---|---|
| Language | Go 1.24 |
| Web | Gin |
| RPC | gRPC + Protobuf |
| DB | PostgreSQL 16 (pgx/v5 + golang-migrate) |
| Cache | Redis 7 (go-redis/v9) |
| DI | Google Wire |
| Observability | OpenTelemetry, Jaeger, Prometheus |
| Testing | testify + testcontainers-go |

---

## Getting started

You need Go 1.24+ and Docker.

```bash
git clone https://github.com/MehulChamoli/auth-service.git
cd auth-service

go mod tidy
cp .env.example .env

# generate RSA key pair
make gen-keys

# spin up postgres, redis, jaeger
docker compose up --build
```

Once running:

| | |
|---|---|
| HTTP API | http://localhost:8080 |
| gRPC | localhost:9090 |
| Metrics | http://localhost:8080/metrics |
| JWKS | http://localhost:8080/.well-known/jwks.json |
| Jaeger | http://localhost:16686 |

Run migrations if you're not using Docker Compose for the DB:

```bash
make migrate-up
```

---

## Testing

```bash
make test                # unit tests with race detector
make test-cover          # coverage report
make test-integration    # integration tests via Testcontainers (needs Docker)
make security            # gosec + govulncheck
```

---

## API

### Health & system
| Method | Path | |
|---|---|---|
| GET | `/healthz` | liveness |
| GET | `/ready` | readiness (DB + Redis) |
| GET | `/version` | build info |
| GET | `/.well-known/jwks.json` | public key set |
| GET | `/metrics` | prometheus |

### Auth
| Method | Path | |
|---|---|---|
| POST | `/api/v1/auth/register` | create account |
| POST | `/api/v1/auth/verify-email` | verify email |
| POST | `/api/v1/auth/login` | login |
| POST | `/api/v1/auth/refresh` | rotate refresh token |
| POST | `/api/v1/auth/logout` | revoke session |
| POST | `/api/v1/auth/forgot-password` | request reset token |
| POST | `/api/v1/auth/reset-password` | reset password |

### User (requires auth)
| Method | Path | |
|---|---|---|
| GET | `/api/v1/users/me` | profile + roles |
| PATCH | `/api/v1/users/me` | update profile |

### MFA (requires auth)
| Method | Path | |
|---|---|---|
| POST | `/api/v1/mfa/setup` | generate TOTP secret + QR |
| POST | `/api/v1/mfa/enable` | enable after verifying OTP |
| POST | `/api/v1/mfa/disable` | disable MFA |

### OAuth2
| Method | Path | |
|---|---|---|
| GET | `/api/v1/oauth/google/login` | redirect to Google |
| GET | `/api/v1/oauth/google/callback` | Google callback |
| GET | `/api/v1/oauth/github/login` | redirect to GitHub |
| GET | `/api/v1/oauth/github/callback` | GitHub callback |

### Admin (requires `admin` role)
| Method | Path | |
|---|---|---|
| GET | `/api/v1/admin/roles` | list roles |
| GET | `/api/v1/admin/permissions` | list permissions |
| GET | `/api/v1/admin/audit-logs` | audit log |
| POST | `/api/v1/admin/users/roles` | assign role |
| DELETE | `/api/v1/admin/users/roles` | revoke role |

---

## Project layout

```
cmd/
  server/       # HTTP + gRPC entrypoint
  worker/       # outbox worker
  migrate/      # migration runner
config/         # Viper config + env expansion
configs/        # app.yaml, feature_flags.yaml
internal/
  auth/         # login, register, refresh, logout, recovery
  mfa/          # TOTP + backup codes
  oauth/        # Google + GitHub
  session/      # session management
  user/         # profile handlers
  admin/        # RBAC + audit log
  webhook/      # webhook delivery
  worker/       # background jobs
  shared/       # errors, response envelope, context keys
migrations/     # SQL migration files
pkg/
  cache/        # Redis + distributed lock
  crypto/       # bcrypt, AES-256-GCM, HIBP, SecureRandom
  database/     # pgxpool
  token/        # RS256 JWT + JWKS
  middleware/   # rate limiting, idempotency
  secrets/      # local / Vault / AWS secrets
  tracing/      # OpenTelemetry
  metrics/      # Prometheus
tests/integration/
proto/auth/v1/
```

---

## A few design notes

**RS256 over HS256** — downstream services can validate tokens using only the public key from JWKS. With HS256 you'd have to share the secret everywhere, which makes rotation a pain.

**Fail-closed on OAuth state** — if Redis is unavailable during a callback, the request is rejected. Skipping a CSRF check because the cache is slow isn't acceptable.

**Token hashes only** — refresh tokens are stored as SHA-256 hashes. If the DB leaks, raw tokens can't be replayed. Same logic as storing password hashes.

**Atomic idempotency** — `SET NX` is a single command, so there's no race window between checking and setting the lock. Two concurrent identical requests can't both slip through.

---

## Make targets

```
make build             build all binaries
make run               build + run
make gen-keys          generate RSA key pair
make migrate-up        run pending migrations
make migrate-down      rollback last migration
make test              unit tests
make test-cover        tests + coverage
make test-integration  integration tests
make lint              golangci-lint
make security          gosec + govulncheck
make docker-up         start Docker stack
make docker-down       stop Docker stack
make clean             remove build artifacts
```

---

## License

[MIT](LICENSE)
