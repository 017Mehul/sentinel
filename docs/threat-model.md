# Sentinel Threat Model

## Assets

- User identities, email addresses, password hashes, profile fields, roles, and permissions.
- Access tokens, refresh-token families, session state, MFA secrets, and backup-code hashes.
- OAuth state and provider credentials.
- Audit records, rate-limit state, idempotency keys, and notification payloads.
- JWT private keys, AES-256 key, DB/Redis credentials, and SMTP credentials.

## Threat actors and abuse cases

| Threat | Expected controls | Residual risk / verification |
|---|---|---|
| Credential stuffing and brute force | Auth rate limits, account lockout, HIBP check, password hashing | Tune limits and monitor false positives |
| Stolen access token | Short access-token TTL, session validation, Redis-backed revocation | Validate revocation and expiry behavior with integration tests |
| Refresh-token theft/reuse | Hashed refresh tokens, rotation, family revocation | Test rotation and concurrent refresh behavior |
| CSRF against refresh/logout | Secure HttpOnly refresh cookie, separate CSRF cookie, constant-time comparison with X-CSRF-Token, credentialed exact-origin CORS | Browser tests must cover actual deployed domains |
| Broken object-level authorization | User-scoped handlers, admin role checks in backend | Add regression tests for each new resource route |
| MFA downgrade or secret replacement | TOTP verification, encrypted secret at rest, backup-code hashing, setup conflict for enabled factors | Test recovery-code exhaustion and recovery procedures |
| OAuth login CSRF/state replay | Server-side state validation; fail closed when Redis is unavailable | Provider credentials, redirect URIs, account-linking policy, and callbacks need live tests |
| SQL injection | Parameterized pgx queries and bounded pagination | Continue reviewing query construction and test all filters |
| Secret leakage | Ignore rules, environment config, private JWT key mounts, no browser token persistence | Rotate any credential accidentally exposed; use a secret manager |
| Dependency/container compromise | Go vulnerability checks, gosec, lint, Trivy, non-root image | CI is not an independent supply-chain audit |
| Database/Redis outage | Readiness checks and fail-closed security paths | Define backup, restore, and incident procedures |

## Security invariants

1. Authorization decisions are made by the Go backend, never by frontend state.
2. Passwords and raw refresh tokens are not stored in plaintext.
3. Production rejects placeholder secrets, wildcard CORS, non-HTTPS origins, plaintext database connections, and non-TLS Redis.
4. Refresh/logout cookie requests require a CSRF token matching the sentinel_csrf cookie.
5. Production refresh cookies are Secure, HttpOnly, scoped to /api/v1/auth, and use SameSite=None only with CSRF protection and exact CORS.
6. Audit events are written as part of relevant domain transactions where implemented.
7. API and worker processes use least-privilege deployment credentials and private network paths.

## Out of scope / not yet proven

- Independent penetration test or formal threat-model review.
- Public production deployment, managed service configuration, backups, disaster recovery, alerting, and key rotation rehearsal.
- End-to-end browser validation against real production OAuth providers and SMTP.
- WebAuthn/passkeys, SSO/SAML, tenant isolation, SCIM interoperability, and compliance certification.
