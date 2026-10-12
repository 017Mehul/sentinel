# Sentinel Architecture

Sentinel is a Go IAM service with a static administrative console. PostgreSQL is the source of truth for identities, roles, sessions, refresh-token hashes, MFA factors, and audit events. Redis backs session validation, rate limiting, OAuth state, and idempotency.

## Runtime architecture

~~~mermaid
flowchart LR
  Browser[Sentinel Web Console<br/>Static HTML/CSS/JS] -->|HTTPS + short-lived Bearer token| API[Go HTTP API]
  API --> DB[(Managed PostgreSQL)]
  API --> Redis[(Redis with TLS)]
  API --> OTel[OpenTelemetry exporter]
  API --> JWKS[RS256 / JWKS]
  API --> Outbox[(Transactional outbox)]
  Worker[Outbox worker] --> DB
  Worker --> SMTP[SMTP provider]
  Proxy[HTTPS reverse proxy / platform] --> API
  Proxy --> Browser
~~~

The production reference Compose file expects externally managed PostgreSQL and Redis plus a trusted TLS-terminating proxy. It does not bundle or provision those services.

## Login and refresh sequence

~~~mermaid
sequenceDiagram
  participant B as Browser
  participant API as Sentinel API
  participant R as Redis
  participant DB as PostgreSQL
  B->>API: POST /api/v1/auth/login
  API->>DB: Verify account, password, MFA, roles
  API->>R: Create session cache entry
  API->>DB: Persist session + hashed refresh token + audit event
  API-->>B: Short-lived access token + user; refresh cookie is HttpOnly in production
  Note over B,API: Production responses also carry a CSRF token; sentinel_csrf cookie and X-CSRF-Token must match
  B->>API: Protected request with Bearer access token
  API->>R: Validate active session
  API-->>B: Authorized response
  B->>API: POST /api/v1/auth/refresh + CSRF header
  API->>DB: Rotate refresh token; revoke previous session/token
  API->>R: Invalidate previous session and cache new session
  API-->>B: New access token, rotated refresh cookie, new CSRF token
~~~

## Trust boundaries

- Browser input and all request bodies are untrusted.
- Admin APIs enforce role checks in the backend; hiding a UI control is not authorization.
- PostgreSQL and Redis are private dependencies and must use encrypted connections in production.
- JWT private keys, AES keys, OAuth secrets, SMTP credentials, and database credentials are deployment secrets and must never be committed.
- Production CORS must list exact HTTPS console origins. TLS_TERMINATED_BY_PROXY=true is valid only when a trusted platform/reverse proxy actually terminates HTTPS.
