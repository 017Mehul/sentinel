# Sentinel Web Console

Static HTML/CSS/JavaScript console for the Sentinel Go IAM API. It is a single frontend, not a second backend.

## Local run

From the repository root:

~~~bash
python3 -m http.server 5173 -d web
~~~

Open http://localhost:5173. In a separate terminal, start the API stack with Docker Compose and configure a verified local account. Local email verification is visible in Mailpit at http://localhost:8025.

## API connection

- Select **Connect API** and use http://localhost:8080 for local development.
- For Vercel production, set the project environment variable SENTINEL_API_BASE to the backend HTTPS origin. The build fails if it is missing or invalid, generates dist/config.js with the origin fixed and URL override disabled, and copies only static assets into dist. The API origin is public configuration, not a secret. Do not hand-edit config.js for production.
- The API must allow the exact console origin in CORS and allow credentials for production refresh cookies.
- Access tokens stay in memory. Production refresh tokens use a Secure HttpOnly cookie and a separate CSRF cookie; refresh/logout send the in-memory CSRF token in X-CSRF-Token.
- The UI does not write tokens to localStorage or sessionStorage.

## Live views

- GET /api/v1/users/me and PATCH /api/v1/users/me — profile
- GET /api/v1/sessions and DELETE /api/v1/sessions/current — current user's sessions and current-session revocation
- GET /api/v1/admin/users — paginated admin directory
- GET /api/v1/admin/sessions and DELETE /api/v1/admin/sessions/{id} — admin session control
- GET /api/v1/admin/roles and GET /api/v1/admin/permissions — RBAC catalogue
- GET /api/v1/admin/audit-logs — audit events
- GET /api/v1/mfa/status and POST /api/v1/mfa/setup, /enable, /disable — MFA management
- GET /healthz, GET /ready, and GET /version — service status

Administrative endpoints require admin privileges enforced by the backend. The console's controls are not a substitute for backend authorization.

## Explicit limitations

- Authentication activity charts, geographic session distribution, and aggregate MFA adoption are not exposed by the current API; the console labels those views illustrative or unavailable.
- OAuth provider login/callback routes exist, but callbacks currently return JSON and are not bridged into the console's in-memory session. Use password login to establish the console session.
- The console cannot create new users because the backend does not currently expose an admin user-creation endpoint.
- A connected screenshot is captured only by the manual Connected Console Screenshot workflow after successful login against a real API; no screenshot is fabricated or represented as live before that run.

Open the interactive API reference at api-docs.html. The spec is in openapi.yaml and docs/api/openapi.yaml. See the repository root README, docs/architecture.md, docs/threat-model.md, docs/demo.md, and SECURITY.md.
