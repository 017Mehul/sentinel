# Sentinel Demo Runbook

## Local stack

Prerequisites: Go 1.26.9, Docker Compose, OpenSSL, and Node.js 22 for frontend syntax checks.

1. Clone the repository and enter its root.
2. Copy .env.example to .env.
3. Set a strong local DB_PASSWORD and a 32-character AES_ENCRYPTION_KEY. Example generators: openssl rand -hex 24 and openssl rand -hex 16. Do not reuse production secrets.
4. Generate local RS256 keys with make gen-keys.
5. Start the stack with make docker-up.
6. Check liveness at http://localhost:8080/healthz, readiness at http://localhost:8080/ready, Jaeger at http://localhost:16686, and Mailpit at http://localhost:8025.
7. Serve the console with python3 -m http.server 5173 -d web, then open http://localhost:5173.
8. Select Connect API and sign in with a verified account. Registration and verification emails can be inspected in Mailpit.
9. Test profile editing, MFA enrollment, role assignment, audit logs, session revocation, refresh rotation, and logout.

Do not create a public demo account with admin privileges or publish credentials in the repository. For a public demo, use a disposable account with minimal seeded data, rotate its password regularly, and restrict permissions.

## Static console deployment on Vercel

1. Import the GitHub repository into Vercel.
2. Set the **Root Directory** to `web` and enable including files outside the root only if your project setup requires it (the web build is self-contained).
3. Use the default build command from `web/vercel.json`: `node build-config.mjs`; output directory: `dist`.
4. Set `SENTINEL_API_BASE` as a Vercel build-time environment variable to the final HTTPS API origin (origin only, no path/query/credentials). The build intentionally fails if this is missing or not HTTPS.
5. Configure the Go API's `CORS_ALLOWED_ORIGINS` to the exact Vercel production domain and any explicit preview domain that you actually intend to allow. Avoid wildcard origins for production.
6. Deploy and verify the browser network panel shows successful `/api/v1/auth/login`, `/api/v1/users/me`, and `/ready` requests. Do not publish a screenshot until the live connection pill appears.

The repository does not have Vercel project identifiers or deployment credentials, so a live deployment must be initiated from your Vercel account.

## Production deployment preparation

docker-compose.production.yml is a reference template for an API/worker pair behind a trusted HTTPS reverse proxy. It expects externally managed PostgreSQL and Redis. Before starting it:

- provide PostgreSQL credentials with DB_SSL_MODE=require or stronger;
- provide Redis credentials with REDIS_TLS_ENABLED=true;
- mount protected JWT private/public key files;
- supply a random 32-byte AES key and a strong OAuth state secret;
- configure a verified SMTP sender and real provider credentials;
- set CORS_ALLOWED_ORIGINS to the exact HTTPS console origin; set Vercel SENTINEL_API_BASE to the API HTTPS origin (the static build fails if missing or invalid);
- set TLS_TERMINATED_BY_PROXY=true only behind a trusted HTTPS proxy;
- restrict the API to private ingress, configure backups, and test restore procedures.

Never paste secrets into GitHub issues, README files, screenshots, or chat logs. Use the hosting platform's protected environment/secrets manager.

## Connected screenshot

A real connected screenshot is not committed as sample art. Run the manual Connected Console Screenshot GitHub Actions workflow after a reachable API and a dedicated demo account exist. Store SENTINEL_API_BASE, SENTINEL_DEMO_EMAIL, and SENTINEL_DEMO_PASSWORD as protected repository secrets. The workflow fails instead of capturing a screenshot if login and the live API connection indicator do not succeed.

## Static console deployment (Vercel)

The repository includes a manual GitHub Actions workflow named **Deploy Web Console to Vercel**. It deploys only the static frontend; it does not provision or deploy the Go API.

Configure the following before running it:

- Repository secrets: `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID`.
- Repository variable: `SENTINEL_API_BASE`, set to the deployed API's HTTPS origin (origin only; no path, credentials, query, or fragment).
- Vercel project root directory: `web`, with production deployment permissions enabled for the token.
- The API's CORS allowlist must include the exact deployed console origin, and production refresh-cookie requests must allow credentials.

The workflow intentionally fails when any required value is missing or the API origin is not HTTPS. Do not add credentials to `web/config.js`; it is public frontend configuration, not a secret store.

The Go API and outbox worker still need deployment to a container host with managed PostgreSQL and TLS-enabled Redis. Configure those using the production Compose reference or the hosting provider's equivalent. The repository does not currently contain cloud credentials, and no public API deployment is claimed.
