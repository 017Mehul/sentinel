# Sentinel Web UI

Portfolio-facing security console for Sentinel. It uses a light enterprise visual system with soft blue washes, white surfaces, navy typography, restrained blue accents, and responsive layouts.

## Connect to the Go API

1. Run the Sentinel Go API and its PostgreSQL/Redis dependencies.
2. Configure the API's CORS allowed origins to include the exact origin serving this static UI.
3. Open the console and choose **Connect API**.
4. Enter the API base URL (for example, `https://api.example.com`), then sign in with a Sentinel account. An MFA code is accepted when required.
5. The console requests the current profile, sessions, roles, permissions, and audit logs using the bearer access token returned by `POST /api/v1/auth/login`.

The access and refresh tokens are held **in memory only**; the UI does not persist them in localStorage or sessionStorage. Refreshing the page clears the connection and requires signing in again. Use HTTPS for any deployed API or console.

## Current API-backed views

- Profile identity from `GET /api/v1/users/me`
- Sessions visible to the authenticated user from `GET /api/v1/sessions`
- Roles from `GET /api/v1/admin/roles` (admin role required)
- Permissions from `GET /api/v1/admin/permissions` (admin role required)
- Audit events from `GET /api/v1/admin/audit-logs` (admin role required)
- Sign-in through `POST /api/v1/auth/login`

Some routes intentionally return authorization errors for non-admin users; the console reports these as unavailable rather than fabricating data.

## Important limitations

The existing Go API does not currently expose an administrative list-users endpoint, a session-revocation-by-ID endpoint, a GET endpoint for MFA enrollment status, or a provider-configuration endpoint. Those areas are not represented as working administrative controls in this integration. The original overview charts and sample user/security tables remain presentation examples and must not be interpreted as live telemetry. The live-data tables below the overview show the records actually returned by the API.

No backend endpoint is added or bypassed by the frontend. Authorization is enforced by Sentinel itself.

## Static deployment

Serve this directory as a static site. If using a fixed API URL, define `window.SENTINEL_API_BASE` before `app.js` loads; otherwise, the Connect API dialog accepts it at runtime. The backend must allow the deployed frontend origin through its CORS configuration.
