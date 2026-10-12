# Sentinel Web UI

Portfolio-facing security console for Sentinel. The UI uses the approved light enterprise visual system: soft blue atmospheric washes, white surfaces, navy typography, restrained blue accents, dense but readable security data, and responsive behavior.

The console is intentionally dependency-light and can be deployed independently as a static site. Demo metrics are seeded presentation data and are labeled as a demo environment; the Go API remains the source of truth for authentication, sessions, MFA, RBAC, and audit operations.

To enable the optional API health check, define `window.SENTINEL_API_BASE` before loading `app.js`.
