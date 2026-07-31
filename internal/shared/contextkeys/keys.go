// Package contextkeys defines typed keys for values stored in request contexts.
// Using a dedicated type (instead of plain strings) prevents key collisions
// between packages and makes context usage greppable.
package contextkeys

// Key is the type used for all context keys in this service.
type Key string

const (
	// RequestID is a UUID generated per-request for tracing.
	RequestID Key = "request_id"

	// CorrelationID is an externally-provided trace identifier (e.g. from a gateway).
	CorrelationID Key = "correlation_id"

	// TraceID is the OpenTelemetry trace ID for the current span.
	TraceID Key = "trace_id"

	// SpanID is the OpenTelemetry span ID for the current span.
	SpanID Key = "span_id"

	// UserID is the authenticated user's UUID.
	UserID Key = "user_id"

	// UserEmail is the authenticated user's email.
	UserEmail Key = "user_email"

	// SessionID is the active session UUID.
	SessionID Key = "session_id"

	// UserRoles is the slice of role names assigned to the authenticated user.
	UserRoles Key = "user_roles"

	// ClientIP is the originating IP address extracted from the request.
	ClientIP Key = "client_ip"

	// UserAgent is the request User-Agent header value.
	UserAgent Key = "user_agent"
)
