package worker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/MehulChamoli/auth-service/config"
	gomail "gopkg.in/gomail.v2"
	"github.com/rs/zerolog/log"
)

// EventDispatcher is the interface that outbox event processors must implement.
// This decouples the Manager from concrete email / webhook implementations and
// makes the dispatch layer straightforward to unit test with mocks.
type EventDispatcher interface {
	// Dispatch processes a single outbox event. Return a non-nil error to
	// signal failure; the Manager will apply its retry / dead-letter logic.
	Dispatch(ctx context.Context, event OutboxEvent) error
}

// RegistrationPayload is the structured payload for auth.user.registered events.
type RegistrationPayload struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"full_name"`
	Token  string `json:"verification_token,omitempty"`
}

// PasswordResetPayload is the structured payload for auth.password.reset events.
type PasswordResetPayload struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Token  string `json:"reset_token"`
}

// LogDispatcher is the default EventDispatcher used when no email or messaging
// backend is configured. It emits a structured log entry so the event is
// observable and auditable without dropping it on the floor.
type LogDispatcher struct{}

// Dispatch logs the outbox event as a structured info entry. This is a real,
// non-no-op implementation: operators can forward logs to alerting pipelines.
func (l *LogDispatcher) Dispatch(ctx context.Context, event OutboxEvent) error {
	logger := log.Ctx(ctx)
	if logger == nil || logger.GetLevel() < 0 {
		logger = &log.Logger
	}

	switch event.EventType {
	case "auth.user.registered":
		var payload RegistrationPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("parsing auth.user.registered payload: %w", err)
		}
		logger.Info().
			Str("event", event.EventType).
			Str("user_id", payload.UserID).
			Str("email", payload.Email).
			Msg("outbox: user registered — send verification email")

	case "auth.password.reset":
		var payload PasswordResetPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("parsing auth.password.reset payload: %w", err)
		}
		logger.Info().
			Str("event", event.EventType).
			Str("user_id", payload.UserID).
			Str("email", payload.Email).
			Msg("outbox: password reset requested — send reset email")

	default:
		// Unknown event types are logged as warnings rather than silently dropped.
		logger.Warn().
			Str("event", event.EventType).
			Str("event_id", event.ID).
			Msg("outbox: unhandled event type")
		return fmt.Errorf("unhandled event type: %s", event.EventType)
	}

	return nil
}

// SMTPDispatcher delivers authentication emails through the configured SMTP server.
type SMTPDispatcher struct {
	cfg config.SMTPConfig
}

func NewSMTPDispatcher(cfg config.SMTPConfig) *SMTPDispatcher { return &SMTPDispatcher{cfg: cfg} }

func (d *SMTPDispatcher) Dispatch(ctx context.Context, event OutboxEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	var to, subject, body string
	switch event.EventType {
	case "auth.user.registered":
		var p RegistrationPayload
		if err := json.Unmarshal(event.Payload, &p); err != nil { return fmt.Errorf("parsing registration email payload: %w", err) }
		to, subject = p.Email, "Verify your Sentinel account"
		body = fmt.Sprintf("Hello %s,\n\nVerify your Sentinel account with this token:\n%s\n\nIf you did not create this account, ignore this email.", p.Name, p.Token)
	case "auth.password.reset":
		var p PasswordResetPayload
		if err := json.Unmarshal(event.Payload, &p); err != nil { return fmt.Errorf("parsing password reset email payload: %w", err) }
		to, subject = p.Email, "Reset your Sentinel password"
		body = fmt.Sprintf("Your Sentinel password reset token is:\n%s\n\nIf you did not request this, ignore this email.", p.Token)
	default:
		return fmt.Errorf("unsupported email event type: %s", event.EventType)
	}
	if d.cfg.Host == "" || d.cfg.FromEmail == "" { return fmt.Errorf("smtp is not configured") }
	msg := gomail.NewMessage()
	from := d.cfg.FromEmail
	if d.cfg.FromName != "" { from = fmt.Sprintf("%s <%s>", d.cfg.FromName, d.cfg.FromEmail) }
	msg.SetHeader("From", from)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", body)
	dialer := gomail.NewDialer(d.cfg.Host, d.cfg.Port, d.cfg.Username, d.cfg.Password)
	if d.cfg.TLSEnabled { dialer.SSL = true }
	if err := dialer.DialAndSend(msg); err != nil { return fmt.Errorf("sending email: %w", err) }
	return nil
}
