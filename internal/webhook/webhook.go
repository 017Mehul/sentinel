package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// maxConcurrentDeliveries caps the number of simultaneous outbound HTTP webhook
// calls. Unbounded goroutine spawning inside a loop will exhaust memory under
// high event volume. A semaphore-backed pool bounds resource usage while still
// delivering to all endpoints concurrently.
const maxConcurrentDeliveries = 10

// deliveryMaxRetries is the number of times to retry a failed webhook delivery
// before giving up (exponential back-off: 1s, 2s, 4s).
const deliveryMaxRetries = 3

type Endpoint struct {
	ID       string   `json:"id"`
	UserID   string   `json:"user_id"`
	URL      string   `json:"url"`
	Secret   string   `json:"-"`
	Events   []string `json:"events"`
	IsActive bool     `json:"is_active"`
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) ListSubscribedEndpoints(ctx context.Context, eventType string) ([]Endpoint, error) {
	if r.db == nil {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, url, secret, events, is_active
		FROM webhook_endpoints
		WHERE is_active = TRUE AND $1 = ANY(events)`,
		eventType,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Endpoint
	for rows.Next() {
		var ep Endpoint
		if err := rows.Scan(&ep.ID, &ep.UserID, &ep.URL, &ep.Secret, &ep.Events, &ep.IsActive); err == nil {
			list = append(list, ep)
		}
	}
	return list, rows.Err()
}

type Dispatcher struct {
	repo   *Repository
	client *http.Client
	// sem is a buffered channel used as a counting semaphore to bound the
	// number of concurrent outbound HTTP webhook calls.
	sem chan struct{}
}

func NewDispatcher(repo *Repository) *Dispatcher {
	return &Dispatcher{
		repo:   repo,
		client: &http.Client{Timeout: 10 * time.Second},
		sem:    make(chan struct{}, maxConcurrentDeliveries),
	}
}

// Dispatch fans out the event payload to all subscribed endpoints using a
// bounded worker pool. Each delivery runs in its own goroutine gated by a
// semaphore, so at most maxConcurrentDeliveries HTTP calls are in-flight
// simultaneously. The parent context is respected for cancellation.
func (d *Dispatcher) Dispatch(ctx context.Context, eventType string, payload any) error {
	endpoints, err := d.repo.ListSubscribedEndpoints(ctx, eventType)
	if err != nil || len(endpoints) == 0 {
		return err
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling webhook payload: %w", err)
	}

	for _, ep := range endpoints {
		ep := ep // capture loop variable
		// Acquire a semaphore slot before launching the goroutine so we never
		// have more than maxConcurrentDeliveries goroutines sending HTTP calls.
		select {
		case d.sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		go func() {
			defer func() { <-d.sem }()
			d.deliverWithRetry(ctx, ep, eventType, bodyBytes)
		}()
	}

	return nil
}

// deliverWithRetry attempts to deliver a webhook up to deliveryMaxRetries times
// using exponential back-off (1s → 2s → 4s). It uses the caller's context so
// deliveries are cancelled when the parent operation is cancelled.
func (d *Dispatcher) deliverWithRetry(ctx context.Context, ep Endpoint, eventType string, body []byte) {
	backoff := time.Second
	for attempt := 1; attempt <= deliveryMaxRetries; attempt++ {
		if err := d.sendWebhook(ctx, ep, eventType, body); err == nil {
			return
		} else if attempt < deliveryMaxRetries {
			log.Warn().
				Err(err).
				Str("endpoint_id", ep.ID).
				Str("url", ep.URL).
				Int("attempt", attempt).
				Msg("webhook delivery failed, retrying")

			select {
			case <-time.After(backoff):
				backoff *= 2
			case <-ctx.Done():
				return
			}
		} else {
			log.Error().
				Err(err).
				Str("endpoint_id", ep.ID).
				Str("url", ep.URL).
				Int("attempts", deliveryMaxRetries).
				Msg("webhook delivery permanently failed after max retries")
		}
	}
}

func (d *Dispatcher) sendWebhook(ctx context.Context, ep Endpoint, eventType string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating webhook request: %w", err)
	}

	sig := computeHMAC(body, ep.Secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	req.Header.Set("X-Webhook-Event", eventType)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func computeHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
