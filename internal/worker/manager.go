package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const maxDeliveryAttempts = 5

type OutboxEvent struct {
	ID        string
	EventType string
	Payload   json.RawMessage
	Attempts  int
}

type Manager struct {
	ctx        context.Context
	cancel     context.CancelFunc
	db         *pgxpool.Pool
	dispatcher EventDispatcher
}

func NewManager(db *pgxpool.Pool, dispatcher EventDispatcher) *Manager {
	if dispatcher == nil {
		dispatcher = &LogDispatcher{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{ctx: ctx, cancel: cancel, db: db, dispatcher: dispatcher}
}

func (m *Manager) Start() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	log.Info().Msg("outbox worker: started")
	for {
		select {
		case <-m.ctx.Done():
			log.Info().Msg("outbox worker: shutting down")
			return
		case <-ticker.C:
			if m.db != nil {
				if err := m.processOutboxEvents(m.ctx); err != nil {
					log.Error().Err(err).Msg("outbox worker: error processing events")
				}
			}
		}
	}
}

func (m *Manager) processOutboxEvents(ctx context.Context) error {
	rows, err := m.db.Query(ctx, `
		SELECT id, event_type, payload, attempts
		FROM outbox_events
		WHERE status = 'pending' AND scheduled_at <= NOW()
		ORDER BY scheduled_at ASC
		LIMIT 10`)
	if err != nil {
		return fmt.Errorf("querying outbox events: %w", err)
	}
	defer rows.Close()

	var events []OutboxEvent
	for rows.Next() {
		var e OutboxEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.Payload, &e.Attempts); err == nil {
			events = append(events, e)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("scanning outbox rows: %w", err)
	}
	for _, event := range events {
		m.handleEvent(ctx, event)
	}
	return nil
}

// handleEvent atomically claims a pending event before dispatching it. This is
// required for safe horizontal scaling: only one worker may deliver an event.
func (m *Manager) handleEvent(ctx context.Context, event OutboxEvent) {
	result, err := m.db.Exec(ctx,
		`UPDATE outbox_events
		 SET status = 'processing', attempts = attempts + 1
		 WHERE id = $1 AND status = 'pending' AND scheduled_at <= NOW()`,
		event.ID,
	)
	if err != nil {
		log.Error().Err(err).Str("event_id", event.ID).Msg("outbox: failed to claim event")
		return
	}
	if result.RowsAffected() != 1 {
		return
	}

	dispatchErr := m.dispatcher.Dispatch(ctx, event)
	if dispatchErr == nil {
		if _, err := m.db.Exec(ctx,
			`UPDATE outbox_events SET status = 'sent', processed_at = NOW() WHERE id = $1 AND status = 'processing'`,
			event.ID,
		); err != nil {
			log.Error().Err(err).Str("event_id", event.ID).Msg("outbox: failed to mark event as sent")
		}
		return
	}

	nextAttempt := event.Attempts + 1
	if nextAttempt >= maxDeliveryAttempts {
		_, _ = m.db.Exec(ctx, `
			UPDATE outbox_events
			SET status = 'dead_lettered', last_error = $2, processed_at = NOW()
			WHERE id = $1 AND status = 'processing'`, event.ID, dispatchErr.Error())
		log.Error().Err(dispatchErr).Str("event_id", event.ID).Str("event_type", event.EventType).
			Int("attempts", nextAttempt).Msg("outbox: event dead-lettered after max retries")
		return
	}

	backoffSeconds := 1 << nextAttempt
	_, _ = m.db.Exec(ctx, `
		UPDATE outbox_events
		SET status = 'pending', last_error = $2,
		    scheduled_at = NOW() + ($3 || ' seconds')::interval
		WHERE id = $1 AND status = 'processing'`, event.ID, dispatchErr.Error(), backoffSeconds)
	log.Warn().Err(dispatchErr).Str("event_id", event.ID).Str("event_type", event.EventType).
		Int("next_attempt", nextAttempt).Int("backoff_seconds", backoffSeconds).
		Msg("outbox: event dispatch failed, scheduled for retry")
}

func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}
