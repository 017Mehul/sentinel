// Package dbtx defines the shared database transaction interface used across
// all repository layers. Every repository method accepts a TX so callers can
// compose multiple operations into a single atomic transaction.
package dbtx

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TX is the minimal interface satisfied by both *pgxpool.Pool and pgx.Tx.
// Accepting TX instead of a concrete type keeps repositories testable and
// allows multiple repo calls to share a single transaction.
type TX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}
