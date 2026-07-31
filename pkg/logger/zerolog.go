package logger

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// contextKey is an unexported type for context keys in this package.
type contextKey struct{}

var loggerKey = contextKey{}

// Config configures the logger.
type Config struct {
	// Level is the minimum log level ("debug", "info", "warn", "error").
	Level string
	// Pretty enables human-readable console output (development only).
	Pretty bool
	// ServiceName is included in every log line as "service".
	ServiceName string
	// ServiceVersion is included in every log line as "version".
	ServiceVersion string
}

// New initialises the global zerolog logger and returns a configured instance.
// Call this once at startup and use FromContext/WithContext for per-request loggers.
func New(cfg Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	zerolog.TimeFieldFormat = time.RFC3339Nano

	var w io.Writer = os.Stdout
	if cfg.Pretty {
		w = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "15:04:05.000",
		}
	}

	logger := zerolog.New(w).
		With().
		Timestamp().
		Str("service", cfg.ServiceName).
		Str("version", cfg.ServiceVersion).
		Logger()

	// Set as the global logger so log.Info() etc. work without context.
	log.Logger = logger

	return logger
}

// WithContext returns a new context with the given logger embedded.
func WithContext(ctx context.Context, logger zerolog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext retrieves the logger from context.
// Falls back to the global logger if none is stored.
func FromContext(ctx context.Context) zerolog.Logger {
	if l, ok := ctx.Value(loggerKey).(zerolog.Logger); ok {
		return l
	}
	return log.Logger
}

// WithFields returns a child logger with additional key-value fields.
// Useful for enriching a request-scoped logger with trace_id, user_id, etc.
func WithFields(ctx context.Context, fields map[string]any) context.Context {
	l := FromContext(ctx)
	e := l.With()
	for k, v := range fields {
		e = e.Interface(k, v)
	}
	return WithContext(ctx, e.Logger())
}
