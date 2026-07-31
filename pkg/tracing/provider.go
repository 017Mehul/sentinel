package tracing

import (
	"context"
	"fmt"

	"github.com/MehulChamoli/auth-service/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Provider is a wrapper around the process-wide OpenTelemetry tracer provider.
type Provider struct {
	tp *sdktrace.TracerProvider
}

// NewTracerProvider initializes OpenTelemetry tracing with OTLP exporter if enabled.
func NewTracerProvider(cfg *config.OTELConfig) (*Provider, error) {
	if cfg == nil || !cfg.Enabled {
		return &Provider{}, nil
	}

	ctx := context.Background()

	endpoint := cfg.ExporterEndpoint
	if endpoint == "" {
		endpoint = "localhost:4317"
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(endpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTel resource: %w", err)
	}

	sampler := sdktrace.AlwaysSample()
	if cfg.SampleRatio > 0 && cfg.SampleRatio < 1.0 {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRatio)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{tp: tp}, nil
}

// Tracer returns a tracer from the global OTel provider.
func (p *Provider) Tracer(name string, opts ...oteltrace.TracerOption) oteltrace.Tracer {
	return otel.Tracer(name, opts...)
}

// Shutdown flushes and closes the tracer provider.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.tp != nil {
		return p.tp.Shutdown(ctx)
	}
	return nil
}
