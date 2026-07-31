package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// LocalProvider reads secrets from environment variables and Viper config.
// This is the default provider for local development and CI.
// Env var lookup is case-insensitive; dots are replaced with underscores
// (e.g., "jwt.private_key" → JWT_PRIVATE_KEY).
type LocalProvider struct{}

// NewLocalProvider creates a LocalProvider.
// It expects Viper to already be configured (call config.Load before this).
func NewLocalProvider() *LocalProvider {
	return &LocalProvider{}
}

// Get returns the value of the secret by first checking the environment via Viper.
func (p *LocalProvider) Get(_ context.Context, key string) (string, error) {
	// Normalise: "jwt.private_key" → "JWT_PRIVATE_KEY" for env lookup.
	envKey := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	val, ok := os.LookupEnv(envKey)
	if !ok || val == "" {
		// Fall back to the original key shape for callers that already use env-style names.
		if val, ok = os.LookupEnv(strings.ReplaceAll(key, ".", "_")); !ok || val == "" {
			return "", &ErrSecretNotFound{Key: key}
		}
	}

	if strings.TrimSpace(val) == "" {
		return "", &ErrSecretNotFound{Key: key}
	}
	return val, nil
}

// Set is a no-op for the local provider; environment variables are immutable at runtime.
func (p *LocalProvider) Set(_ context.Context, key, _ string) error {
	return fmt.Errorf("LocalProvider.Set: environment variables cannot be set at runtime (key: %s)", key)
}

// Rotate is not supported for local environment variables.
func (p *LocalProvider) Rotate(_ context.Context, key string) (string, error) {
	return "", fmt.Errorf("LocalProvider.Rotate: rotation not supported (key: %s)", key)
}
