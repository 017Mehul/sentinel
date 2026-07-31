package secrets

import (
	"context"
	"fmt"

	"github.com/MehulChamoli/auth-service/config"
)

// NewProvider is a factory that returns the configured SecretProvider based on
// the SECRET_PROVIDER environment variable. Adding a new provider requires only
// adding a case here — all callers use the SecretProvider interface unchanged.
func NewProvider(cfg *config.SecretsConfig) (SecretProvider, error) {
	switch cfg.Provider {
	case "local", "":
		return NewLocalProvider(), nil
	case "vault":
		return NewVaultProvider(cfg.Vault.Addr, cfg.Vault.Token, cfg.Vault.MountPath)
	case "aws":
		return NewAWSProvider(cfg.AWS.Region, cfg.AWS.SecretPrefix)
	default:
		return nil, fmt.Errorf("unknown secret provider %q (valid: local, vault, aws)", cfg.Provider)
	}
}

// MustGet is a convenience wrapper that panics if the secret cannot be retrieved.
// Use only at startup for mandatory secrets (e.g., JWT private key).
func MustGet(ctx context.Context, p SecretProvider, key string) string {
	val, err := p.Get(ctx, key)
	if err != nil {
		panic(fmt.Sprintf("failed to retrieve mandatory secret %q: %v", key, err))
	}
	return val
}
