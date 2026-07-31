package secrets

import "context"

// SecretProvider abstracts how secrets (keys, credentials, tokens) are retrieved.
// Implementations include: LocalProvider (.env), VaultProvider (HashiCorp Vault),
// AWSProvider (AWS Secrets Manager).
//
// The interface is intentionally minimal — production services should use Get only.
// Set and Rotate are provided for operational tooling.
type SecretProvider interface {
	// Get retrieves the secret value for the given key.
	// Returns an error if the key does not exist or access is denied.
	Get(ctx context.Context, key string) (string, error)

	// Set stores or updates a secret value.
	// Not all providers support writes (e.g., environment variables are read-only).
	Set(ctx context.Context, key, value string) error

	// Rotate requests that the provider generates a new secret for the key.
	// Returns the new value. Not all providers support this operation.
	Rotate(ctx context.Context, key string) (string, error)
}

// ErrSecretNotFound is returned by Get when a key does not exist.
type ErrSecretNotFound struct {
	Key string
}

func (e *ErrSecretNotFound) Error() string {
	return "secret not found: " + e.Key
}
