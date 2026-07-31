// Package secrets — HashiCorp Vault provider stub.
// TODO: Implement using github.com/hashicorp/vault/api
//
// Wire this provider by setting SECRET_PROVIDER=vault and providing:
//   VAULT_ADDR, VAULT_TOKEN, VAULT_MOUNT_PATH
//
// Implementation sketch:
//   client, _ := vault.NewClient(&vault.Config{Address: cfg.Addr})
//   client.SetToken(cfg.Token)
//   secret, _ := client.KVv2(cfg.MountPath).Get(ctx, key)
//   return secret.Data["value"].(string), nil
package secrets

import "context"

// VaultProvider retrieves secrets from HashiCorp Vault KV v2.
type VaultProvider struct {
	// TODO: add *vault.Client field
	addr      string
	mountPath string
}

// NewVaultProvider creates a VaultProvider.
// TODO: initialise vault client, authenticate, and verify connectivity.
func NewVaultProvider(addr, token, mountPath string) (*VaultProvider, error) {
	return &VaultProvider{addr: addr, mountPath: mountPath}, nil
}

func (p *VaultProvider) Get(_ context.Context, key string) (string, error) {
	// TODO: implement
	return "", &ErrSecretNotFound{Key: key}
}

func (p *VaultProvider) Set(_ context.Context, key, value string) error {
	// TODO: implement KVv2 Put
	return nil
}

func (p *VaultProvider) Rotate(_ context.Context, key string) (string, error) {
	// TODO: implement Vault secret rotation
	return "", nil
}
