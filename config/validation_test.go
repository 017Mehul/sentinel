package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validProductionConfig(t *testing.T) *Config {
	t.Helper()

	dir := t.TempDir()
	privateKey := filepath.Join(dir, "private.pem")
	publicKey := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(privateKey, []byte("test private key fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicKey, []byte("test public key fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	return &Config{
		App: AppConfig{Env: "production", Port: 8080, GRPCPort: 9090},
		Database: DatabaseConfig{
			Host: "db.example.com", Name: "sentinel",
			Password: "database-secret-value-123456", SSLMode: "require",
		},
		Redis: RedisConfig{
			Addr: "redis.example.com:6379", Password: "redis-secret-value-123456", TLSEnabled: true,
		},
		JWT: JWTConfig{
			PrivateKeyPath: privateKey, PublicKeyPath: publicKey,
			Issuer: "sentinel", Audience: "api",
		},
		OAuth: OAuthConfig{StateSecret: "oauth-state-secret-with-at-least-32-bytes"},
		Security: SecurityConfig{
			AESEncryptionKey: "0123456789abcdef0123456789abcdef",
			BcryptCost:       12,
		},
		SMTP: SMTPConfig{Host: "smtp.example.com", Username: "smtp-user", Password: "smtp-password", FromEmail: "security@example.net", TLSEnabled: true},
		CORS: CORSConfig{
			AllowedOrigins: []string{"https://console.example.com"},
			AllowCredentials: true,
		},
		TLS: TLSConfig{TerminatedByProxy: true},
	}
}

func TestProductionConfigAcceptsSecureProxyTerminatedSetup(t *testing.T) {
	if err := validate(validProductionConfig(t)); err != nil {
		t.Fatalf("expected secure production config to pass, got: %v", err)
	}
}

func TestProductionConfigRejectsWeakSecrets(t *testing.T) {
	cfg := validProductionConfig(t)
	cfg.Database.Password = "changeme"
	cfg.OAuth.StateSecret = "changeme-oauth-state-hmac-secret"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "database.password") || !strings.Contains(err.Error(), "oauth.state_secret") {
		t.Fatalf("expected database and OAuth placeholder errors, got: %v", err)
	}
}

func TestProductionConfigRequiresEncryptedDatabaseAndRedis(t *testing.T) {
	cfg := validProductionConfig(t)
	cfg.Database.SSLMode = "disable"
	cfg.Redis.TLSEnabled = false

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "database.ssl_mode") || !strings.Contains(err.Error(), "redis.tls_enabled") {
		t.Fatalf("expected database and Redis TLS errors, got: %v", err)
	}
}

func TestProductionConfigRejectsWildcardOrNonOriginCORS(t *testing.T) {
	for _, origin := range []string{"*", "https://console.example.com/path", "http://console.example.com"} {
		t.Run(origin, func(t *testing.T) {
			cfg := validProductionConfig(t)
			cfg.CORS.AllowedOrigins = []string{origin}
			if err := validate(cfg); err == nil || !strings.Contains(err.Error(), "cors.allowed_origins") {
				t.Fatalf("expected CORS origin to be rejected, got: %v", err)
			}
		})
	}
}
