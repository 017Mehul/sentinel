package config

import (
	"os"
	"regexp"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration struct. All fields are validated at startup.
type Config struct {
	App      AppConfig      `mapstructure:"app"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Secrets  SecretsConfig  `mapstructure:"secrets"`
	NATS     NATSConfig     `mapstructure:"nats"`
	SMTP     SMTPConfig     `mapstructure:"smtp"`
	OAuth    OAuthConfig    `mapstructure:"oauth"`
	Security SecurityConfig `mapstructure:"security"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	CORS     CORSConfig     `mapstructure:"cors"`
	HIBP     HIBPConfig     `mapstructure:"hibp"`
	OTEL     OTELConfig     `mapstructure:"otel"`
	Features FeaturesConfig `mapstructure:"features"`
	Webhook  WebhookConfig  `mapstructure:"webhook"`
	TLS      TLSConfig      `mapstructure:"tls"`
}

type AppConfig struct {
	Name            string        `mapstructure:"name"`
	Env             string        `mapstructure:"env"`
	Version         string        `mapstructure:"version"`
	Port            int           `mapstructure:"port"`
	GRPCPort        int           `mapstructure:"grpc_port"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Name            string        `mapstructure:"name"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
}

// DSN returns a pgx-compatible connection string.
func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		d.Host, d.Port, d.Name, d.User, d.Password, d.SSLMode,
	)
}

type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type JWTConfig struct {
	PrivateKeyPath   string        `mapstructure:"private_key_path"`
	PublicKeyPath    string        `mapstructure:"public_key_path"`
	AccessTokenTTL   time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `mapstructure:"refresh_token_ttl"`
	Issuer           string        `mapstructure:"issuer"`
	Audience         string        `mapstructure:"audience"`
}

type SecretsConfig struct {
	Provider string      `mapstructure:"provider"`
	Vault    VaultConfig `mapstructure:"vault"`
	AWS      AWSConfig   `mapstructure:"aws"`
}

type VaultConfig struct {
	Addr      string `mapstructure:"addr"`
	Token     string `mapstructure:"token"`
	MountPath string `mapstructure:"mount_path"`
}

type AWSConfig struct {
	Region       string `mapstructure:"region"`
	SecretPrefix string `mapstructure:"secret_prefix"`
}

type NATSConfig struct {
	URL            string `mapstructure:"url"`
	StreamName     string `mapstructure:"stream_name"`
	StreamSubjects string `mapstructure:"stream_subjects"`
	ConsumerName   string `mapstructure:"consumer_name"`
}

type SMTPConfig struct {
	Host       string `mapstructure:"host"`
	Port       int    `mapstructure:"port"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	FromName   string `mapstructure:"from_name"`
	FromEmail  string `mapstructure:"from_email"`
	TLSEnabled bool   `mapstructure:"tls_enabled"`
}

type OAuthConfig struct {
	StateSecret string              `mapstructure:"state_secret"`
	Google      OAuthProviderConfig `mapstructure:"google"`
	GitHub      OAuthProviderConfig `mapstructure:"github"`
}

type OAuthProviderConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

type SecurityConfig struct {
	AESEncryptionKey          string        `mapstructure:"aes_encryption_key"`
	BcryptCost                int           `mapstructure:"bcrypt_cost"`
	AccountLockMaxAttempts    int           `mapstructure:"account_lock_max_attempts"`
	AccountLockDuration       time.Duration `mapstructure:"account_lock_duration"`
	PasswordResetTokenTTL     time.Duration `mapstructure:"password_reset_token_ttl"`
	EmailVerificationTokenTTL time.Duration `mapstructure:"email_verification_token_ttl"`
	IdempotencyKeyTTL         time.Duration `mapstructure:"idempotency_key_ttl"`
	ReplayDetectWindow        time.Duration `mapstructure:"replay_detect_window"`
	MFAOTPWindow              int           `mapstructure:"mfa_otp_window"`
	MFABackupCodeCount        int           `mapstructure:"mfa_backup_code_count"`
}

type RateLimitConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	AuthRPM    int           `mapstructure:"auth_rpm"`
	GeneralRPM int           `mapstructure:"general_rpm"`
	Window     time.Duration `mapstructure:"window"`
}

type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
}

type HIBPConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	APITimeout time.Duration `mapstructure:"api_timeout"`
}

type OTELConfig struct {
	Enabled          bool    `mapstructure:"enabled"`
	ServiceName      string  `mapstructure:"service_name"`
	ExporterEndpoint string  `mapstructure:"exporter_endpoint"`
	SampleRatio      float64 `mapstructure:"sample_ratio"`
}

type FeaturesConfig struct {
	File           string        `mapstructure:"file"`
	ReloadInterval time.Duration `mapstructure:"reload_interval"`
}

type WebhookConfig struct {
	DeliveryTimeout time.Duration `mapstructure:"delivery_timeout"`
	MaxRetries      int           `mapstructure:"max_retries"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// Load reads configuration from the YAML file and overlays environment variables.
// Environment variables take precedence over file values.
func Load(configPath string) (*Config, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", configPath, err)
	}

	expanded := expandEnvPlaceholders(string(raw))

	v := viper.New()
	v.SetConfigType("yaml")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadConfig(strings.NewReader(expanded)); err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", configPath, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	normalize(&cfg)

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return &cfg, nil
}

var envPattern = regexp.MustCompile(`\$\{([A-Z0-9_]+)(?::([^}]*))?\}`)

// expandEnvPlaceholders resolves ${VAR:default} placeholders before YAML parsing.
func expandEnvPlaceholders(input string) string {
	return envPattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := envPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}

		if value, ok := os.LookupEnv(parts[1]); ok {
			return value
		}
		return parts[2]
	})
}

// normalize adjusts values that are commonly expressed as delimited strings in env vars.
func normalize(cfg *Config) {
	if len(cfg.CORS.AllowedOrigins) == 1 && strings.Contains(cfg.CORS.AllowedOrigins[0], ",") {
		parts := strings.Split(cfg.CORS.AllowedOrigins[0], ",")
		cfg.CORS.AllowedOrigins = cfg.CORS.AllowedOrigins[:0]
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				cfg.CORS.AllowedOrigins = append(cfg.CORS.AllowedOrigins, trimmed)
			}
		}
	}
}

// validate enforces mandatory configuration rules at startup so the service
// fails fast rather than discovering misconfiguration at runtime.
func validate(cfg *Config) error {
	var errs []string

	if cfg.App.Port == 0 {
		errs = append(errs, "app.port must be set")
	}
	if cfg.App.GRPCPort == 0 {
		errs = append(errs, "app.grpc_port must be set")
	}
	if cfg.Database.Host == "" {
		errs = append(errs, "database.host must be set")
	}
	if cfg.Database.Name == "" {
		errs = append(errs, "database.name must be set")
	}
	if cfg.Redis.Addr == "" {
		errs = append(errs, "redis.addr must be set")
	}
	if cfg.JWT.PrivateKeyPath == "" {
		errs = append(errs, "jwt.private_key_path must be set")
	}
	if cfg.JWT.PublicKeyPath == "" {
		errs = append(errs, "jwt.public_key_path must be set")
	}
	if cfg.JWT.Issuer == "" {
		errs = append(errs, "jwt.issuer must be set")
	}
	if len(cfg.Security.AESEncryptionKey) != 32 {
		errs = append(errs, "security.aes_encryption_key must be exactly 32 bytes")
	}
	if cfg.Security.BcryptCost < 10 || cfg.Security.BcryptCost > 14 {
		errs = append(errs, "security.bcrypt_cost must be between 10 and 14")
	}

	if cfg.IsProduction() {
		if cfg.Database.Password == "" || cfg.Database.Password == "changeme" {
			errs = append(errs, "database.password must be set to a non-default value in production")
		}
		if cfg.OAuth.StateSecret == "" || cfg.OAuth.StateSecret == "changeme" {
			errs = append(errs, "oauth.state_secret must be set to a non-default value in production")
		}
		if cfg.Security.AESEncryptionKey == "" || strings.Contains(cfg.Security.AESEncryptionKey, "changeme") {
			errs = append(errs, "security.aes_encryption_key must be a non-default value in production")
		}
		if cfg.JWT.PrivateKeyPath == "" || cfg.JWT.PublicKeyPath == "" {
			errs = append(errs, "jwt key paths must be set in production")
		} else {
			if _, err := os.Stat(cfg.JWT.PrivateKeyPath); err != nil {
				errs = append(errs, "jwt.private_key_path must point to an existing key in production")
			}
			if _, err := os.Stat(cfg.JWT.PublicKeyPath); err != nil {
				errs = append(errs, "jwt.public_key_path must point to an existing key in production")
			}
		}
		if !cfg.TLS.Enabled {
			errs = append(errs, "tls.enabled must be true in production")
		}
		if len(cfg.CORS.AllowedOrigins) == 0 {
			errs = append(errs, "cors.allowed_origins must contain at least one origin in production")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// IsDevelopment returns true when running in local development mode.
func (c *Config) IsDevelopment() bool {
	return c.App.Env == "development"
}

// IsProduction returns true when running in production mode.
func (c *Config) IsProduction() bool {
	return c.App.Env == "production"
}
