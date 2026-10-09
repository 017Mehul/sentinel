package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/MehulChamoli/auth-service/config"
)

// Claims extends the standard JWT claims with application-specific fields.
type Claims struct {
	jwt.RegisteredClaims
	SessionID string   `json:"sid"`
	Roles     []string `json:"roles"`
}

// TokenPair holds an access token and refresh token issued together.
type TokenPair struct {
	AccessToken  string
	RefreshToken string // raw random token (not JWT); store SHA-256 hash in DB
	ExpiresIn    int    // access token TTL in seconds
}

// Manager handles RS256 JWT signing and verification.
// The private key is loaded once at startup from the Secrets Manager.
type Manager struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	issuer        string
	audience      string
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

// NewManager loads RSA keys from disk and returns a Manager.
func NewManager(cfg *config.JWTConfig) (*Manager, error) {
	privateKey, publicKey, err := loadKeyPair(cfg.PrivateKeyPath, cfg.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	return &Manager{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		accessTTL:  cfg.AccessTokenTTL,
		refreshTTL: cfg.RefreshTokenTTL,
	}, nil
}

func loadKeyPair(privatePath, publicPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if privatePath == "" {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("generating private key: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil
	}

	privPEM, privErr := os.ReadFile(privatePath) // #nosec G304 -- key path is explicit trusted startup configuration
	if privErr != nil {
		if !os.IsNotExist(privErr) {
			return nil, nil, fmt.Errorf("reading private key: %w", privErr)
		}

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("generating private key: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing private key: %w", err)
	}

	if publicPath == "" {
		return privateKey, &privateKey.PublicKey, nil
	}

	pubPEM, pubErr := os.ReadFile(publicPath) // #nosec G304 -- key path is explicit trusted startup configuration
	if pubErr != nil {
		if !os.IsNotExist(pubErr) {
			return nil, nil, fmt.Errorf("reading public key: %w", pubErr)
		}
		return privateKey, &privateKey.PublicKey, nil
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// IssueAccessToken creates and signs a new RS256 access token for the given user.
func (m *Manager) IssueAccessToken(userID, sessionID string, roles []string) (string, *Claims, error) {
	now := time.Now()
	jti := uuid.New().String()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID,
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
		},
		SessionID: sessionID,
		Roles:     roles,
	}

	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(m.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("signing access token: %w", err)
	}

	return tokenStr, claims, nil
}

// Verify parses and validates a signed access token, returning the claims.
// It enforces algorithm, issuer, and audience checks.
func (m *Manager) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(t *jwt.Token) (any, error) {
			// Explicitly reject any algorithm other than RS256 to prevent
			// the "algorithm confusion" attack (e.g., alg:none or HS256 with public key).
			if t.Method != jwt.SigningMethodRS256 {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return m.publicKey, nil
		},
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}

// AccessTTL returns the configured access token time-to-live.
func (m *Manager) AccessTTL() time.Duration {
	return m.accessTTL
}

// RefreshTTL returns the configured refresh token time-to-live.
func (m *Manager) RefreshTTL() time.Duration {
	return m.refreshTTL
}

// ── JWKS ─────────────────────────────────────────────────────────────────────

// JWKSResponse is the JSON Web Key Set served at /.well-known/jwks.json.
// Downstream services use this to validate access tokens without contacting the auth service.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK is a JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`  // Key type: "RSA"
	Use string `json:"use"`  // Usage: "sig"
	Alg string `json:"alg"`  // Algorithm: "RS256"
	Kid string `json:"kid"`  // Key ID
	N   string `json:"n"`    // RSA modulus (base64url)
	E   string `json:"e"`    // RSA exponent (base64url)
}

// JWKS returns the public key set for this service.
// The key ID (kid) is a fixed string; in production, rotate keys with versioned kids.
func (m *Manager) JWKS() JWKSResponse {
	pub := m.publicKey
	return JWKSResponse{
		Keys: []JWK{{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: "auth-service-key-v1",
			N:   base64URLEncode(pub.N.Bytes()),
			E:   base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
}

// ServeJWKS writes the JWKS JSON response to w.
func (m *Manager) ServeJWKS(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if err := json.NewEncoder(w).Encode(m.JWKS()); err != nil { return }
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Sentinel errors for token validation failures.
var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
)
