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

const defaultKeyID = "auth-service-key-v1"

type Claims struct {
	jwt.RegisteredClaims
	SessionID string   `json:"sid"`
	Roles     []string `json:"roles"`
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

type Manager struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	currentKeyID   string
	previousKeyID  string
	previousPubKey *rsa.PublicKey
	issuer         string
	audience       string
	accessTTL      time.Duration
	refreshTTL     time.Duration
}

func NewManager(cfg *config.JWTConfig) (*Manager, error) {
	privateKey, publicKey, err := loadKeyPair(cfg.PrivateKeyPath, cfg.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	currentID := cfg.CurrentKeyID
	if currentID == "" {
		currentID = defaultKeyID
	}

	var previousKey *rsa.PublicKey
	if cfg.PreviousPublicKeyPath != "" {
		previousKey, err = loadPublicKey(cfg.PreviousPublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading previous JWT public key: %w", err)
		}
		if cfg.PreviousKeyID == "" {
			return nil, fmt.Errorf("jwt.previous_key_id must be set when jwt.previous_public_key_path is configured")
		}
		if cfg.PreviousKeyID == currentID {
			return nil, fmt.Errorf("jwt.previous_key_id must differ from jwt.current_key_id")
		}
	}

	return &Manager{
		privateKey: privateKey,
		publicKey: publicKey,
		currentKeyID: currentID,
		previousKeyID: cfg.PreviousKeyID,
		previousPubKey: previousKey,
		issuer: cfg.Issuer,
		audience: cfg.Audience,
		accessTTL: cfg.AccessTokenTTL,
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

	privPEM, err := os.ReadFile(privatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("reading private key: %w", err)
		}
		privateKey, genErr := rsa.GenerateKey(rand.Reader, 2048)
		if genErr != nil {
			return nil, nil, fmt.Errorf("generating private key: %w", genErr)
		}
		return privateKey, &privateKey.PublicKey, nil
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing private key: %w", err)
	}
	if privateKey.N.BitLen() < 2048 {
		return nil, nil, fmt.Errorf("RSA private key must be at least 2048 bits")
	}

	if publicPath == "" {
		return privateKey, &privateKey.PublicKey, nil
	}
	publicKey, err := loadPublicKey(publicPath)
	if err != nil {
		return nil, nil, err
	}
	if publicKey.E != privateKey.E || publicKey.N.Cmp(privateKey.N) != 0 {
		return nil, nil, fmt.Errorf("RSA public key does not match private key")
	}
	return privateKey, publicKey, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	pubPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	if publicKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA public key must be at least 2048 bits")
	}
	return publicKey, nil
}

func (m *Manager) IssueAccessToken(userID, sessionID string, roles []string) (string, *Claims, error) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: uuid.New().String(), Subject: userID, Issuer: m.issuer,
			Audience: jwt.ClaimStrings{m.audience}, IssuedAt: jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
		},
		SessionID: sessionID, Roles: roles,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.currentKeyID
	tokenStr, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("signing access token: %w", err)
	}
	return tokenStr, claims, nil
}

func (m *Manager) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		switch kid {
		case "":
			// Backwards compatibility for tokens minted before kid was introduced.
			return m.publicKey, nil
		case m.currentKeyID:
			return m.publicKey, nil
		case m.previousKeyID:
			if m.previousPubKey == nil {
				return nil, fmt.Errorf("previous signing key is not configured")
			}
			return m.previousPubKey, nil
		default:
			return nil, fmt.Errorf("unknown signing key id: %q", kid)
		}
	}, jwt.WithIssuer(m.issuer), jwt.WithAudience(m.audience), jwt.WithExpirationRequired())
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

func (m *Manager) AccessTTL() time.Duration { return m.accessTTL }
func (m *Manager) RefreshTTL() time.Duration { return m.refreshTTL }

type JWKSResponse struct { Keys []JWK `json:"keys"` }
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N string `json:"n"`
	E string `json:"e"`
}

func (m *Manager) JWKS() JWKSResponse {
	keys := []JWK{m.publicJWK(m.currentKeyID, m.publicKey)}
	if m.previousPubKey != nil {
		keys = append(keys, m.publicJWK(m.previousKeyID, m.previousPubKey))
	}
	return JWKSResponse{Keys: keys}
}

func (m *Manager) publicJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{Kty:"RSA", Use:"sig", Alg:"RS256", Kid:kid,
		N:base64URLEncode(pub.N.Bytes()), E:base64URLEncode(big.NewInt(int64(pub.E)).Bytes())}
}

func (m *Manager) ServeJWKS(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(m.JWKS()); err != nil { return }
}

func base64URLEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
)
