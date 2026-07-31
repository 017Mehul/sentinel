package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/user"
	"github.com/MehulChamoli/auth-service/internal/shared/dbtx"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
	"github.com/MehulChamoli/auth-service/pkg/cache"
	"github.com/MehulChamoli/auth-service/pkg/crypto"
	"github.com/MehulChamoli/auth-service/pkg/token"
)

// dbTX aliases the shared transaction interface so existing code needs no changes.
type dbTX = dbtx.TX

type OAuthUser struct {
	ID        string
	Email     string
	Name      string
	AvatarURL string
}

type OAuthAccount struct {
	ID             string
	UserID         string
	Provider       string
	ProviderUserID string
	ProviderEmail  string
	CreatedAt      time.Time
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) GetAccountByProviderUserID(ctx context.Context, tx dbTX, provider, providerUserID string) (*OAuthAccount, error) {
	if tx == nil {
		tx = r.db
	}
	var acc OAuthAccount
	err := tx.QueryRow(ctx, `
		SELECT id, user_id, provider, provider_user_id, COALESCE(provider_email, ''), created_at
		FROM oauth_accounts
		WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&acc.ID, &acc.UserID, &acc.Provider, &acc.ProviderUserID, &acc.ProviderEmail, &acc.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrUserNotFound()
		}
		return nil, fmt.Errorf("reading oauth account: %w", err)
	}
	return &acc, nil
}

func (r *Repository) CreateRefreshToken(ctx context.Context, tx dbTX, userID, tokenHash, familyID string, expiresAt time.Time, deviceInfo map[string]any, ipAddress string) (string, error) {
	if tx == nil {
		tx = r.db
	}
	deviceJSON, _ := json.Marshal(deviceInfo)
	var ipArg any
	if ipAddress != "" {
		ipArg = ipAddress
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, device_info, ip_address, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`,
		uuid.NewString(), userID, tokenHash, familyID, deviceJSON, ipArg, expiresAt,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("creating oauth refresh token: %w", err)
	}
	return id, nil
}

func (r *Repository) CreateSession(ctx context.Context, tx dbTX, sessionID, userID, refreshTokenID, ipAddress, userAgent string, deviceInfo map[string]any) (string, error) {
	if tx == nil {
		tx = r.db
	}
	deviceJSON, _ := json.Marshal(deviceInfo)
	var ipArg any
	if ipAddress != "" {
		ipArg = ipAddress
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO sessions (id, user_id, refresh_token_id, device_info, ip_address, user_agent, last_active_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		RETURNING id`,
		sessionID, userID, refreshTokenID, deviceJSON, ipArg, userAgent,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("creating oauth session: %w", err)
	}
	return id, nil
}

func (r *Repository) CreateAccount(ctx context.Context, tx dbTX, userID, provider, providerUserID, providerEmail string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, provider_email)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (provider, provider_user_id) DO NOTHING`,
		uuid.NewString(), userID, provider, providerUserID, providerEmail,
	)
	if err != nil {
		return fmt.Errorf("creating oauth account: %w", err)
	}
	return nil
}

type Service struct {
	repo       *Repository
	users      *user.Repository
	cache      *cache.Client
	tokens     *token.Manager
	configs    map[string]*oauth2.Config
	security   config.SecurityConfig
}

func NewService(repo *Repository, users *user.Repository, c *cache.Client, tokens *token.Manager, cfg *config.Config) *Service {
	configs := make(map[string]*oauth2.Config)
	if cfg.OAuth.Google.ClientID != "" {
		configs["google"] = &oauth2.Config{
			ClientID:     cfg.OAuth.Google.ClientID,
			ClientSecret: cfg.OAuth.Google.ClientSecret,
			RedirectURL:  cfg.OAuth.Google.RedirectURL,
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
			Endpoint:     google.Endpoint,
		}
	}
	if cfg.OAuth.GitHub.ClientID != "" {
		configs["github"] = &oauth2.Config{
			ClientID:     cfg.OAuth.GitHub.ClientID,
			ClientSecret: cfg.OAuth.GitHub.ClientSecret,
			RedirectURL:  cfg.OAuth.GitHub.RedirectURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		}
	}

	return &Service{
		repo:     repo,
		users:    users,
		cache:    c,
		tokens:   tokens,
		configs:  configs,
		security: cfg.Security,
	}
}

func (s *Service) GetAuthURL(ctx context.Context, provider string) (string, error) {
	cfg, ok := s.configs[provider]
	if !ok {
		return "", apperrors.ErrNotImplemented()
	}

	state, err := crypto.SecureRandom(24)
	if err != nil {
		return "", err
	}

	if s.cache != nil {
		_ = s.cache.Set(ctx, "oauth_state:"+state, provider, 10*time.Minute)
	}

	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

func (s *Service) HandleCallback(ctx context.Context, provider, code, state, ipAddress, userAgent string) (*AuthResponse, error) {
	// CSRF protection: always validate the state parameter.
	// If the cache is unavailable, we refuse the flow entirely rather than
	// silently skipping the check (fail-closed on security-critical validation).
	if s.cache == nil {
		return nil, apperrors.ErrServiceUnavailable("cache unavailable: cannot validate OAuth state parameter")
	}
	storedProvider, err := s.cache.Get(ctx, "oauth_state:"+state)
	if err != nil || storedProvider != provider {
		return nil, apperrors.ErrResetTokenInvalid()
	}
	_ = s.cache.Delete(ctx, "oauth_state:"+state)

	cfg, ok := s.configs[provider]
	if !ok {
		return nil, apperrors.ErrNotImplemented()
	}

	oauthToken, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging oauth code: %w", err)
	}

	authUser, err := s.fetchUserInfo(ctx, provider, oauthToken)
	if err != nil {
		return nil, err
	}

	// Wrap all DB mutations in a single transaction so that partial state
	// (e.g. user created but oauth_accounts row missing) is never committed.
	tx, err := s.repo.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("beginning oauth callback transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	acc, err := s.repo.GetAccountByProviderUserID(ctx, tx, provider, authUser.ID)
	var targetUserID string

	if err == nil {
		targetUserID = acc.UserID
	} else {
		u, _, getErr := s.users.GetByEmail(ctx, tx, authUser.Email)
		if getErr == nil {
			targetUserID = u.ID
		} else {
			// New user — create account, assign role, record first login.
			created, createErr := s.users.Create(ctx, tx, user.CreateInput{
				Email:     strings.ToLower(authUser.Email),
				FullName:  authUser.Name,
				AvatarURL: &authUser.AvatarURL,
			}, "")
			if createErr != nil {
				return nil, createErr
			}
			if err := s.users.AssignRoleByName(ctx, tx, created.ID, "user"); err != nil {
				return nil, err
			}
			if err := s.users.SetLastLoginAt(ctx, tx, created.ID, time.Now()); err != nil {
				return nil, err
			}
			targetUserID = created.ID
		}
		// Link provider account — must succeed atomically with user creation.
		if err := s.repo.CreateAccount(ctx, tx, targetUserID, provider, authUser.ID, authUser.Email); err != nil {
			return nil, err
		}
	}

	u, err := s.users.GetByID(ctx, tx, targetUserID)
	if err != nil {
		return nil, err
	}

	roles, err := s.users.ListRoles(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}

	resp, err := s.issueOAuthSession(ctx, tx, *u, roles, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing oauth callback transaction: %w", err)
	}

	return resp, nil
}

// issueOAuthSession mints an access token, persists the refresh token and
// session record within the caller's transaction, then returns the full
// AuthResponse. The caller is responsible for committing the transaction.
func (s *Service) issueOAuthSession(ctx context.Context, tx dbTX, u user.User, roles []string, ipAddress, userAgent string) (*AuthResponse, error) {
	now := time.Now()
	sessionID := uuid.NewString()
	familyID := uuid.NewString()

	accessToken, _, err := s.tokens.IssueAccessToken(u.ID, sessionID, roles)
	if err != nil {
		return nil, err
	}

	rawRefresh, err := crypto.SecureRandom(32)
	if err != nil {
		return nil, err
	}

	refreshHash := crypto.SHA256Hex(rawRefresh)

	// Persist refresh token so it can be rotated and revoked later.
	refreshID, err := s.repo.CreateRefreshToken(ctx, tx, u.ID, refreshHash, familyID,
		now.Add(s.tokens.RefreshTTL()), map[string]any{"user_agent": userAgent}, ipAddress)
	if err != nil {
		return nil, err
	}

	// Persist session so it can be listed and revoked from the admin panel.
	finalSessionID, err := s.repo.CreateSession(ctx, tx, sessionID, u.ID, refreshID,
		ipAddress, userAgent, map[string]any{"user_agent": userAgent})
	if err != nil {
		return nil, err
	}

	// Write audit log so OAuth logins appear in the admin audit trail.
	// We embed this inline rather than calling auth.Repository to avoid a
	// cross-package dependency — both packages share the same audit_logs table.
	auditMeta, _ := json.Marshal(map[string]any{
		"provider":  "oauth",
		"family_id": familyID,
		"roles":     roles,
	})
	_, _ = tx.Exec(ctx, `
		INSERT INTO audit_logs (id, user_id, action, resource, resource_id, metadata, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		uuid.NewString(), u.ID, "auth.oauth_login", "session", finalSessionID,
		auditMeta, ipAddress, userAgent,
	)

	if s.cache != nil {
		_ = s.cache.SetJSON(ctx, "session:"+finalSessionID, map[string]any{
			"user_id":          u.ID,
			"refresh_token_id": refreshID,
			"family_id":        familyID,
			"action":           "oauth",
			"roles":            roles,
		}, s.tokens.RefreshTTL())
	}

	return &AuthResponse{
		User:         u,
		Roles:        roles,
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokens.AccessTTL().Seconds()),
		SessionID:    finalSessionID,
	}, nil
}

func (s *Service) fetchUserInfo(ctx context.Context, provider string, tok *oauth2.Token) (*OAuthUser, error) {
	client := s.configs[provider].Client(ctx, tok)

	switch provider {
	case "google":
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var res struct {
			ID      string `json:"id"`
			Email   string `json:"email"`
			Name    string `json:"name"`
			Picture string `json:"picture"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, err
		}
		return &OAuthUser{ID: res.ID, Email: res.Email, Name: res.Name, AvatarURL: res.Picture}, nil

	case "github":
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var res struct {
			ID        int64  `json:"id"`
			Email     string `json:"email"`
			Name      string `json:"name"`
			AvatarURL string `json:"avatar_url"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, err
		}

		if res.Email == "" {
			// Fetch primary email
			emailResp, err := client.Get("https://api.github.com/user/emails")
			if err == nil {
				defer emailResp.Body.Close()
				var emails []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				_ = json.NewDecoder(emailResp.Body).Decode(&emails)
				for _, e := range emails {
					if e.Primary {
						res.Email = e.Email
						break
					}
				}
			}
		}
		name := res.Name
		if name == "" {
			name = res.Email
		}
		return &OAuthUser{ID: fmt.Sprintf("%d", res.ID), Email: res.Email, Name: name, AvatarURL: res.AvatarURL}, nil
	}

	return nil, apperrors.ErrNotImplemented()
}

type AuthResponse struct {
	User         user.User `json:"user"`
	Roles        []string  `json:"roles"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	SessionID    string    `json:"session_id"`
}

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) GoogleLogin(c *gin.Context) {
	url, err := h.svc.GetAuthURL(c.Request.Context(), "google")
	if err != nil {
		response.Error(c, err)
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *Handler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	resp, err := h.svc.HandleCallback(c.Request.Context(), "google", code, state, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, resp)
}

func (h *Handler) GitHubLogin(c *gin.Context) {
	url, err := h.svc.GetAuthURL(c.Request.Context(), "github")
	if err != nil {
		response.Error(c, err)
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *Handler) GitHubCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	resp, err := h.svc.HandleCallback(c.Request.Context(), "github", code, state, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, resp)
}
