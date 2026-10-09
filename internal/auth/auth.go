package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/mfa"
	"github.com/MehulChamoli/auth-service/internal/shared/dbtx"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
	"github.com/MehulChamoli/auth-service/internal/user"
	"github.com/MehulChamoli/auth-service/pkg/cache"
	"github.com/MehulChamoli/auth-service/pkg/crypto"
	"github.com/MehulChamoli/auth-service/pkg/token"
)

// dbTX aliases the shared transaction interface so existing code needs no changes.
type dbTX = dbtx.TX

// Repository stores auth-related persistence operations.
type Repository struct {
	db *pgxpool.Pool
}

// Service contains auth business logic.
type Service struct {
	repo      *Repository
	users     *user.Repository
	mfa       *mfa.Service
	cache     *cache.Client
	tokens    *token.Manager
	security  config.SecurityConfig
	isProd    bool // true when app.env == "production"; suppresses tokens in HTTP responses
}

// Handler exposes auth HTTP handlers.
type Handler struct {
	svc *Service
}

type RegisterRequest struct {
	Email     string  `json:"email" binding:"required,email"`
	Password  string  `json:"password" binding:"required,min=8"`
	FullName  string  `json:"full_name" binding:"required,min=2"`
	AvatarURL *string `json:"avatar_url"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	MFACode  string `json:"mfa_code"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// AuthResponse is returned for login and register operations.
type AuthResponse struct {
	User         user.User `json:"user"`
	Roles        []string  `json:"roles"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	SessionID    string    `json:"session_id"`
}

type RefreshTokenRecord struct {
	ID        string
	UserID    string
	TokenHash string
	FamilyID  string
	ExpiresAt time.Time
	RevokedAt *time.Time
	SessionID string
}

func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func NewService(repo *Repository, users *user.Repository, mfaSvc *mfa.Service, c *cache.Client, tokens *token.Manager, security *config.SecurityConfig, appEnv string) *Service {
	return &Service{
		repo:     repo,
		users:    users,
		mfa:      mfaSvc,
		cache:    c,
		tokens:   tokens,
		security: *security,
		isProd:   appEnv == "production",
	}
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func (r *Repository) beginTx(ctx context.Context) (pgx.Tx, error) {
	return r.db.BeginTx(ctx, pgx.TxOptions{})
}

func (r *Repository) CreateLoginHistory(ctx context.Context, tx dbTX, userID, email, ipAddress, userAgent string, success bool, failureReason string) error {
	if tx == nil {
		tx = r.db
	}

	var userIDArg any
	if userID != "" {
		userIDArg = userID
	}
	var ipArg any
	if parsed := net.ParseIP(ipAddress); parsed != nil {
		ipArg = parsed
	}

	_, err := tx.Exec(ctx, `
		INSERT INTO login_history (user_id, email, ip_address, user_agent, success, failure_reason)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		userIDArg, email, ipArg, userAgent, success, failureReason,
	)
	if err != nil {
		return fmt.Errorf("creating login history: %w", err)
	}
	return nil
}

func (r *Repository) CreateRefreshToken(ctx context.Context, tx dbTX, userID, tokenHash, familyID string, expiresAt time.Time, deviceInfo map[string]any, ipAddress string) (string, error) {
	if tx == nil {
		tx = r.db
	}

	deviceJSON, _ := json.Marshal(deviceInfo)
	var ipArg any
	if parsed := net.ParseIP(ipAddress); parsed != nil {
		ipArg = parsed
	}

	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, device_info, ip_address, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`,
		uuid.NewString(), userID, tokenHash, familyID, deviceJSON, ipArg, expiresAt,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("creating refresh token: %w", err)
	}
	return id, nil
}

func (r *Repository) GetRefreshTokenByHash(ctx context.Context, tx dbTX, tokenHash string) (*RefreshTokenRecord, error) {
	if tx == nil {
		tx = r.db
	}

	var rec RefreshTokenRecord
	err := tx.QueryRow(ctx, `
		SELECT rt.id, rt.user_id, rt.token_hash, rt.family_id, rt.expires_at, rt.revoked_at, COALESCE(s.id::text, '')
		FROM refresh_tokens rt
		LEFT JOIN sessions s ON s.refresh_token_id = rt.id AND s.deleted_at IS NULL
		WHERE rt.token_hash = $1`,
		tokenHash,
	).Scan(&rec.ID, &rec.UserID, &rec.TokenHash, &rec.FamilyID, &rec.ExpiresAt, &rec.RevokedAt, &rec.SessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrTokenInvalid()
		}
		return nil, fmt.Errorf("reading refresh token: %w", err)
	}
	return &rec, nil
}

func (r *Repository) RevokeRefreshTokenByID(ctx context.Context, tx dbTX, id string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

func (r *Repository) RevokeRefreshTokensByUser(ctx context.Context, tx dbTX, userID string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("revoking refresh tokens by user: %w", err)
	}
	return nil
}

func (r *Repository) CreateSession(ctx context.Context, tx dbTX, sessionID, userID, refreshTokenID, ipAddress, userAgent string, deviceInfo map[string]any) (string, error) {
	if tx == nil {
		tx = r.db
	}

	deviceJSON, _ := json.Marshal(deviceInfo)
	var ipArg any
	if parsed := net.ParseIP(ipAddress); parsed != nil {
		ipArg = parsed
	}

	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO sessions (id, user_id, refresh_token_id, device_info, ip_address, user_agent, last_active_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		RETURNING id`,
		sessionID, userID, refreshTokenID, deviceJSON, ipArg, userAgent,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}
	return id, nil
}

type SessionRecord struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	UserAgent    string    `json:"user_agent,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	LastActiveAt time.Time `json:"last_active_at"`
	CreatedAt    time.Time `json:"created_at"`
}

func (r *Repository) ListActiveSessions(ctx context.Context, userID string) ([]SessionRecord, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id::text, user_id::text, COALESCE(user_agent, ''), COALESCE(host(ip_address), ''), last_active_at, created_at
		FROM sessions
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY last_active_at DESC`, userID)
	if err != nil { return nil, fmt.Errorf("listing sessions: %w", err) }
	defer rows.Close()
	var sessions []SessionRecord
	for rows.Next() {
		var s SessionRecord
		if err := rows.Scan(&s.ID, &s.UserID, &s.UserAgent, &s.IPAddress, &s.LastActiveAt, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning session: %w", err)
		}
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil { return nil, fmt.Errorf("reading sessions: %w", err) }
	return sessions, nil
}

func (r *Repository) RevokeSession(ctx context.Context, tx dbTX, sessionID string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE sessions SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, sessionID)
	if err != nil {
		return fmt.Errorf("revoking session: %w", err)
	}
	return nil
}

func (r *Repository) RevokeSessionAndRefreshToken(ctx context.Context, sessionID string) error {
	tx, err := r.beginTx(ctx)
	if err != nil { return fmt.Errorf("beginning session revoke transaction: %w", err) }
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = (SELECT refresh_token_id FROM sessions WHERE id = $1) AND revoked_at IS NULL`, sessionID); err != nil {
		return fmt.Errorf("revoking session refresh token: %w", err)
	}
	if err := r.RevokeSession(ctx, tx, sessionID); err != nil { return err }
	if err := commitTx(ctx, tx); err != nil { return fmt.Errorf("committing session revoke: %w", err) }
	return nil
}

func (r *Repository) TouchSession(ctx context.Context, tx dbTX, sessionID string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE sessions SET last_active_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, sessionID)
	if err != nil {
		return fmt.Errorf("touching session: %w", err)
	}
	return nil
}

func (s *Service) Login(ctx context.Context, req LoginRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning login transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	u, passwordHash, err := s.users.GetByEmail(ctx, tx, strings.TrimSpace(req.Email))
	if err != nil {
		if ae := apperrors.AsAppError(err); ae != nil && ae.Code == apperrors.CodeUserNotFound {
			_ = s.repo.CreateLoginHistory(ctx, tx, "", req.Email, ipAddress, userAgent, false, "invalid_credentials")
			return nil, apperrors.ErrInvalidCredentials()
		}
		return nil, err
	}

	now := time.Now()
	if u.IsLocked && u.LockedUntil != nil && u.LockedUntil.After(now) {
		_ = s.repo.CreateLoginHistory(ctx, tx, u.ID, u.Email, ipAddress, userAgent, false, "account_locked")
		return nil, apperrors.ErrAccountLocked(u.LockedUntil.UTC().Format(time.RFC3339))
	}

	if passwordHash == "" || crypto.ComparePassword(passwordHash, req.Password) != nil {
		attempts, incErr := s.users.IncrementFailedAttempts(ctx, tx, u.ID)
		if incErr != nil {
			return nil, incErr
		}
		if attempts >= s.security.AccountLockMaxAttempts {
			lockedUntil := now.Add(s.security.AccountLockDuration)
			// Lock state failure must be propagated — a silent failure here means
			// an account that should be locked remains accessible.
			if lockErr := s.users.SetLockState(ctx, tx, u.ID, true, &lockedUntil); lockErr != nil {
				return nil, lockErr
			}
		}
		_ = s.repo.CreateLoginHistory(ctx, tx, u.ID, u.Email, ipAddress, userAgent, false, "invalid_credentials")
		return nil, apperrors.ErrInvalidCredentials()
	}

	if u.IsLocked || u.FailedAttempts > 0 {
		if err := s.users.ResetFailedAttempts(ctx, tx, u.ID); err != nil {
			return nil, err
		}
	}

	if !u.IsVerified {
		_ = s.repo.CreateLoginHistory(ctx, tx, u.ID, u.Email, ipAddress, userAgent, false, "email_not_verified")
		return nil, apperrors.ErrEmailNotVerified()
	}

	if s.mfa != nil {
		enabled, err := s.mfa.Enabled(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if enabled {
			if req.MFACode == "" {
				return nil, apperrors.ErrMFARequired()
			}
			// Pass the current transaction so backup-code consumption is atomic
			// with the rest of the login — if login fails, the code is not consumed.
			if err := s.mfa.VerifyForLogin(ctx, tx, u.ID, req.MFACode); err != nil {
				return nil, err
			}
		}
	}

	if err := s.users.SetLastLoginAt(ctx, tx, u.ID, now); err != nil {
		return nil, err
	}

	roles, err := s.users.ListRoles(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}
	return s.issueSession(ctx, tx, *u, roles, ipAddress, userAgent, "login")
}

func (s *Service) Refresh(ctx context.Context, refreshToken, ipAddress, userAgent string) (*AuthResponse, error) {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning refresh transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tokenHash := crypto.SHA256Hex(refreshToken)
	rec, err := s.repo.GetRefreshTokenByHash(ctx, tx, tokenHash)
	if err != nil {
		return nil, err
	}
	if rec.RevokedAt != nil {
		return nil, apperrors.ErrTokenReused()
	}
	if time.Now().After(rec.ExpiresAt) {
		return nil, apperrors.ErrTokenExpired()
	}

	u, err := s.users.GetByID(ctx, tx, rec.UserID)
	if err != nil {
		return nil, err
	}
	roles, err := s.users.ListRoles(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}

	if rec.SessionID != "" {
		_ = s.repo.TouchSession(ctx, tx, rec.SessionID)
	}

	// Token revocation must succeed — silently ignoring failure would leave
	// the old token valid, breaking the family-rotation security guarantee.
	if err := s.repo.RevokeRefreshTokenByID(ctx, tx, rec.ID); err != nil {
		return nil, err
	}
	if rec.SessionID != "" {
		if err := s.repo.RevokeSession(ctx, tx, rec.SessionID); err != nil {
			return nil, err
		}
	}

	response, err := s.issueSessionWithFamily(ctx, tx, *u, roles, ipAddress, userAgent, rec.FamilyID, "refresh")
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("beginning logout transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tokenHash := crypto.SHA256Hex(refreshToken)
	rec, err := s.repo.GetRefreshTokenByHash(ctx, tx, tokenHash)
	if err != nil {
		return err
	}
	if err := s.repo.RevokeRefreshTokenByID(ctx, tx, rec.ID); err != nil {
		return err
	}
	if rec.SessionID != "" {
		if err := s.repo.RevokeSession(ctx, tx, rec.SessionID); err != nil {
			return err
		}
		if s.cache != nil {
			_ = s.cache.Delete(ctx, "session:"+rec.SessionID)
		}
	}
	if err := s.repo.WriteAuditLog(ctx, tx, rec.UserID, "", "auth.logout", "session", rec.SessionID, nil, "", ""); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) issueSession(ctx context.Context, tx dbTX, u user.User, roles []string, ipAddress, userAgent, action string) (*AuthResponse, error) {
	return s.issueSessionWithFamily(ctx, tx, u, roles, ipAddress, userAgent, uuid.NewString(), action)
}

func (s *Service) issueSessionWithFamily(ctx context.Context, tx dbTX, u user.User, roles []string, ipAddress, userAgent, familyID, action string) (*AuthResponse, error) {
	now := time.Now()
	sessionID := uuid.NewString()
	accessToken, _, err := s.tokens.IssueAccessToken(u.ID, sessionID, roles)
	if err != nil {
		return nil, err
	}

	refreshToken, err := crypto.SecureRandom(32)
	if err != nil {
		return nil, err
	}

	refreshHash := crypto.SHA256Hex(refreshToken)
	refreshID, err := s.repo.CreateRefreshToken(ctx, tx, u.ID, refreshHash, familyID, now.Add(s.tokens.RefreshTTL()), deviceInfoFrom(userAgent), ipAddress)
	if err != nil {
		return nil, err
	}

	sessionID, err = s.repo.CreateSession(ctx, tx, sessionID, u.ID, refreshID, ipAddress, userAgent, deviceInfoFrom(userAgent))
	if err != nil {
		return nil, err
	}

	if err := s.repo.CreateLoginHistory(ctx, tx, u.ID, u.Email, ipAddress, userAgent, true, ""); err != nil {
		return nil, err
	}

	if err := s.repo.WriteAuditLog(ctx, tx, u.ID, "", "auth."+action, "session", sessionID, map[string]any{
		"family_id": familyID,
		"roles":     roles,
	}, ipAddress, userAgent); err != nil {
		return nil, err
	}

	if err := commitTx(ctx, tx); err != nil {
		return nil, fmt.Errorf("committing auth transaction: %w", err)
	}

	if s.cache != nil {
		_ = s.cache.SetJSON(ctx, "session:"+sessionID, map[string]any{
			"user_id":          u.ID,
			"refresh_token_id":  refreshID,
			"family_id":         familyID,
			"action":            action,
			"roles":             roles,
		}, s.tokens.RefreshTTL())
	}

	return &AuthResponse{
		User:         u,
		Roles:        roles,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokens.AccessTTL().Seconds()),
		SessionID:    sessionID,
	}, nil
}

func commitTx(ctx context.Context, tx dbTX) error {
	committer, ok := tx.(interface{ Commit(context.Context) error })
	if !ok {
		return fmt.Errorf("transaction does not support commit")
	}
	return committer.Commit(ctx)
}

func deviceInfoFrom(userAgent string) map[string]any {
	return map[string]any{
		"user_agent": userAgent,
	}
}

// WriteAuditLog records an immutable audit event for auth-domain actions.
func (r *Repository) WriteAuditLog(ctx context.Context, tx dbTX, userID, actorID, action, resource, resourceID string, metadata map[string]any, ipAddress, userAgent string) error {
	if tx == nil {
		tx = r.db
	}
	var userArg any
	if userID != "" {
		userArg = userID
	}
	var actorArg any
	if actorID != "" {
		actorArg = actorID
	}
	var resourceArg any
	if resource != "" {
		resourceArg = resource
	}
	var resourceIDArg any
	if resourceID != "" {
		resourceIDArg = resourceID
	}
	var ipArg any
	if ipAddress != "" {
		ipArg = ipAddress
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encoding audit metadata: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs (id, user_id, actor_id, action, resource, resource_id, metadata, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		uuid.NewString(), userArg, actorArg, action, resourceArg, resourceIDArg, metadataJSON, ipArg, userAgent,
	)
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}

// clientIP returns the real client IP address.
// It delegates entirely to Gin's trusted-proxy-aware c.ClientIP() rather than
// parsing X-Forwarded-For manually — the router sets SetTrustedProxies(nil)
// which means Gin itself handles the header correctly and prevents spoofing.
func clientIP(c *gin.Context) string {
	return c.ClientIP()
}

func (h *Handler) ListSessions(c *gin.Context) {
	userID, ok := c.Get(string(contextkeys.UserID))
	if !ok { response.Error(c, apperrors.ErrTokenInvalid()); return }
	uid, ok := userID.(string)
	if !ok || uid == "" { response.Error(c, apperrors.ErrTokenInvalid()); return }
	sessions, err := h.svc.repo.ListActiveSessions(c.Request.Context(), uid)
	if err != nil { response.Error(c, err); return }
	if sessions == nil { sessions = []SessionRecord{} }
	response.OK(c, gin.H{"sessions": sessions})
}

func (h *Handler) RevokeCurrentSession(c *gin.Context) {
	sessionID, ok := c.Get(string(contextkeys.SessionID))
	if !ok { response.Error(c, apperrors.ErrTokenInvalid()); return }
	sid, ok := sessionID.(string)
	if !ok || sid == "" { response.Error(c, apperrors.ErrTokenInvalid()); return }
	if err := h.svc.repo.RevokeSessionAndRefreshToken(c.Request.Context(), sid); err != nil { response.Error(c, err); return }
	if h.svc.cache != nil { _ = h.svc.cache.Delete(c.Request.Context(), "session:"+sid) }
	response.NoContent(c)
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}

	resp, err := h.svc.Register(c.Request.Context(), req, clientIP(c), c.GetHeader("User-Agent"))
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Created(c, resp)
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}

	resp, err := h.svc.Login(c.Request.Context(), req, clientIP(c), c.GetHeader("User-Agent"))
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, resp)
}

func (h *Handler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}

	resp, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken, clientIP(c), c.GetHeader("User-Agent"))
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, resp)
}

func (h *Handler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}

	if err := h.svc.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		response.Error(c, err)
		return
	}
	response.NoContent(c)
}
