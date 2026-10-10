package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
	"github.com/MehulChamoli/auth-service/internal/user"
	"github.com/MehulChamoli/auth-service/pkg/crypto"
)

type emailVerificationTokenRecord struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

type passwordResetTokenRecord struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// RegistrationResponse is returned after creating a new account.
// NOTE: EmailVerificationToken is only populated in non-production environments.
// In production the token is delivered exclusively via email; the field is
// omitted from the response body (omitempty) so clients cannot rely on it.
type RegistrationResponse struct {
	User                       user.User `json:"user"`
	Roles                      []string  `json:"roles"`
	EmailVerificationToken     string    `json:"email_verification_token,omitempty"`
	EmailVerificationExpiresIn int       `json:"email_verification_expires_in,omitempty"`
	Message                    string    `json:"message"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ForgotPasswordResponse is returned after requesting a password reset.
// NOTE: PasswordResetToken is only populated in non-production environments.
// In production the token is delivered exclusively via email.
type ForgotPasswordResponse struct {
	PasswordResetToken     string `json:"password_reset_token,omitempty"`
	PasswordResetExpiresIn int    `json:"password_reset_expires_in,omitempty"`
	Message                string `json:"message"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

func (s *Service) Register(ctx context.Context, req RegisterRequest, ipAddress, userAgent string) (*RegistrationResponse, error) {
	return s.createUserAndVerification(ctx, req, ipAddress, userAgent)
}

func (s *Service) createUserAndVerification(ctx context.Context, req RegisterRequest, ipAddress, userAgent string) (*RegistrationResponse, error) {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning register transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if s.hibp != nil {
		pwned, _, hibpErr := s.hibp.IsPwned(ctx, req.Password)
	if hibpErr != nil {
		// HIBP is unavailable — log the error so operators can alert on this,
		// but fail-open to avoid blocking registrations during outages.
		log.Warn().Err(hibpErr).Msg("HIBP check failed — proceeding without breach validation")
		} else if pwned {
			return nil, apperrors.ErrPasswordBreached()
		}
	}

	passwordHash, err := crypto.HashPassword(req.Password, s.security.BcryptCost)
	if err != nil {
		return nil, err
	}

	u, err := s.users.Create(ctx, tx, user.CreateInput{
		Email:     strings.TrimSpace(strings.ToLower(req.Email)),
		FullName:  strings.TrimSpace(req.FullName),
		AvatarURL: req.AvatarURL,
	}, passwordHash)
	if err != nil {
		return nil, err
	}

	if err := s.users.AssignRoleByName(ctx, tx, u.ID, "user"); err != nil {
		return nil, err
	}

	roles, err := s.users.ListRoles(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}

	token, expiresAt, err := s.createEmailVerificationToken(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}

	if err := s.repo.WriteAuditLog(ctx, tx, u.ID, "", "auth.register", "user", u.ID, map[string]any{
		"email": u.Email,
	}, ipAddress, userAgent); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing register transaction: %w", err)
	}

	// In production the verification token is delivered via email only.
	// Never expose it in the HTTP response body where it could appear in
	// access logs, proxies, or browser history.
	verifyToken := token
	expiresIn := int(time.Until(expiresAt).Seconds())
	if s.isProd {
		verifyToken = ""
		expiresIn = 0
	}

	return &RegistrationResponse{
		User:                       *u,
		Roles:                      roles,
		EmailVerificationToken:     verifyToken,
		EmailVerificationExpiresIn: expiresIn,
		Message:                    "Account created. Verify your email before signing in.",
	}, nil
}

func (s *Service) createEmailVerificationToken(ctx context.Context, tx dbTX, userID string) (string, time.Time, error) {
	if tx == nil {
		tx = s.repo.db
	}
	token, err := crypto.SecureRandom(32)
	if err != nil {
		return "", time.Time{}, err
	}
	tokenHash := crypto.SHA256Hex(token)
	expiresAt := time.Now().Add(s.security.EmailVerificationTokenTTL)
	if s.security.EmailVerificationTokenTTL <= 0 {
		expiresAt = time.Now().Add(24 * time.Hour)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)`,
		uuid.NewString(), userID, tokenHash, expiresAt,
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating email verification token: %w", err)
	}
	return token, expiresAt, nil
}

func (s *Service) getEmailVerificationToken(ctx context.Context, tx dbTX, token string) (*emailVerificationTokenRecord, error) {
	if tx == nil {
		tx = s.repo.db
	}
	var rec emailVerificationTokenRecord
	tokenHash := crypto.SHA256Hex(token)
	err := tx.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, used_at
		FROM email_verification_tokens
		WHERE token_hash = $1`,
		tokenHash,
	).Scan(&rec.ID, &rec.UserID, &rec.TokenHash, &rec.ExpiresAt, &rec.UsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrInvalidVerifyToken()
		}
		return nil, fmt.Errorf("reading email verification token: %w", err)
	}
	return &rec, nil
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("beginning verify email transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	rec, err := s.getEmailVerificationToken(ctx, tx, token)
	if err != nil {
		return err
	}
	if rec.UsedAt != nil {
		return apperrors.ErrEmailAlreadyVerified()
	}
	if time.Now().After(rec.ExpiresAt) {
		return apperrors.ErrVerificationExpired()
	}

	u, err := s.users.GetByID(ctx, tx, rec.UserID)
	if err != nil {
		return err
	}
	if u.IsVerified {
		return apperrors.ErrEmailAlreadyVerified()
	}

	if err := s.repo.MarkUserEmailVerified(ctx, tx, rec.UserID); err != nil {
		return err
	}
	if err := s.repo.MarkEmailVerificationTokenUsed(ctx, tx, rec.ID); err != nil {
		return err
	}
	if err := s.repo.WriteAuditLog(ctx, tx, rec.UserID, "", "auth.email_verified", "user", rec.UserID, nil, "", ""); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) RequestPasswordReset(ctx context.Context, email, ipAddress, userAgent string) (*ForgotPasswordResponse, error) {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning password reset request transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	u, _, err := s.users.GetByEmail(ctx, tx, strings.TrimSpace(strings.ToLower(email)))
	if err != nil {
		if ae := apperrors.AsAppError(err); ae != nil && ae.Code == apperrors.CodeUserNotFound {
			return &ForgotPasswordResponse{Message: "If the account exists, a reset token has been generated."}, tx.Commit(ctx)
		}
		return nil, err
	}

	token, expiresAt, err := s.createPasswordResetToken(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}
	if err := s.repo.WriteAuditLog(ctx, tx, u.ID, "", "auth.password_reset_requested", "user", u.ID, map[string]any{"email": u.Email}, ipAddress, userAgent); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing password reset request transaction: %w", err)
	}

	// In production the reset token is delivered via email only.
	resetToken := token
	expiresIn := int(time.Until(expiresAt).Seconds())
	if s.isProd {
		resetToken = ""
		expiresIn = 0
	}

	return &ForgotPasswordResponse{
		PasswordResetToken:     resetToken,
		PasswordResetExpiresIn: expiresIn,
		Message:                "If the account exists, a reset token has been generated.",
	}, nil
}

func (s *Service) createPasswordResetToken(ctx context.Context, tx dbTX, userID string) (string, time.Time, error) {
	if tx == nil {
		tx = s.repo.db
	}
	token, err := crypto.SecureRandom(32)
	if err != nil {
		return "", time.Time{}, err
	}
	tokenHash := crypto.SHA256Hex(token)
	expiresAt := time.Now().Add(s.security.PasswordResetTokenTTL)
	if s.security.PasswordResetTokenTTL <= 0 {
		expiresAt = time.Now().Add(30 * time.Minute)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)`,
		uuid.NewString(), userID, tokenHash, expiresAt,
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating password reset token: %w", err)
	}
	return token, expiresAt, nil
}

func (s *Service) getPasswordResetToken(ctx context.Context, tx dbTX, token string) (*passwordResetTokenRecord, error) {
	if tx == nil {
		tx = s.repo.db
	}
	var rec passwordResetTokenRecord
	tokenHash := crypto.SHA256Hex(token)
	err := tx.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, used_at
		FROM password_reset_tokens
		WHERE token_hash = $1`,
		tokenHash,
	).Scan(&rec.ID, &rec.UserID, &rec.TokenHash, &rec.ExpiresAt, &rec.UsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrResetTokenInvalid()
		}
		return nil, fmt.Errorf("reading password reset token: %w", err)
	}
	return &rec, nil
}

func (s *Service) ResetPassword(ctx context.Context, token, newPassword, ipAddress, userAgent string) error {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("beginning password reset transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	rec, err := s.getPasswordResetToken(ctx, tx, token)
	if err != nil {
		return err
	}
	if rec.UsedAt != nil {
		return apperrors.ErrResetTokenExpired()
	}
	if time.Now().After(rec.ExpiresAt) {
		return apperrors.ErrResetTokenExpired()
	}

	currentHash, err := s.users.GetPasswordHashByID(ctx, tx, rec.UserID)
	if err != nil {
		return err
	}
	if currentHash != "" && crypto.ComparePassword(currentHash, newPassword) == nil {
		return apperrors.ErrPasswordSameAsOld()
	}

	nextHash, err := crypto.HashPassword(newPassword, s.security.BcryptCost)
	if err != nil {
		return err
	}
	if err := s.repo.UpdatePasswordHash(ctx, tx, rec.UserID, nextHash); err != nil {
		return err
	}
	if err := s.users.ResetFailedAttempts(ctx, tx, rec.UserID); err != nil {
		return err
	}
	if err := s.repo.RevokeRefreshTokensByUser(ctx, tx, rec.UserID); err != nil {
		return err
	}
	if err := s.repo.RevokeSessionsByUser(ctx, tx, rec.UserID); err != nil {
		return err
	}
	if err := s.repo.MarkPasswordResetTokenUsed(ctx, tx, rec.ID); err != nil {
		return err
	}
	if err := s.repo.WriteAuditLog(ctx, tx, rec.UserID, "", "auth.password_reset_completed", "user", rec.UserID, nil, ipAddress, userAgent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *Repository) MarkUserEmailVerified(ctx context.Context, tx dbTX, userID string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE users SET is_verified = TRUE, updated_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("marking user email verified: %w", err)
	}
	return nil
}

func (r *Repository) MarkEmailVerificationTokenUsed(ctx context.Context, tx dbTX, tokenID string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE email_verification_tokens SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, tokenID)
	if err != nil {
		return fmt.Errorf("marking email verification token used: %w", err)
	}
	return nil
}

func (r *Repository) MarkPasswordResetTokenUsed(ctx context.Context, tx dbTX, tokenID string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, tokenID)
	if err != nil {
		return fmt.Errorf("marking password reset token used: %w", err)
	}
	return nil
}

func (r *Repository) UpdatePasswordHash(ctx context.Context, tx dbTX, userID, passwordHash string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("updating password hash: %w", err)
	}
	return nil
}

func (r *Repository) RevokeSessionsByUser(ctx context.Context, tx dbTX, userID string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `
		UPDATE sessions
		SET deleted_at = NOW()
		FROM refresh_tokens rt
		WHERE sessions.refresh_token_id = rt.id
		  AND rt.user_id = $1
		  AND sessions.deleted_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("revoking sessions by user: %w", err)
	}
	return nil
}

func (h *Handler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}
	if err := h.svc.VerifyEmail(c.Request.Context(), req.Token); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"status": "verified"})
}

func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}
	resp, err := h.svc.RequestPasswordReset(c.Request.Context(), req.Email, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, resp)
}

func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), req.Token, req.Password, c.ClientIP(), c.GetHeader("User-Agent")); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"status": "password_reset"})
}

func (h *Handler) RequestPasswordReset(c *gin.Context) {
	h.ForgotPassword(c)
}
