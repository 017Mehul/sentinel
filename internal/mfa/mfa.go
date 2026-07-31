package mfa

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/shared/contextkeys"
	"github.com/MehulChamoli/auth-service/internal/shared/dbtx"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
	"github.com/MehulChamoli/auth-service/internal/user"
	"github.com/MehulChamoli/auth-service/pkg/crypto"
)

// dbTX aliases the shared transaction interface so existing code needs no changes.
type dbTX = dbtx.TX

// Secret describes an MFA secret record.
type Secret struct {
	ID        string
	UserID    string
	SecretEnc string
	IsEnabled bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// BackupCode holds a backup code record.
type BackupCode struct {
	ID        string
	UserID    string
	CodeHash  string
	UsedAt    *time.Time
	CreatedAt time.Time
}

type Repository struct {
	db *pgxpool.Pool
}

type Service struct {
	repo     *Repository
	users    *user.Repository
	security config.SecurityConfig
	appName  string
}

type Handler struct {
	svc *Service
}

type SetupResponse struct {
	Issuer       string   `json:"issuer"`
	AccountName  string   `json:"account_name"`
	Secret       string   `json:"secret"`
	QRCodeBase64  string   `json:"qr_code_base64"`
	BackupCodes  []string `json:"backup_codes"`
}

type VerifyRequest struct {
	Code string `json:"code" binding:"required"`
}

type DisableRequest struct {
	Code string `json:"code" binding:"required"`
}

func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func NewService(repo *Repository, users *user.Repository, security *config.SecurityConfig) *Service {
	return &Service{repo: repo, users: users, security: *security, appName: "auth-service"}
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func (r *Repository) beginTx(ctx context.Context) (pgx.Tx, error) {
	return r.db.BeginTx(ctx, pgx.TxOptions{})
}

func (r *Repository) GetSecret(ctx context.Context, tx dbTX, userID string) (*Secret, error) {
	if tx == nil {
		tx = r.db
	}
	var s Secret
	err := tx.QueryRow(ctx, `
		SELECT id, user_id, secret_enc, is_enabled, created_at, updated_at
		FROM mfa_secrets
		WHERE user_id = $1`,
		userID,
	).Scan(&s.ID, &s.UserID, &s.SecretEnc, &s.IsEnabled, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrMFANotEnabled()
		}
		return nil, fmt.Errorf("reading mfa secret: %w", err)
	}
	return &s, nil
}

func (r *Repository) UpsertSecret(ctx context.Context, tx dbTX, userID, secretEnc string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO mfa_secrets (id, user_id, secret_enc, is_enabled)
		VALUES ($1, $2, $3, FALSE)
		ON CONFLICT (user_id)
		DO UPDATE SET secret_enc = EXCLUDED.secret_enc, is_enabled = FALSE, updated_at = NOW()`,
		uuid.NewString(), userID, secretEnc,
	)
	if err != nil {
		return fmt.Errorf("upserting mfa secret: %w", err)
	}
	return nil
}

func (r *Repository) SetEnabled(ctx context.Context, tx dbTX, userID string, enabled bool) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE mfa_secrets SET is_enabled = $2, updated_at = NOW() WHERE user_id = $1`, userID, enabled)
	if err != nil {
		return fmt.Errorf("setting mfa enabled: %w", err)
	}
	return nil
}

func (r *Repository) ReplaceBackupCodes(ctx context.Context, tx dbTX, userID string, codeHashes []string) error {
	if tx == nil {
		tx = r.db
	}
	if _, err := tx.Exec(ctx, `DELETE FROM backup_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("clearing backup codes: %w", err)
	}
	if len(codeHashes) == 0 {
		return nil
	}
	// Build a single parameterised INSERT for all codes in one round-trip.
	args := make([]any, 0, len(codeHashes)*3)
	query := "INSERT INTO backup_codes (id, user_id, code_hash) VALUES "
	for i, hash := range codeHashes {
		if i > 0 {
			query += ", "
		}
		base := i * 3
		query += fmt.Sprintf("($%d, $%d, $%d)", base+1, base+2, base+3)
		args = append(args, uuid.NewString(), userID, hash)
	}
	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("inserting backup codes: %w", err)
	}
	return nil
}

func (r *Repository) UseBackupCode(ctx context.Context, tx dbTX, userID, codeHash string) error {
	if tx == nil {
		tx = r.db
	}
	ct, err := tx.Exec(ctx, `
		UPDATE backup_codes
		SET used_at = NOW()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		userID, codeHash,
	)
	if err != nil {
		return fmt.Errorf("using backup code: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return apperrors.ErrInvalidBackupCode()
	}
	return nil
}

func (s *Service) Setup(ctx context.Context, userID string) (*SetupResponse, error) {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning mfa setup transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	u, err := s.users.GetByID(ctx, tx, userID)
	if err != nil {
		return nil, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.appName,
		AccountName: u.Email,
		Period:      30,
		SecretSize:  20,
	})
	if err != nil {
		return nil, fmt.Errorf("generating totp secret: %w", err)
	}

	secretEnc, err := crypto.AESEncrypt([]byte(s.security.AESEncryptionKey), key.Secret())
	if err != nil {
		return nil, err
	}
	if err := s.repo.UpsertSecret(ctx, tx, userID, secretEnc); err != nil {
		return nil, err
	}

	backupCodes, hashedCodes, err := generateBackupCodes(s.security.MFABackupCodeCount)
	if err != nil {
		return nil, err
	}
	if err := s.repo.ReplaceBackupCodes(ctx, tx, userID, hashedCodes); err != nil {
		return nil, err
	}

	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("encoding qr: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing mfa setup: %w", err)
	}

	return &SetupResponse{
		Issuer:      s.appName,
		AccountName: u.Email,
		Secret:      key.Secret(),
		QRCodeBase64: base64.StdEncoding.EncodeToString(png),
		BackupCodes: backupCodes,
	}, nil
}

func (s *Service) Enabled(ctx context.Context, userID string) (bool, error) {
	secret, err := s.repo.GetSecret(ctx, nil, userID)
	if err != nil {
		if ae := apperrors.AsAppError(err); ae != nil && ae.Code == apperrors.CodeMFANotEnabled {
			return false, nil
		}
		return false, err
	}
	return secret.IsEnabled, nil
}

func (s *Service) Enable(ctx context.Context, userID, code string) error {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("beginning mfa enable transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	secret, err := s.repo.GetSecret(ctx, tx, userID)
	if err != nil {
		return err
	}
	plain, err := crypto.AESDecrypt([]byte(s.security.AESEncryptionKey), secret.SecretEnc)
	if err != nil {
		return err
	}
	if !totp.Validate(code, plain) {
		return apperrors.ErrMFAInvalidOTP()
	}
	if err := s.repo.SetEnabled(ctx, tx, userID, true); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) Disable(ctx context.Context, userID, code string) error {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("beginning mfa disable transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := s.verifyWithBackupOrTOTP(ctx, tx, userID, code); err != nil {
		return err
	}
	if err := s.repo.SetEnabled(ctx, tx, userID, false); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) VerifyForLogin(ctx context.Context, tx dbTX, userID, code string) error {
	// NOTE: tx is provided by the caller (Service.Login) so that backup-code
	// consumption is part of the same transaction as the login itself.
	// If the outer transaction rolls back, the backup code is NOT consumed.
	if tx == nil {
		// Standalone call path: open our own transaction.
		ownTx, err := s.repo.beginTx(ctx)
		if err != nil {
			return fmt.Errorf("beginning mfa verify transaction: %w", err)
		}
		defer ownTx.Rollback(ctx) //nolint:errcheck
		if err := s.verifyWithBackupOrTOTP(ctx, ownTx, userID, code); err != nil {
			return err
		}
		return ownTx.Commit(ctx)
	}
	return s.verifyWithBackupOrTOTP(ctx, tx, userID, code)
}

func (s *Service) verifyWithBackupOrTOTP(ctx context.Context, tx dbTX, userID, code string) error {
	secret, err := s.repo.GetSecret(ctx, tx, userID)
	if err != nil {
		return err
	}
	if code == "" {
		return apperrors.ErrMFAInvalidOTP()
	}

	plain, err := crypto.AESDecrypt([]byte(s.security.AESEncryptionKey), secret.SecretEnc)
	if err != nil {
		return err
	}
	if totp.Validate(code, plain) {
		return nil
	}
	if len(code) == 8 {
		if err := s.repo.UseBackupCode(ctx, tx, userID, crypto.SHA256Hex(code)); err == nil {
			return nil
		}
	}
	return apperrors.ErrMFAInvalidOTP()
}

func (h *Handler) Setup(c *gin.Context) {
	actualUserID, ok := c.Get(string(contextkeys.UserID))
	if !ok {
		response.Error(c, apperrors.ErrForbidden())
		return
	}
	resp, err := h.svc.Setup(c.Request.Context(), fmt.Sprint(actualUserID))
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, resp)
}

func (h *Handler) Enable(c *gin.Context) {
	userID, ok := c.Get(string(contextkeys.UserID))
	if !ok {
		response.Error(c, apperrors.ErrForbidden())
		return
	}
	var req VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}
	if err := h.svc.Enable(c.Request.Context(), fmt.Sprint(userID), req.Code); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"status": "enabled"})
}

func (h *Handler) Disable(c *gin.Context) {
	userID, ok := c.Get(string(contextkeys.UserID))
	if !ok {
		response.Error(c, apperrors.ErrForbidden())
		return
	}
	var req DisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}
	if err := h.svc.Disable(c.Request.Context(), fmt.Sprint(userID), req.Code); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"status": "disabled"})
}

func generateBackupCodes(count int) ([]string, []string, error) {
	if count <= 0 {
		count = 10
	}
	plain := make([]string, 0, count)
	hashed := make([]string, 0, count)
	for i := 0; i < count; i++ {
		code, err := crypto.SecureRandom(4)
		if err != nil {
			return nil, nil, err
		}
		plain = append(plain, code)
		hashed = append(hashed, crypto.SHA256Hex(code))
	}
	return plain, hashed, nil
}
