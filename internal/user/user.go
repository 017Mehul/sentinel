package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/MehulChamoli/auth-service/internal/shared/contextkeys"
	"github.com/MehulChamoli/auth-service/internal/shared/dbtx"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
)

// dbTX aliases the shared transaction interface so existing code needs no changes.
type dbTX = dbtx.TX

// User is the public profile returned by the API.
type User struct {
	ID            string     `json:"id"`
	Email          string     `json:"email"`
	FullName       string     `json:"full_name"`
	AvatarURL      *string    `json:"avatar_url,omitempty"`
	IsVerified     bool       `json:"is_verified"`
	IsLocked       bool       `json:"is_locked"`
	FailedAttempts int        `json:"failed_attempts"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CreateInput contains registration data.
type CreateInput struct {
	Email     string
	FullName  string
	AvatarURL *string
}

// Repository stores user persistence operations.
type Repository struct {
	db *pgxpool.Pool
}

// Service contains user business logic.
type Service struct {
	repo *Repository
}

// Handler exposes user HTTP handlers.
type Handler struct {
	svc *Service
}

func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func NewService(repo *Repository) *Service { return &Service{repo: repo} }

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Create inserts a new user record and returns the created profile.
func (r *Repository) Create(ctx context.Context, tx dbTX, input CreateInput, passwordHash string) (*User, error) {
	if tx == nil {
		tx = r.db
	}

	var avatar any
	if input.AvatarURL != nil && *input.AvatarURL != "" {
		avatar = *input.AvatarURL
	}

	var u User
	err := tx.QueryRow(ctx, `
		INSERT INTO users (id, email, password_hash, full_name, avatar_url)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, email, full_name, avatar_url, is_verified, is_locked,
		          failed_attempts, locked_until, last_login_at, created_at, updated_at`,
		uuid.NewString(), input.Email, passwordHash, input.FullName, avatar,
	).Scan(
		&u.ID, &u.Email, &u.FullName, &u.AvatarURL, &u.IsVerified, &u.IsLocked,
		&u.FailedAttempts, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, apperrors.ErrEmailTaken()
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return &u, nil
}

// GetByEmail returns a user by email and the stored password hash.
func (r *Repository) GetByEmail(ctx context.Context, tx dbTX, email string) (*User, string, error) {
	if tx == nil {
		tx = r.db
	}

	var u User
	var passwordHash string
	err := tx.QueryRow(ctx, `
		SELECT id, email, COALESCE(password_hash, ''), full_name, avatar_url, is_verified, is_locked,
		       failed_attempts, locked_until, last_login_at, created_at, updated_at
		FROM users
		WHERE lower(email) = lower($1) AND deleted_at IS NULL`,
		email,
	).Scan(
		&u.ID, &u.Email, &passwordHash, &u.FullName, &u.AvatarURL, &u.IsVerified, &u.IsLocked,
		&u.FailedAttempts, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", apperrors.ErrUserNotFound()
		}
		return nil, "", fmt.Errorf("querying user by email: %w", err)
	}

	return &u, passwordHash, nil
}

// GetByID returns a user profile by ID.
func (r *Repository) GetByID(ctx context.Context, tx dbTX, userID string) (*User, error) {
	if tx == nil {
		tx = r.db
	}

	var u User
	err := tx.QueryRow(ctx, `
		SELECT id, email, full_name, avatar_url, is_verified, is_locked,
		       failed_attempts, locked_until, last_login_at, created_at, updated_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(
		&u.ID, &u.Email, &u.FullName, &u.AvatarURL, &u.IsVerified, &u.IsLocked,
		&u.FailedAttempts, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrUserNotFound()
		}
		return nil, fmt.Errorf("querying user by id: %w", err)
	}

	return &u, nil
}

// GetPasswordHashByID returns the current password hash for a user.
func (r *Repository) GetPasswordHashByID(ctx context.Context, tx dbTX, userID string) (string, error) {
	if tx == nil {
		tx = r.db
	}

	var passwordHash string
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(password_hash, '')
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(&passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", apperrors.ErrUserNotFound()
		}
		return "", fmt.Errorf("querying password hash by id: %w", err)
	}

	return passwordHash, nil
}

// AssignRoleByName assigns a role to the user if it exists.
func (r *Repository) AssignRoleByName(ctx context.Context, tx dbTX, userID, roleName string) error {
	if tx == nil {
		tx = r.db
	}

	_, err := tx.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id FROM roles WHERE name = $2
		ON CONFLICT DO NOTHING`,
		userID, roleName,
	)
	if err != nil {
		return fmt.Errorf("assigning role %q to user %s: %w", roleName, userID, err)
	}
	return nil
}

// ListRoles returns the user's role names.
func (r *Repository) ListRoles(ctx context.Context, tx dbTX, userID string) ([]string, error) {
	if tx == nil {
		tx = r.db
	}

	rows, err := tx.Query(ctx, `
		SELECT r.name
		FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	defer rows.Close()

	roles := make([]string, 0, 4)
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// SetLastLoginAt records the latest successful login timestamp.
func (r *Repository) SetLastLoginAt(ctx context.Context, tx dbTX, userID string, at time.Time) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `UPDATE users SET last_login_at = $2, updated_at = NOW() WHERE id = $1`, userID, at)
	if err != nil {
		return fmt.Errorf("updating last login: %w", err)
	}
	return nil
}

// SetLockState updates lock fields after repeated failures.
func (r *Repository) SetLockState(ctx context.Context, tx dbTX, userID string, isLocked bool, lockedUntil *time.Time) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `
		UPDATE users
		SET is_locked = $2, locked_until = $3, updated_at = NOW()
		WHERE id = $1`,
		userID, isLocked, lockedUntil,
	)
	if err != nil {
		return fmt.Errorf("updating lock state: %w", err)
	}
	return nil
}

// IncrementFailedAttempts increments the failure counter and returns the new value.
func (r *Repository) IncrementFailedAttempts(ctx context.Context, tx dbTX, userID string) (int, error) {
	if tx == nil {
		tx = r.db
	}
	var attempts int
	err := tx.QueryRow(ctx, `
		UPDATE users
		SET failed_attempts = failed_attempts + 1, updated_at = NOW()
		WHERE id = $1
		RETURNING failed_attempts`,
		userID,
	).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("incrementing failed attempts: %w", err)
	}
	return attempts, nil
}

// ResetFailedAttempts clears the failure counter after successful login.
func (r *Repository) ResetFailedAttempts(ctx context.Context, tx dbTX, userID string) error {
	if tx == nil {
		tx = r.db
	}
	_, err := tx.Exec(ctx, `
		UPDATE users
		SET failed_attempts = 0, is_locked = FALSE, locked_until = NULL, updated_at = NOW()
		WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("resetting failed attempts: %w", err)
	}
	return nil
}

// UpdateProfileInput contains fields that can be updated by the user.
type UpdateProfileInput struct {
	FullName  *string `json:"full_name"`
	AvatarURL *string `json:"avatar_url"`
}

// UpdateProfile updates the profile information for a user.
func (r *Repository) UpdateProfile(ctx context.Context, tx dbTX, userID string, input UpdateProfileInput) (*User, error) {
	if tx == nil {
		tx = r.db
	}

	var current User
	err := tx.QueryRow(ctx, `
		SELECT id, email, full_name, avatar_url, is_verified, is_locked,
		       failed_attempts, locked_until, last_login_at, created_at, updated_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(
		&current.ID, &current.Email, &current.FullName, &current.AvatarURL, &current.IsVerified, &current.IsLocked,
		&current.FailedAttempts, &current.LockedUntil, &current.LastLoginAt, &current.CreatedAt, &current.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrUserNotFound()
		}
		return nil, fmt.Errorf("reading user profile for update: %w", err)
	}

	fullName := current.FullName
	if input.FullName != nil && *input.FullName != "" {
		fullName = *input.FullName
	}
	avatarURL := current.AvatarURL
	if input.AvatarURL != nil {
		avatarURL = input.AvatarURL
	}

	var u User
	err = tx.QueryRow(ctx, `
		UPDATE users
		SET full_name = $2, avatar_url = $3, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING id, email, full_name, avatar_url, is_verified, is_locked,
		          failed_attempts, locked_until, last_login_at, created_at, updated_at`,
		userID, fullName, avatarURL,
	).Scan(
		&u.ID, &u.Email, &u.FullName, &u.AvatarURL, &u.IsVerified, &u.IsLocked,
		&u.FailedAttempts, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("updating user profile: %w", err)
	}

	return &u, nil
}

// Profile returns the authenticated user's profile with roles.
func (s *Service) Profile(ctx context.Context, userID string) (*ProfileResponse, error) {
	u, err := s.repo.GetByID(ctx, nil, userID)
	if err != nil {
		return nil, err
	}
	roles, err := s.repo.ListRoles(ctx, nil, userID)
	if err != nil {
		return nil, err
	}
	return &ProfileResponse{User: *u, Roles: roles}, nil
}

// UpdateProfile updates the profile of the user.
func (s *Service) UpdateProfile(ctx context.Context, userID string, input UpdateProfileInput) (*ProfileResponse, error) {
	u, err := s.repo.UpdateProfile(ctx, nil, userID, input)
	if err != nil {
		return nil, err
	}
	roles, err := s.repo.ListRoles(ctx, nil, userID)
	if err != nil {
		return nil, err
	}
	return &ProfileResponse{User: *u, Roles: roles}, nil
}

// ProfileResponse joins a public profile with role names.
type ProfileResponse struct {
	User  User     `json:"user"`
	Roles []string `json:"roles"`
}

// Me returns the authenticated user's profile.
func (h *Handler) Me(c *gin.Context) {
	userID, ok := c.Get(string(contextkeys.UserID))
	if !ok {
		response.Error(c, apperrors.ErrForbidden())
		return
	}

	profile, err := h.svc.Profile(c.Request.Context(), userID.(string))
	if err != nil {
		response.Error(c, err)
		return
	}

	response.OK(c, profile)
}

// UpdateMe updates the authenticated user's profile.
func (h *Handler) UpdateMe(c *gin.Context) {
	userID, ok := c.Get(string(contextkeys.UserID))
	if !ok {
		response.Error(c, apperrors.ErrForbidden())
		return
	}

	var req UpdateProfileInput
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}

	profile, err := h.svc.UpdateProfile(c.Request.Context(), userID.(string), req)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.OK(c, profile)
}
