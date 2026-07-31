package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/MehulChamoli/auth-service/internal/shared/contextkeys"
	"github.com/MehulChamoli/auth-service/internal/shared/dbtx"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
)

// dbTX aliases the shared transaction interface so existing code needs no changes.
type dbTX = dbtx.TX

// Role describes a system role.
type Role struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Permission describes an RBAC permission.
type Permission struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// AuditLog represents an immutable audit event.
type AuditLog struct {
	ID         string         `json:"id"`
	UserID     *string        `json:"user_id,omitempty"`
	ActorID    *string        `json:"actor_id,omitempty"`
	Action     string         `json:"action"`
	Resource   *string        `json:"resource,omitempty"`
	ResourceID *string        `json:"resource_id,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	IPAddress  *string        `json:"ip_address,omitempty"`
	UserAgent  string         `json:"user_agent"`
	CreatedAt  time.Time      `json:"created_at"`
}

// UserRole is used by admin assignment endpoints.
type UserRole struct {
	UserID   string `json:"user_id"`
	RoleName string `json:"role_name"`
}

type Repository struct {
	db *pgxpool.Pool
}

type Service struct {
	repo *Repository
}

type Handler struct {
	svc *Service
}

func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func NewService(repo *Repository) *Service { return &Service{repo: repo} }

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func (r *Repository) beginTx(ctx context.Context) (pgx.Tx, error) {
	return r.db.BeginTx(ctx, pgx.TxOptions{})
}

func (r *Repository) ListRoles(ctx context.Context, tx dbTX) ([]Role, error) {
	if tx == nil {
		tx = r.db
	}
	rows, err := tx.Query(ctx, `SELECT id, name, COALESCE(description, ''), created_at, updated_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *Repository) ListPermissions(ctx context.Context, tx dbTX) ([]Permission, error) {
	if tx == nil {
		tx = r.db
	}
	rows, err := tx.Query(ctx, `SELECT id, name, resource, action, COALESCE(description, ''), created_at FROM permissions ORDER BY resource, action`)
	if err != nil {
		return nil, fmt.Errorf("listing permissions: %w", err)
	}
	defer rows.Close()

	var permissions []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Resource, &p.Action, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning permission: %w", err)
		}
		permissions = append(permissions, p)
	}
	return permissions, rows.Err()
}

func (r *Repository) ListAuditLogs(ctx context.Context, tx dbTX, limit int) ([]AuditLog, error) {
	if tx == nil {
		tx = r.db
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := tx.Query(ctx, `
		SELECT id, user_id, actor_id, action, resource, resource_id, metadata, ip_address::text, COALESCE(user_agent, ''), created_at
		FROM audit_logs
		ORDER BY created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("listing audit logs: %w", err)
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var log AuditLog
		var metadata []byte
		if err := rows.Scan(&log.ID, &log.UserID, &log.ActorID, &log.Action, &log.Resource, &log.ResourceID, &metadata, &log.IPAddress, &log.UserAgent, &log.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning audit log: %w", err)
		}
		if len(metadata) > 0 {
			log.Metadata = json.RawMessage(metadata)
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

func (r *Repository) AssignRole(ctx context.Context, tx dbTX, userID, roleName, actorID string) error {
	if tx == nil {
		tx = r.db
	}
	ct, err := tx.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, assigned_by)
		SELECT $1, id, $3 FROM roles WHERE name = $2
		ON CONFLICT DO NOTHING`,
		userID, roleName, actorID,
	)
	if err != nil {
		return fmt.Errorf("assigning role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return apperrors.ErrRoleNotFound()
	}
	return nil
}

func (r *Repository) RemoveRole(ctx context.Context, tx dbTX, userID, roleName string) error {
	if tx == nil {
		tx = r.db
	}
	ct, err := tx.Exec(ctx, `
		DELETE FROM user_roles
		WHERE user_id = $1
		AND role_id = (SELECT id FROM roles WHERE name = $2)`,
		userID, roleName,
	)
	if err != nil {
		return fmt.Errorf("removing role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return apperrors.ErrRoleNotFound()
	}
	return nil
}

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

func (s *Service) Roles(ctx context.Context) ([]Role, error) {
	return s.repo.ListRoles(ctx, nil)
}

func (s *Service) Permissions(ctx context.Context) ([]Permission, error) {
	return s.repo.ListPermissions(ctx, nil)
}

func (s *Service) AuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	return s.repo.ListAuditLogs(ctx, nil, limit)
}

func (s *Service) AssignRole(ctx context.Context, userID, roleName, actorID, ipAddress, userAgent string) error {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("beginning assign role transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := s.repo.AssignRole(ctx, tx, userID, roleName, actorID); err != nil {
		return err
	}
	if err := s.repo.WriteAuditLog(ctx, tx, userID, actorID, "rbac.role_assigned", "user", userID, map[string]any{"role": roleName}, ipAddress, userAgent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) RemoveRole(ctx context.Context, userID, roleName, actorID, ipAddress, userAgent string) error {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("beginning remove role transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := s.repo.RemoveRole(ctx, tx, userID, roleName); err != nil {
		return err
	}
	if err := s.repo.WriteAuditLog(ctx, tx, userID, actorID, "rbac.role_removed", "user", userID, map[string]any{"role": roleName}, ipAddress, userAgent); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func requireAdmin(c *gin.Context) bool {
	roles, _ := c.Get(string(contextkeys.UserRoles))
	roleList, _ := roles.([]string)
	for _, role := range roleList {
		if role == "admin" {
			return true
		}
	}
	response.Error(c, apperrors.ErrForbidden())
	return false
}

func (h *Handler) ListRoles(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	roles, err := h.svc.Roles(c.Request.Context())
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"roles": roles})
}

func (h *Handler) ListPermissions(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	permissions, err := h.svc.Permissions(c.Request.Context())
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"permissions": permissions})
}

func (h *Handler) ListAuditLogs(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	logs, err := h.svc.AuditLogs(c.Request.Context(), 100)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"audit_logs": logs})
}

type AssignRoleRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	RoleName string `json:"role_name" binding:"required"`
}

func (h *Handler) AssignRole(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	var req AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}
	actorID, _ := c.Get(string(contextkeys.UserID))
	if err := h.svc.AssignRole(c.Request.Context(), req.UserID, req.RoleName, fmt.Sprint(actorID), c.ClientIP(), c.GetHeader("User-Agent")); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"status": "assigned"})
}

type RemoveRoleRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	RoleName string `json:"role_name" binding:"required"`
}

func (h *Handler) RemoveRole(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	var req RemoveRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperrors.NewValidation([]apperrors.FieldError{{Field: "body", Message: err.Error()}}))
		return
	}
	actorID, _ := c.Get(string(contextkeys.UserID))
	if err := h.svc.RemoveRole(c.Request.Context(), req.UserID, req.RoleName, fmt.Sprint(actorID), c.ClientIP(), c.GetHeader("User-Agent")); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"status": "removed"})
}
