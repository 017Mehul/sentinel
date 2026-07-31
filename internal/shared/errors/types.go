package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// AppError is the canonical error type for this service.
// Every error returned from service and repository layers should be (or wrap) an AppError.
type AppError struct {
	// Code is a machine-readable error code (e.g., AUTH_001).
	Code string
	// Message is a human-readable description safe to send to clients.
	Message string
	// HTTPStatus is the HTTP status code this error maps to.
	HTTPStatus int
	// Err is the underlying cause (not sent to clients).
	Err error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// ValidationError represents one or more input validation failures.
type ValidationError struct {
	Code   string
	Fields []FieldError
}

// FieldError describes a single field-level validation failure.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("[%s] validation failed: %d field(s) invalid", e.Code, len(e.Fields))
}

// ── Constructors ──────────────────────────────────────────────────────────────

func New(code, message string, httpStatus int) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: httpStatus}
}

func Wrap(code, message string, httpStatus int, cause error) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: httpStatus, Err: cause}
}

func NewValidation(fields []FieldError) *ValidationError {
	return &ValidationError{Code: CodeValidationFailed, Fields: fields}
}

// ── Sentinel constructors (common errors) ─────────────────────────────────────

func ErrInvalidCredentials() *AppError {
	return New(CodeInvalidCredentials, "Invalid email or password", http.StatusUnauthorized)
}

func ErrAccountLocked(until string) *AppError {
	return New(CodeAccountLocked, fmt.Sprintf("Account locked until %s", until), http.StatusLocked)
}

func ErrTokenInvalid() *AppError {
	return New(CodeTokenInvalid, "Token is invalid", http.StatusUnauthorized)
}

func ErrTokenExpired() *AppError {
	return New(CodeTokenExpired, "Token has expired", http.StatusUnauthorized)
}

func ErrTokenReused() *AppError {
	return New(CodeTokenReused, "Security alert: refresh token reuse detected. Please login again.", http.StatusUnauthorized)
}

func ErrConcurrentRefresh() *AppError {
	return New(CodeConcurrentRefresh, "Concurrent token refresh detected", http.StatusConflict)
}

func ErrEmailNotVerified() *AppError {
	return New(CodeEmailNotVerified, "Email address is not verified", http.StatusForbidden)
}

func ErrEmailAlreadyVerified() *AppError {
	return New(CodeEmailAlreadyVerified, "Email is already verified", http.StatusConflict)
}

func ErrVerificationExpired() *AppError {
	return New(CodeVerificationExpired, "Email verification token has expired", http.StatusBadRequest)
}

func ErrInvalidVerifyToken() *AppError {
	return New(CodeInvalidVerifyToken, "Email verification token is invalid", http.StatusBadRequest)
}

func ErrMFARequired() *AppError {
	return New(CodeMFARequired, "MFA verification required", http.StatusUnauthorized)
}

func ErrMFAInvalidOTP() *AppError {
	return New(CodeMFAInvalidOTP, "Invalid or expired OTP", http.StatusUnauthorized)
}

func ErrMFANotEnabled() *AppError {
	return New(CodeMFANotEnabled, "MFA is not enabled for this account", http.StatusBadRequest)
}

func ErrInvalidBackupCode() *AppError {
	return New(CodeInvalidBackupCode, "Invalid backup code", http.StatusUnauthorized)
}

func ErrUserNotFound() *AppError {
	return New(CodeUserNotFound, "User not found", http.StatusNotFound)
}

func ErrEmailTaken() *AppError {
	return New(CodeEmailTaken, "An account with this email already exists", http.StatusConflict)
}

func ErrForbidden() *AppError {
	return New(CodeForbidden, "You do not have permission to perform this action", http.StatusForbidden)
}

func ErrRoleNotFound() *AppError {
	return New(CodeRoleNotFound, "Role not found", http.StatusNotFound)
}

func ErrSessionNotFound() *AppError {
	return New(CodeSessionNotFound, "Session not found", http.StatusNotFound)
}

func ErrPasswordBreached() *AppError {
	return New(CodePasswordBreached, "This password was found in a known data breach. Please choose a different password.", http.StatusBadRequest)
}

func ErrPasswordSameAsOld() *AppError {
	return New(CodePasswordSameAsOld, "New password must differ from the current password", http.StatusBadRequest)
}

func ErrResetTokenInvalid() *AppError {
	return New(CodeResetTokenInvalid, "Password reset token is invalid", http.StatusBadRequest)
}

func ErrResetTokenExpired() *AppError {
	return New(CodeResetTokenExpired, "Password reset token has expired", http.StatusBadRequest)
}

func ErrRateLimited() *AppError {
	return New(CodeRateLimited, "Too many requests. Please try again later.", http.StatusTooManyRequests)
}

func ErrDuplicateRequest() *AppError {
	return New(CodeDuplicateRequest, "Duplicate request detected", http.StatusConflict)
}

func ErrInternal(cause error) *AppError {
	return Wrap(CodeInternalError, "An internal error occurred", http.StatusInternalServerError, cause)
}

func ErrNotImplemented() *AppError {
	return New(CodeNotImplemented, "Not implemented", http.StatusNotImplemented)
}

func ErrServiceUnavailable(message string) *AppError {
	if message == "" {
		message = "Service temporarily unavailable"
	}
	return New(CodeServiceUnavailable, message, http.StatusServiceUnavailable)
}

// ── Type assertions ───────────────────────────────────────────────────────────

// IsAppError returns true if err is or wraps an *AppError.
func IsAppError(err error) bool {
	var ae *AppError
	return errors.As(err, &ae)
}

// AsAppError extracts the *AppError from err, returning nil if not found.
func AsAppError(err error) *AppError {
	var ae *AppError
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}

// AsValidationError extracts a *ValidationError from err.
func AsValidationError(err error) *ValidationError {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve
	}
	return nil
}
