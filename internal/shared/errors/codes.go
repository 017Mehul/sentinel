package errors

// Error codes follow the pattern DOMAIN_NNN.
// Domains: AUTH, USER, RBAC, MFA, OAUTH, SESSION, WEBHOOK, SYS
const (
	// ── Authentication ───────────────────────────────────────────────────────
	CodeInvalidCredentials   = "AUTH_001"
	CodeAccountLocked        = "AUTH_002"
	CodeTokenInvalid         = "AUTH_003"
	CodeTokenReused          = "AUTH_004" // refresh token rotation attack
	CodeTokenExpired         = "AUTH_005"
	CodeConcurrentRefresh    = "AUTH_006"
	CodeEmailNotVerified     = "AUTH_007"
	CodeEmailAlreadyVerified = "AUTH_008"
	CodeVerificationExpired  = "AUTH_009"
	CodeInvalidVerifyToken   = "AUTH_010"
	CodeMFARequired          = "AUTH_011"
	CodeMFAInvalidOTP        = "AUTH_012"
	CodeMFAAlreadyEnabled    = "AUTH_013"
	CodeMFANotEnabled        = "AUTH_014"
	CodeInvalidBackupCode    = "AUTH_015"
	CodePasswordBreached     = "AUTH_016"
	CodeResetTokenInvalid    = "AUTH_017"
	CodeResetTokenExpired    = "AUTH_018"
	CodePasswordSameAsOld    = "AUTH_019"

	// ── User ─────────────────────────────────────────────────────────────────
	CodeUserNotFound      = "USER_001"
	CodeEmailTaken        = "USER_002"
	CodeInvalidPassword   = "USER_003"

	// ── RBAC ─────────────────────────────────────────────────────────────────
	CodeForbidden          = "RBAC_001"
	CodeRoleNotFound       = "RBAC_002"
	CodeRoleAlreadyExists  = "RBAC_003"
	CodePermissionNotFound = "RBAC_004"
	CodeRoleAlreadyAssigned = "RBAC_005"

	// ── MFA ──────────────────────────────────────────────────────────────────
	CodeMFASetupConflict = "MFA_001"

	// ── OAuth ─────────────────────────────────────────────────────────────────
	CodeOAuthProviderError   = "OAUTH_001"
	CodeOAuthStateInvalid    = "OAUTH_002"
	CodeOAuthAccountLinked   = "OAUTH_003"

	// ── Session ───────────────────────────────────────────────────────────────
	CodeSessionNotFound   = "SESSION_001"
	CodeSessionRevoked    = "SESSION_002"

	// ── Request ───────────────────────────────────────────────────────────────
	CodeValidationFailed  = "REQ_001"
	CodeRateLimited       = "REQ_002"
	CodeDuplicateRequest  = "REQ_003" // idempotency / replay
	CodeBadRequest        = "REQ_004"

	// ── System ────────────────────────────────────────────────────────────────
	CodeInternalError     = "SYS_001"
	CodeServiceUnavailable = "SYS_002"
	CodeNotImplemented    = "SYS_003"
)
