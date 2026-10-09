package errors

// Error codes follow the pattern DOMAIN_NNN.
// Domains: AUTH, USER, RBAC, MFA, OAUTH, SESSION, WEBHOOK, SYS
const (
	// ── Authentication ───────────────────────────────────────────────────────
	CodeInvalidCredentials   = "AUTH_001" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeAccountLocked        = "AUTH_002" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeTokenInvalid         = "AUTH_003" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeTokenReused          = "AUTH_004" // refresh token rotation attack // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeTokenExpired         = "AUTH_005" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeConcurrentRefresh    = "AUTH_006" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeEmailNotVerified     = "AUTH_007" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeEmailAlreadyVerified = "AUTH_008" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeVerificationExpired  = "AUTH_009" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeInvalidVerifyToken   = "AUTH_010" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeMFARequired          = "AUTH_011" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeMFAInvalidOTP        = "AUTH_012" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeMFAAlreadyEnabled    = "AUTH_013" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeMFANotEnabled        = "AUTH_014" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeInvalidBackupCode    = "AUTH_015" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodePasswordBreached     = "AUTH_016" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeResetTokenInvalid    = "AUTH_017" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeResetTokenExpired    = "AUTH_018" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodePasswordSameAsOld    = "AUTH_019" // #nosec G101 -- these are symbolic application error codes, not credentials

	// ── User ─────────────────────────────────────────────────────────────────
	CodeUserNotFound      = "USER_001" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeEmailTaken        = "USER_002" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeInvalidPassword   = "USER_003" // #nosec G101 -- these are symbolic application error codes, not credentials

	// ── RBAC ─────────────────────────────────────────────────────────────────
	CodeForbidden          = "RBAC_001" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeRoleNotFound       = "RBAC_002" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeRoleAlreadyExists  = "RBAC_003" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodePermissionNotFound = "RBAC_004" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeRoleAlreadyAssigned = "RBAC_005" // #nosec G101 -- these are symbolic application error codes, not credentials

	// ── MFA ──────────────────────────────────────────────────────────────────
	CodeMFASetupConflict = "MFA_001" // #nosec G101 -- these are symbolic application error codes, not credentials

	// ── OAuth ─────────────────────────────────────────────────────────────────
	CodeOAuthProviderError   = "OAUTH_001" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeOAuthStateInvalid    = "OAUTH_002" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeOAuthAccountLinked   = "OAUTH_003" // #nosec G101 -- these are symbolic application error codes, not credentials

	// ── Session ───────────────────────────────────────────────────────────────
	CodeSessionNotFound   = "SESSION_001" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeSessionRevoked    = "SESSION_002" // #nosec G101 -- these are symbolic application error codes, not credentials

	// ── Request ───────────────────────────────────────────────────────────────
	CodeValidationFailed  = "REQ_001" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeRateLimited       = "REQ_002" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeDuplicateRequest  = "REQ_003" // idempotency / replay // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeBadRequest        = "REQ_004" // #nosec G101 -- these are symbolic application error codes, not credentials

	// ── System ────────────────────────────────────────────────────────────────
	CodeInternalError     = "SYS_001" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeServiceUnavailable = "SYS_002" // #nosec G101 -- these are symbolic application error codes, not credentials
	CodeNotImplemented    = "SYS_003" // #nosec G101 -- these are symbolic application error codes, not credentials
)
