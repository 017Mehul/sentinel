package response

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/contextkeys"
)

// Envelope is the standard JSON response wrapper for all API responses.
type Envelope struct {
	Success bool        `json:"success"`
	Data    any         `json:"data,omitempty"`
	Error   *ErrorBody  `json:"error,omitempty"`
	Meta    Meta        `json:"meta"`
}

// ErrorBody carries machine-readable and human-readable error information.
type ErrorBody struct {
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Details []FieldError `json:"details,omitempty"`
}

// FieldError represents a single field-level validation failure.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Meta carries request-level metadata attached to every response.
type Meta struct {
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

const apiVersion = "1.0"

// OK sends a 200 response with the given data payload.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Envelope{
		Success: true,
		Data:    data,
		Meta:    buildMeta(c),
	})
}

// Created sends a 201 response with the given data payload.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, Envelope{
		Success: true,
		Data:    data,
		Meta:    buildMeta(c),
	})
}

// NoContent sends a 204 response with no body.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Error sends an error response, translating AppError / ValidationError to HTTP.
func Error(c *gin.Context, err error) {
	if ve := apperrors.AsValidationError(err); ve != nil {
		details := make([]FieldError, len(ve.Fields))
		for i, f := range ve.Fields {
			details[i] = FieldError{Field: f.Field, Message: f.Message}
		}
		c.JSON(http.StatusUnprocessableEntity, Envelope{
			Success: false,
			Error: &ErrorBody{
				Code:    ve.Code,
				Message: "Validation failed",
				Details: details,
			},
			Meta: buildMeta(c),
		})
		return
	}

	if ae := apperrors.AsAppError(err); ae != nil {
		c.JSON(ae.HTTPStatus, Envelope{
			Success: false,
			Error:   &ErrorBody{Code: ae.Code, Message: ae.Message},
			Meta:    buildMeta(c),
		})
		return
	}

	// Unknown error — never leak internal details to the client.
	c.JSON(http.StatusInternalServerError, Envelope{
		Success: false,
		Error: &ErrorBody{
			Code:    apperrors.CodeInternalError,
			Message: "An internal error occurred",
		},
		Meta: buildMeta(c),
	})
}

// Forbidden sends a 403 response.
func Forbidden(c *gin.Context) {
	c.JSON(http.StatusForbidden, Envelope{
		Success: false,
		Error: &ErrorBody{
			Code:    apperrors.CodeForbidden,
			Message: "You do not have permission to perform this action",
		},
		Meta: buildMeta(c),
	})
}

// Unauthorized sends a 401 response.
func Unauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, Envelope{
		Success: false,
		Error: &ErrorBody{
			Code:    apperrors.CodeTokenInvalid,
			Message: "Authentication required",
		},
		Meta: buildMeta(c),
	})
}

func buildMeta(c *gin.Context) Meta {
	requestID, _ := c.Get(string(contextkeys.RequestID))
	rid, _ := requestID.(string)
	return Meta{
		RequestID: rid,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   apiVersion,
	}
}
