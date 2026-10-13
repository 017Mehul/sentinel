package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestValidateRefreshCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		cookie     string
		header     string
		wantValid  bool
	}{
		{name: "matching token", cookie: "token-value", header: "token-value", wantValid: true},
		{name: "missing cookie", header: "token-value", wantValid: false},
		{name: "missing header", cookie: "token-value", wantValid: false},
		{name: "mismatched token", cookie: "cookie-value", header: "header-value", wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
			if tt.cookie != "" {
				ctx.Request.AddCookie(&http.Cookie{Name: "sentinel_csrf", Value: tt.cookie})
			}
			if tt.header != "" {
				ctx.Request.Header.Set("X-CSRF-Token", tt.header)
			}

			handler := &Handler{svc: &Service{isProd: true}}
			if got := handler.validateRefreshCSRF(ctx); got != tt.wantValid {
				t.Fatalf("validateRefreshCSRF() = %v, want %v", got, tt.wantValid)
			}
		})
	}
}
