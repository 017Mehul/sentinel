package grpc

import (
	"context"
	"testing"

	"github.com/MehulChamoli/auth-service/config"
	authv1 "github.com/MehulChamoli/auth-service/proto/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGetUserRequiresAuthentication(t *testing.T) {
	s := &authServer{}
	_, err := s.GetUser(context.Background(), &authv1.GetUserRequest{UserId: "target-user"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestCheckPermissionRequiresAuthentication(t *testing.T) {
	s := &authServer{}
	_, err := s.CheckPermission(context.Background(), &authv1.CheckPermissionRequest{
		UserId: "target-user", Permission: "users:read",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestGetUserRejectsMissingUserID(t *testing.T) {
	s := &authServer{}
	_, err := s.GetUser(context.Background(), &authv1.GetUserRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestCheckPermissionRejectsMissingFields(t *testing.T) {
	s := &authServer{}
	_, err := s.CheckPermission(context.Background(), &authv1.CheckPermissionRequest{UserId: "user"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestMalformedAuthorizationHeaderRejected(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic abc"))
	s := &authServer{}
	_, err := s.authenticate(ctx)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestNewServerWithoutTLSForDevelopment(t *testing.T) {
	srv, err := NewServer(nil, config.TLSConfig{})
	if err != nil {
		t.Fatalf("expected development server to initialize: %v", err)
	}
	if srv == nil || srv.Server == nil {
		t.Fatal("expected a configured gRPC server")
	}
	srv.Stop()
}

func TestNewServerFailsClosedOnInvalidTLSFiles(t *testing.T) {
	_, err := NewServer(nil, config.TLSConfig{
		Enabled: true,
		CertFile: "missing-test-cert.pem",
		KeyFile: "missing-test-key.pem",
	})
	if err == nil {
		t.Fatal("expected TLS certificate loading to fail")
	}
}
