package grpc

import (
	"context"
	"testing"

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
