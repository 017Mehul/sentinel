package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/auth"
	authv1 "github.com/MehulChamoli/auth-service/proto/auth/v1"
		"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"github.com/MehulChamoli/auth-service/pkg/token"
)

type Server struct{ *grpc.Server }

type authServer struct {
	authv1.UnimplementedAuthServiceServer
	auth *auth.Service
}

func (s *authServer) authenticate(ctx context.Context) (*token.Claims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "bearer token required")
	}
	for _, value := range md.Get("authorization") {
		const prefix = "Bearer "
		if len(value) <= len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
			continue
		}
		claims, err := s.auth.ValidateAccessToken(ctx, strings.TrimSpace(value[len(prefix):]))
		if err == nil {
			return claims, nil
		}
	}
	return nil, status.Error(codes.Unauthenticated, "valid bearer token required")
}

func isAdmin(claims *token.Claims) bool {
	for _, role := range claims.Roles {
		if strings.EqualFold(role, "admin") {
			return true
		}
	}
	return false
}

func (s *authServer) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	if req == nil || req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	claims, err := s.auth.ValidateAccessToken(ctx, req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}
	return &authv1.ValidateTokenResponse{Valid: true, UserId: claims.Subject, SessionId: claims.SessionID, Roles: claims.Roles}, nil
}

func (s *authServer) GetUser(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if req == nil || req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	claims, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if claims.Subject != req.GetUserId() && !isAdmin(claims) {
		return nil, status.Error(codes.PermissionDenied, "cannot read another user's profile")
	}
	u, roles, err := s.auth.GetUserForToken(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	return &authv1.GetUserResponse{Id: u.ID, Email: u.Email, FullName: u.FullName, IsVerified: u.IsVerified, Roles: roles}, nil
}

func (s *authServer) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	if req == nil || req.GetUserId() == "" || req.GetPermission() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and permission are required")
	}
	claims, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if claims.Subject != req.GetUserId() && !isAdmin(claims) {
		return nil, status.Error(codes.PermissionDenied, "cannot check another user's permissions")
	}
	allowed, err := s.auth.CheckPermission(ctx, req.GetUserId(), req.GetPermission())
	if err != nil {
		return nil, status.Error(codes.Internal, "permission check failed")
	}
	return &authv1.CheckPermissionResponse{Allowed: allowed}, nil
}

func NewServer(authSvc *auth.Service, tlsCfg config.TLSConfig) (*Server, error) {
	opts := make([]grpc.ServerOption, 0, 1)
	if tlsCfg.Enabled {
		cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading gRPC TLS certificate: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})))
	}
	srv := grpc.NewServer(opts...)
	authv1.RegisterAuthServiceServer(srv, &authServer{auth: authSvc})
	reflection.Register(srv)
	return &Server{Server: srv}, nil
}
