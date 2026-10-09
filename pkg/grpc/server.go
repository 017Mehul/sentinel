package grpc

import (
	"context"

	"github.com/MehulChamoli/auth-service/internal/auth"
	authv1 "github.com/MehulChamoli/auth-service/proto/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type Server struct{ *grpc.Server }

type authServer struct {
	authv1.UnimplementedAuthServiceServer
	auth *auth.Service
}

func (s *authServer) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	if req == nil || req.GetToken() == "" { return nil, status.Error(codes.InvalidArgument, "token is required") }
	claims, err := s.auth.ValidateAccessToken(ctx, req.GetToken())
	if err != nil { return nil, status.Error(codes.Unauthenticated, "invalid access token") }
	return &authv1.ValidateTokenResponse{Valid:true, UserId:claims.Subject, SessionId:claims.SessionID, Roles:claims.Roles}, nil
}

func (s *authServer) GetUser(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if req == nil || req.GetUserId() == "" { return nil, status.Error(codes.InvalidArgument, "user_id is required") }
	u, roles, err := s.auth.GetUserForToken(ctx, req.GetUserId())
	if err != nil { return nil, status.Error(codes.NotFound, "user not found") }
	return &authv1.GetUserResponse{Id:u.ID, Email:u.Email, FullName:u.FullName, IsVerified:u.IsVerified, Roles:roles}, nil
}

func (s *authServer) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	if req == nil || req.GetUserId() == "" || req.GetPermission() == "" { return nil, status.Error(codes.InvalidArgument, "user_id and permission are required") }
	allowed, err := s.auth.CheckPermission(ctx, req.GetUserId(), req.GetPermission())
	if err != nil { return nil, status.Error(codes.Internal, "permission check failed") }
	return &authv1.CheckPermissionResponse{Allowed:allowed}, nil
}

func NewServer(authSvc *auth.Service) *Server {
	srv := grpc.NewServer()
	authv1.RegisterAuthServiceServer(srv, &authServer{auth:authSvc})
	reflection.Register(srv)
	return &Server{Server:srv}
}
