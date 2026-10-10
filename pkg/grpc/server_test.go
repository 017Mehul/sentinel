package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/MehulChamoli/auth-service/config"
	authv1 "github.com/MehulChamoli/auth-service/proto/auth/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestAuthServiceRejectsInvalidRequestsAndMissingIdentity(t *testing.T) {
	server, err := NewServer(nil, config.TLSConfig{})
	require.NoError(t, err)

	listener := bufconn.Listen(1024 * 1024)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := authv1.NewAuthServiceClient(conn)
	_, err = client.ValidateToken(ctx, &authv1.ValidateTokenRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = client.GetUser(ctx, &authv1.GetUserRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = client.GetUser(ctx, &authv1.GetUserRequest{UserId: "user-123"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = client.CheckPermission(ctx, &authv1.CheckPermissionRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = client.CheckPermission(ctx, &authv1.CheckPermissionRequest{UserId: "user-123", Permission: "users.read"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}
