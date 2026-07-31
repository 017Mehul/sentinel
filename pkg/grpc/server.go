package grpc

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server wraps grpc.Server so the rest of the app can depend on a small surface area.
type Server struct {
	*grpc.Server
}

// NewServer constructs the gRPC server used by the auth service.
func NewServer() *Server {
	srv := grpc.NewServer()
	reflection.Register(srv)
	return &Server{Server: srv}
}
