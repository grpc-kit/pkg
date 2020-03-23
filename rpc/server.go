package rpc

import (
	"context"
	"net"
	"net/http"
	"time"

	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// Server server instance
type Server struct {
	logger  *logrus.Entry
	config  *Config
	server  *grpc.Server
	gateway *http.Server
}

// NewServer returns Server instance
func NewServer(c *Config, opts ...grpc.ServerOption) *Server {
	s := new(Server)

	keepParam := grpc.KeepaliveParams(keepalive.ServerParameters{
		Timeout: c.KeepaliveTimeout,
	})

	opts = append(opts, keepParam)

	s.config = c
	s.logger = c.logger
	s.server = grpc.NewServer(opts...)

	return s
}

// Server return the grpc server for registering service
func (s *Server) Server() *grpc.Server {
	return s.server
}

// RegisterGateway return the http server for registering service
func (s *Server) RegisterGateway(mux *http.ServeMux) error {
	// TODO; check HTTPAddress

	srv := &http.Server{
		Addr:    s.config.HTTPAddress,
		Handler: mux,
	}

	s.gateway = srv

	return nil
}

// StartBackground xx
func (s *Server) StartBackground() error {
	// TODO; check GRPCAddress

	// start grpc
	lis, err := net.Listen("tcp", s.config.GRPCAddress)
	if err != nil {
		return err
	}

	go func() {
		if err := s.server.Serve(lis); err != nil {
			panic(err)
		}
	}()

	if s.gateway == nil {
		return nil
	}

	time.Sleep(2 * time.Second)

	// register prometheus
	grpcprometheus.Register(s.server)
	grpcprometheus.EnableHandlingTimeHistogram()

	go func() {
		if err := s.gateway.ListenAndServe(); err != nil {
			// ignore shutdown error
			if err != http.ErrServerClosed {
				panic(err)
			}
		}
	}()

	return nil
}

// Shutdown graceful stop server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.gateway != nil {
		s.logger.Debugf("Shutdown gateway server start")

		if err := s.gateway.Shutdown(ctx); err != nil {
			return err
		}

		s.logger.Debugf("Shutdown gateway server end")
	}

	s.logger.Debugf("Shutdown gRPC server start")

	s.server.GracefulStop()

	s.logger.Debugf("Shutdown gRPC server end")

	return nil
}
