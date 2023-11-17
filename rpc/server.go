package rpc

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Server server instance
type Server struct {
	logger  *logrus.Entry
	config  *Config
	server  *grpc.Server
	opts    []grpc.ServerOption
	gateway *http.Server
}

// NewServer returns Server instance
func NewServer(c *Config) *Server {
	s := new(Server)

	keepParam := grpc.KeepaliveParams(keepalive.ServerParameters{
		Timeout: c.KeepaliveTimeout,
	})

	s.opts = append(s.opts, keepParam)

	// grpc 服务添加证书
	if c.TLS.GRPCCertFile != "" && c.TLS.GRPCKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.TLS.GRPCCertFile, c.TLS.GRPCKeyFile)
		if err != nil {
			panic(err)
		}
		s.opts = append(s.opts, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	} else {
		s.opts = append(s.opts, grpc.Creds(insecure.NewCredentials()))
	}

	s.config = c
	s.logger = c.logger

	return s
}

// Server return the grpc server for registering service
func (s *Server) Server() *grpc.Server {
	if s.server == nil {
		s.server = grpc.NewServer(s.opts...)
	}

	return s.server
}

// UseServerOption 用于设置选项并初始化grpc server
func (s *Server) UseServerOption(opts ...grpc.ServerOption) *Server {
	s.opts = append(s.opts, opts...)

	if s.server == nil {
		s.server = grpc.NewServer(s.opts...)
	}

	return s
}

// RegisterGateway return the http server for registering service
func (s *Server) RegisterGateway(mux *http.ServeMux) error {
	// TODO; check HTTPAddress

	srv := &http.Server{
		Addr:    s.config.HTTPAddress,
		Handler: mux,
	}

	// 支持 acme 自动化申请证书
	var auto *autocert.Manager
	if len(s.config.TLS.ACMEDomains) > 0 {
		cacheDir := "/tmp/grpc-kit"
		if s.config.TLS.ACMECacheDir != "" {
			cacheDir = s.config.TLS.ACMECacheDir
		}

		auto = &autocert.Manager{
			Cache:      autocert.DirCache(cacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.config.TLS.ACMEDomains...),
		}
		if s.config.TLS.ACMEEmail != "" {
			auto.Email = s.config.TLS.ACMEEmail
		}

		srv.TLSConfig = auto.TLSConfig()
	}

	s.gateway = srv

	return nil
}

// StartBackground xx
func (s *Server) StartBackground() error {
	// TODO; check GRPCAddress

	if s.server == nil {
		s.server = grpc.NewServer(s.opts...)
	}

	// start grpc
	lis, err := net.Listen("tcp", s.config.GRPCAddress)
	if err != nil {
		return err
	}

	go func() {
		if s.config.DisableGRPCServer {
			s.logger.Warnf("Disable gRPC server")
			return
		}

		if err := s.server.Serve(lis); err != nil {
			panic(err)
		}
	}()

	if s.gateway == nil {
		return nil
	}

	// TODO; 如果有启动 grpc，则通过健康检测，启动之后在开启 http gateway
	time.Sleep(2 * time.Second)

	go func() {
		if s.config.DisableHTTPServer {
			s.logger.Warnf("Disable gateway server")
			return
		}

		certFile := s.config.TLS.HTTPCertFile
		keyFile := s.config.TLS.HTTPKeyFile

		// 这里可以通过替换为ListenAndServeTLS，开启HTTP2

		if s.gateway.TLSConfig != nil {
			err = s.gateway.ListenAndServeTLS("", "")
		} else if certFile != "" && keyFile != "" {
			err = s.gateway.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = s.gateway.ListenAndServe()
		}

		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
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
