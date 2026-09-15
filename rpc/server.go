package rpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Server server instance
type Server struct {
	logger  *slog.Logger
	config  *Config
	server  *grpc.Server
	opts    []grpc.ServerOption
	gateway *http.Server
}

// NewServer returns Server instance
func NewServer(c *Config) *Server {
	s := new(Server)
	s.config = c
	s.logger = c.logger

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

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// 配置了客户端 ca 证书，说明服务端需要验证客户端的有效性
		clientCAFile := c.TLS.GRPCCAFile
		if clientCAFile != "" {
			caBody, err := ioutil.ReadFile(clientCAFile)
			if err != nil {
				panic(err)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caBody) {
				panic(fmt.Errorf("grpc ca file invalid: %v", clientCAFile))
			}

			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = caPool
		}

		s.opts = append(s.opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		s.opts = append(s.opts, grpc.Creds(insecure.NewCredentials()))
	}

	for _, v := range c.opts {
		s.opts = append(s.opts, v)
	}

	return s
}

// Server return the grpc server for registering service
func (s *Server) Server() *grpc.Server {
	if s.server == nil {
		s.server = grpc.NewServer(s.opts...)
		// TODO; 是否加入反射，比如可用于 grpcurl -plaintext 127.0.0.1:10081 list
		// reflection.Register(s.server)
	}

	return s.server
}

// UseServerOption 用于设置选项并初始化grpc server
func (s *Server) UseServerOption(opts ...grpc.ServerOption) *Server {
	s.opts = append(s.opts, opts...)

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

// StartBackground 在后台启动 gRPC 和 HTTP 服务。
// ctx 仅控制启动过程；启动完成后仍应调用 Shutdown 关闭服务。
func (s *Server) StartBackground(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// TODO; check GRPCAddress

	// start grpc
	lis, err := net.Listen("tcp", s.config.GRPCAddress)
	if err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		_ = lis.Close()
		return err
	}

	var grpcServer *grpc.Server
	if s.config.DisableGRPCServer {
		s.logger.WarnContext(ctx, "Disable gRPC server")
		_ = lis.Close()
	} else {
		grpcServer = s.Server()
		go func() {
			if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				panic(err)
			}
		}()
	}

	if s.gateway == nil {
		return nil
	}

	// TODO; 如果有启动 grpc，则通过健康检测，启动之后在开启 http gateway
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		if grpcServer != nil {
			grpcServer.Stop()
		}
		return ctx.Err()
	case <-timer.C:
	}
	if err := ctx.Err(); err != nil {
		if grpcServer != nil {
			grpcServer.Stop()
		}
		return err
	}

	go func() {
		if s.config.DisableHTTPServer {
			s.logger.WarnContext(ctx, "Disable gateway server")
			return
		}

		certFile := s.config.TLS.HTTPCertFile
		keyFile := s.config.TLS.HTTPKeyFile

		// 这里可以通过替换为ListenAndServeTLS，开启HTTP2

		var serveErr error
		if s.gateway.TLSConfig != nil {
			serveErr = s.gateway.ListenAndServeTLS("", "")
		} else if certFile != "" && keyFile != "" {
			serveErr = s.gateway.ListenAndServeTLS(certFile, keyFile)
		} else {
			serveErr = s.gateway.ListenAndServe()
		}

		if !errors.Is(serveErr, http.ErrServerClosed) {
			panic(serveErr)
		}
	}()

	return nil
}

// Shutdown graceful stop server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.gateway != nil {
		s.logger.DebugContext(ctx, "Shutdown gateway server start")

		if err := s.gateway.Shutdown(ctx); err != nil {
			return err
		}

		s.logger.DebugContext(ctx, "Shutdown gateway server end")
	}

	s.logger.DebugContext(ctx, "Shutdown gRPC server start")

	s.server.GracefulStop()

	s.logger.DebugContext(ctx, "Shutdown gRPC server end")

	return nil
}
