package admin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/grpc-kit/pkg/lion"
	pklogging "github.com/grpc-kit/pkg/logging"
	"github.com/lib/pq"
	"golang.org/x/oauth2"
)

// logAuthenticationFailure records diagnostics without formatting the error:
// provider responses, URLs and database errors can contain credentials or PII.
func (a *KnownAdminAPI) logAuthenticationFailure(ctx context.Context, provider, stage string, err error) {
	if err == nil {
		return
	}
	reason := authenticationFailureReason(err)
	level := slog.LevelError
	if reason == "username_unavailable" || reason == "login_rejected" || reason == "not_found" || reason == "canceled" {
		level = slog.LevelWarn
	}
	cause := err
	for wrapped := errors.Unwrap(cause); wrapped != nil; wrapped = errors.Unwrap(cause) {
		cause = wrapped
	}
	pklogging.OrFallback(a.logger).LogAttrs(ctx, level, "authentication failed",
		slog.String("event", "authentication_failed"),
		slog.String("provider", provider),
		slog.String("stage", stage),
		slog.String("reason", reason),
		slog.String("error_type", fmt.Sprintf("%T", cause)),
	)
}

func authenticationFailureReason(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, errExternalUsernameConflict):
		return "username_unavailable"
	case errors.Is(err, errExternalLoginRejected):
		return "login_rejected"
	case errors.Is(err, errInvalidIdentityPolicy):
		return "invalid_identity_policy"
	case lion.IsNotFound(err):
		return "not_found"
	case retryableDatabaseError(err):
		return "database_retryable"
	}
	var postgresErr *pq.Error
	var mysqlErr *mysqlDriver.MySQLError
	if errors.As(err, &postgresErr) || errors.As(err, &mysqlErr) || lion.IsConstraintError(err) ||
		errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) || errors.Is(err, sql.ErrTxDone) {
		return "database_error"
	}
	var tokenErr *oauth2.RetrieveError
	if errors.As(err, &tokenErr) {
		return "oauth_token_error"
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		return "network_error"
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return "invalid_json"
	}
	return "internal_error"
}
