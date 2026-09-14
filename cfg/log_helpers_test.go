package cfg

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

type safeTimeoutError struct{}

func (safeTimeoutError) Error() string { return "sensitive network timeout detail" }
func (safeTimeoutError) Timeout() bool { return true }

func TestClassifySafeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", want: "none"},
		{name: "canceled", err: context.Canceled, want: "canceled"},
		{name: "deadline", err: context.DeadlineExceeded, want: "deadline_exceeded"},
		{name: "connection refused", err: syscall.ECONNREFUSED, want: "connection_refused"},
		{name: "timeout", err: safeTimeoutError{}, want: "timeout"},
		{name: "other", err: errors.New("sensitive error detail"), want: "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySafeError(tt.err); got != tt.want {
				t.Errorf("classifySafeError() = %q, want %q", got, tt.want)
			}
		})
	}
}
