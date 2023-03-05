package errs

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

// OK is returned on success.
func OK(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.OK),
		"No error.")
	s = s.WithDetails(details...)
	return s
}

// Canceled indicates the operation was canceled (typically by the caller).
func Canceled(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.Canceled),
		"Request cancelled by the client.")
	s = s.WithDetails(details...)
	return s
}

// Unknown error. An example of where this error may be returned is
// if a Status value received from another address space belongs to
// an error-space that is not known in this address space. Also
// errors raised by APIs that do not return enough error information
// may be converted to this error.
func Unknown(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.Unknown),
		"Unknown server error.")
	s = s.WithDetails(details...)
	return s
}

// InvalidArgument indicates client specified an invalid argument.
// Note that this differs from FailedPrecondition. It indicates arguments
// that are problematic regardless of the state of the system
// (e.g., a malformed file name).
// For example, Request field x.y.z is xxx, expected one of [yyy, zzz].
func InvalidArgument(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.InvalidArgument),
		"Client specified an invalid argument.")
	s = s.WithDetails(details...)
	return s
}

// DeadlineExceeded means operation expired before completion.
// For operations that change the state of the system, this error may be
// returned even if the operation has completed successfully. For
// example, a successful response from a server could have been delayed
// long enough for the deadline to expire.
// This will happen only if the caller sets a deadline that is shorter than the method's
// default deadline (i.e. requested deadline is not enough for the server to process the request) and
// the request did not finish within the deadline.
func DeadlineExceeded(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.DeadlineExceeded),
		"Request deadline exceeded.")
	s = s.WithDetails(details...)
	return s
}

// NotFound means some requested entity (e.g., file or directory) was
// not found.
func NotFound(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.NotFound),
		"A specified resource is not found, or the request is rejected by undisclosed reasons, such as whitelisting.")
	s = s.WithDetails(details...)
	return s
}

// AlreadyExists means an attempt to create an entity failed because one
// already exists.
// For example, Resource 'xxx' already exists.
func AlreadyExists(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.AlreadyExists),
		"The resource that a client tried to create already exists.")
	s = s.WithDetails(details...)
	return s
}

// PermissionDenied indicates the caller does not have permission to
// execute the specified operation. It must not be used for rejections
// caused by exhausting some resource (use ResourceExhausted
// instead for those errors). It must not be
// used if the caller cannot be identified (use Unauthenticated
// instead for those errors).
// For example, Permission 'xxx' denied on file 'yyy'.
// This can happen because the OAuth token does not have the right scopes,
// the client doesn't have permission, or the API has not been enabled for the client project.
func PermissionDenied(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.PermissionDenied),
		"Client does not have sufficient permission.")
	s = s.WithDetails(details...)
	return s
}

// ResourceExhausted indicates some resource has been exhausted, perhaps
// a per-user quota, or perhaps the entire file system is out of space.
// For example, Quota limit 'xxx' exceeded.
// The client should look for google.rpc.QuotaFailure error detail for more information.
func ResourceExhausted(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.ResourceExhausted),
		"Either out of resource quota or reaching rate limiting.")
	s = s.WithDetails(details...)
	return s
}

// FailedPrecondition indicates operation was rejected because the
// system is not in a state required for the operation's execution.
// For example, directory to be deleted may be non-empty, an rmdir
// operation is applied to a non-directory, etc.
//
// A litmus test that may help a service implementor in deciding
// between FailedPrecondition, Aborted, and Unavailable:
//  (a) Use Unavailable if the client can retry just the failing call.
//  (b) Use Aborted if the client should retry at a higher-level
//      (e.g., restarting a read-modify-write sequence).
//  (c) Use FailedPrecondition if the client should not retry until
//      the system state has been explicitly fixed. E.g., if an "rmdir"
//      fails because the directory is non-empty, FailedPrecondition
//      should be returned since the client should not retry unless
//      they have first fixed up the directory by deleting files from it.
//  (d) Use FailedPrecondition if the client performs conditional
//      REST Get/Update/Delete on a resource and the resource on the
//      server does not match the condition. E.g., conflicting
//      read-modify-write on the same resource.
//
// For example, Resource xxx is a non-empty directory, so it cannot be deleted.
func FailedPrecondition(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.FailedPrecondition),
		"Request can not be executed in the current system state, such as deleting a non-empty directory.")
	s = s.WithDetails(details...)
	return s
}

// Aborted indicates the operation was aborted, typically due to a
// concurrency issue like sequencer check failures, transaction aborts,
// etc.
//
// See litmus test above for deciding between FailedPrecondition,
// Aborted, and Unavailable.
//
// For example, Couldn’t acquire lock on resource ‘xxx’.
func Aborted(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.Aborted),
		"Concurrency conflict, such as read-modify-write conflict.")
	s = s.WithDetails(details...)
	return s
}

// OutOfRange means operation was attempted past the valid range.
// E.g., seeking or reading past end of file.
//
// Unlike InvalidArgument, this error indicates a problem that may
// be fixed if the system state changes. For example, a 32-bit file
// system will generate InvalidArgument if asked to read at an
// offset that is not in the range [0,2^32-1], but it will generate
// OutOfRange if asked to read from an offset past the current
// file size.
//
// There is a fair bit of overlap between FailedPrecondition and
// OutOfRange. We recommend using OutOfRange (the more specific
// error) when it applies so that callers who are iterating through
// a space can easily look for an OutOfRange error to detect when
// they are done.
//
// For example, Parameter 'age' is out of range [0, 125].
func OutOfRange(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.OutOfRange),
		"Client specified an invalid range.")
	s = s.WithDetails(details...)
	return s
}

// Unimplemented indicates operation is not implemented or not
// supported/enabled in this service.
// For example, Method 'xxx' not implemented.
func Unimplemented(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.Unimplemented),
		"The API method not implemented or enabled by the server.")
	s = s.WithDetails(details...)
	return s
}

// Internal errors. Means some invariants expected by underlying
// system has been broken. If you see one of these errors,
// something is very broken.
func Internal(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.Internal),
		"Internal server error.")
	s = s.WithDetails(details...)
	return s
}

// Unavailable indicates the service is currently unavailable.
// This is a most likely a transient condition and may be corrected
// by retrying with a backoff. Note that it is not always safe to retry
// non-idempotent operations.
//
// See litmus test above for deciding between FailedPrecondition,
// Aborted, and Unavailable.
func Unavailable(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.Unavailable),
		"Service unavailable.")
	s = s.WithDetails(details...)
	return s
}

// DataLoss indicates unrecoverable data loss or corruption.
func DataLoss(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.DataLoss),
		"Unrecoverable data loss or data corruption.")
	s = s.WithDetails(details...)
	return s
}

// Unauthenticated indicates the request does not have valid
// authentication credentials for the operation.
func Unauthenticated(ctx context.Context, details ...proto.Message) *Status {
	s := New(int32(codes.Unauthenticated),
		"Request not authenticated due to missing, invalid, or expired OAuth token.")
	s = s.WithDetails(details...)
	return s
}
