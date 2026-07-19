// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import "fmt"

// ErrorKind classifies an archive error as recoverable or fatal.
type ErrorKind uint8

const (
	// ErrKindFatal indicates the archive cannot be processed further.
	ErrKindFatal ErrorKind = iota
	// ErrKindRecoverable indicates the current entry failed but processing may continue.
	ErrKindRecoverable
)

// ArchiveError is the structured error type for all sarc I/O operations.
// Internal details (keys, paths, crypto state) are never included in Message
// to prevent leaking sensitive information to callers.
type ArchiveError struct {
	Kind    ErrorKind
	Code    string
	Message string
	cause   error
}

func (e *ArchiveError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *ArchiveError) Unwrap() error { return e.cause }

func (e *ArchiveError) IsFatal() bool { return e.Kind == ErrKindFatal }

// fatal returns a non-recoverable ArchiveError wrapping cause.
func fatal(code, message string, cause error) *ArchiveError {
	return &ArchiveError{Kind: ErrKindFatal, Code: code, Message: message, cause: cause}
}

// recoverable returns a recoverable ArchiveError wrapping cause.
func recoverable(code, message string, cause error) *ArchiveError {
	return &ArchiveError{Kind: ErrKindRecoverable, Code: code, Message: message, cause: cause}
}

// Sentinel error codes.
const (
	ErrCodeBadMagic      = "BAD_MAGIC"
	ErrCodeBadVersion    = "BAD_VERSION"
	ErrCodeAuthFailed    = "AUTH_FAILED"
	ErrCodeTruncated     = "TRUNCATED"
	ErrCodeIntegrityFail = "INTEGRITY_FAIL"
	ErrCodeWriteFailed   = "WRITE_FAILED"
	ErrCodeReadFailed    = "READ_FAILED"
	ErrCodeWorkerPanic   = "WORKER_PANIC"
)
