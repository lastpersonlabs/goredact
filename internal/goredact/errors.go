package goredact

import "errors"

// Errors returned by this package never contain bytes from the scanned
// input. Errors that originate in the caller-supplied reader or writer are
// wrapped in ReadError or WriteError respectively so callers can
// distinguish I/O failures from configuration or internal failures; the
// wrapped error is produced by the caller's own io implementation and is
// returned unmodified.

// ErrInvalidConfig is returned (wrapped, with detail that never includes
// input data) by New when the configuration is invalid.
var ErrInvalidConfig = errors.New("goredact: invalid configuration")

// ReadError wraps an error returned by the source io.Reader.
type ReadError struct{ Err error }

func (e *ReadError) Error() string { return "goredact: read: " + e.Err.Error() }
func (e *ReadError) Unwrap() error { return e.Err }

// WriteError wraps an error returned by the destination io.Writer.
type WriteError struct{ Err error }

func (e *WriteError) Error() string { return "goredact: write: " + e.Err.Error() }
func (e *WriteError) Unwrap() error { return e.Err }
