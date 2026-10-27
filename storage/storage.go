// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

// Package storage reads and writes archives as objects in local or remote stores, named
// by URLs such as s3://bucket/key. A Backend serves one bucket; a Registry maps URL
// schemes to the factories that create them, so new stores plug in without changes to
// the archive code, which only ever sees an io.Writer, io.Reader, or io.ReaderAt.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Backend stores objects named by keys in one bucket or container.
type Backend interface {
	// Create starts writing the object key. Nothing appears under key until the Writer
	// is closed successfully, which replaces any existing object.
	Create(ctx context.Context, key string) (Writer, error)
	// Open returns the current version of the object key, or an error wrapping
	// ErrNotFound.
	Open(ctx context.Context, key string) (Object, error)
}

// Writer writes one object. Close commits it; Abort discards everything written. Only
// the first call to either has any effect.
type Writer interface {
	io.Writer
	Close() error
	Abort() error
}

// Object is one version of a stored object. Reads of an object that was replaced after
// Open fail with an error wrapping ErrObjectChanged, so a reader never mixes versions.
type Object interface {
	Size() int64
	// NewRangeReader reads length bytes from offset, or to the end when length < 0.
	NewRangeReader(ctx context.Context, offset, length int64) (io.ReadCloser, error)
}

var (
	// ErrNotFound is wrapped by errors for a missing object or bucket.
	ErrNotFound = errors.New("storage: object not found")
	// ErrObjectChanged is wrapped by errors for reads of an object replaced after Open.
	ErrObjectChanged = errors.New("storage: object changed while reading")
)

// Location names an object as scheme://bucket/key. Bucket is empty for file:///path.
type Location struct {
	Scheme string
	Bucket string
	Key    string
}

func (l Location) String() string { return l.Scheme + "://" + l.Bucket + "/" + l.Key }

// ParseLocation parses raw as scheme://bucket/key and reports false when raw is not a
// URL, such as a plain path. The key is taken verbatim, without URL decoding, since
// object keys may contain '%', '?', and '#'.
func ParseLocation(raw string) (Location, bool, error) {
	scheme, rest, found := strings.Cut(raw, "://")
	if !found || !validScheme(scheme) {
		return Location{}, false, nil
	}
	bucket, key, _ := strings.Cut(rest, "/")
	if key == "" || strings.HasSuffix(key, "/") {
		return Location{}, true, fmt.Errorf("storage: %s:// location needs an object key, as in %s://bucket/path/archive.sarc", scheme, scheme)
	}
	return Location{Scheme: strings.ToLower(scheme), Bucket: bucket, Key: key}, true, nil
}

// validScheme reports whether s is a URL scheme of at least two characters, so that a
// Windows drive letter is never taken for one.
func validScheme(s string) bool {
	if len(s) < 2 {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// Factory returns the Backend for one bucket.
type Factory func(ctx context.Context, bucket string) (Backend, error)

// Registry maps URL schemes to backend factories.
type Registry struct {
	factories map[string]Factory
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{factories: map[string]Factory{}}
}

// Register adds the factory for scheme. It fails if scheme is invalid or taken.
func (r *Registry) Register(scheme string, f Factory) error {
	scheme = strings.ToLower(scheme)
	if !validScheme(scheme) {
		return fmt.Errorf("storage: invalid scheme %q", scheme)
	}
	if _, ok := r.factories[scheme]; ok {
		return fmt.Errorf("storage: scheme %q registered twice", scheme)
	}
	r.factories[scheme] = f
	return nil
}

// Backend returns the backend serving loc's bucket.
func (r *Registry) Backend(ctx context.Context, loc Location) (Backend, error) {
	f, ok := r.factories[loc.Scheme]
	if !ok {
		return nil, fmt.Errorf("storage: unsupported scheme %q (supported: %s)", loc.Scheme, strings.Join(r.Schemes(), ", "))
	}
	b, err := f(ctx, loc.Bucket)
	if err != nil {
		return nil, fmt.Errorf("storage: %s: %w", loc.Scheme, err)
	}
	return b, nil
}

// Schemes returns the registered schemes in order.
func (r *Registry) Schemes() []string {
	schemes := make([]string, 0, len(r.factories))
	for s := range r.factories {
		schemes = append(schemes, s)
	}
	sort.Strings(schemes)
	return schemes
}
