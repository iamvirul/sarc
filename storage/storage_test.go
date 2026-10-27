// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestParseLocation(t *testing.T) {
	cases := []struct {
		raw    string
		want   Location
		remote bool
		err    bool
	}{
		{raw: "archive.sarc"},
		{raw: "./dir/archive.sarc"},
		{raw: `C:\backups\archive.sarc`},
		{raw: "C://odd"},
		{raw: "-"},
		{raw: "s3://bucket/backups/2026.sarc", want: Location{"s3", "bucket", "backups/2026.sarc"}, remote: true},
		{raw: "GS://b/k?v=1#x%20", want: Location{"gs", "b", "k?v=1#x%20"}, remote: true},
		{raw: "file:///tmp/a.sarc", want: Location{"file", "", "tmp/a.sarc"}, remote: true},
		{raw: "s3://bucket", remote: true, err: true},
		{raw: "s3://bucket/", remote: true, err: true},
		{raw: "s3://bucket/dir/", remote: true, err: true},
	}
	for _, c := range cases {
		got, remote, err := ParseLocation(c.raw)
		if remote != c.remote || (err != nil) != c.err {
			t.Errorf("%q: remote=%v err=%v, want remote=%v err=%v", c.raw, remote, err, c.remote, c.err)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("%q: got %+v, want %+v", c.raw, got, c.want)
		}
	}
}

func TestLocationStringRoundtrips(t *testing.T) {
	for _, raw := range []string{"s3://bucket/a/b.sarc", "file:///tmp/a.sarc"} {
		loc, _, err := ParseLocation(raw)
		if err != nil || loc.String() != raw {
			t.Errorf("%q: String() = %q, %v", raw, loc.String(), err)
		}
	}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	factory := func(context.Context, string) (Backend, error) { return nil, nil }
	if err := r.Register("mem", factory); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("MEM", factory); err == nil {
		t.Error("duplicate scheme accepted")
	}
	if err := r.Register("x", factory); err == nil {
		t.Error("one-letter scheme accepted")
	}
	if _, err := r.Backend(context.Background(), Location{Scheme: "nope"}); err == nil {
		t.Error("unregistered scheme accepted")
	}
	failing := func(context.Context, string) (Backend, error) { return nil, ErrNotFound }
	if err := r.Register("bad", failing); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Backend(context.Background(), Location{Scheme: "bad"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("factory error not wrapped: %v", err)
	}
}

// flakyObject serves data, and the first len(failAt) opens break after failAt[i] bytes,
// or fail to open with openErr.
type flakyObject struct {
	data    []byte
	failAt  []int
	openErr error
	opens   int
}

func (o *flakyObject) Size() int64 { return int64(len(o.data)) }

func (o *flakyObject) NewRangeReader(_ context.Context, offset, length int64) (io.ReadCloser, error) {
	o.opens++
	if o.openErr != nil {
		return nil, o.openErr
	}
	if length < 0 {
		length = int64(len(o.data)) - offset
	}
	r := io.Reader(bytes.NewReader(o.data[offset : offset+length]))
	if len(o.failAt) > 0 {
		r = io.MultiReader(io.LimitReader(r, int64(o.failAt[0])), errReader{})
		o.failAt = o.failAt[1:]
	}
	return io.NopCloser(r), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func noSleep(context.Context, time.Duration) error { return nil }

func readAllFrom(t *testing.T, obj Object) ([]byte, error) {
	t.Helper()
	r := newRangeReader(context.Background(), obj, 0, obj.Size())
	r.sleep = noSleep
	defer r.Close()
	return io.ReadAll(r)
}

func TestReaderResumesAfterBrokenConnections(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 10000)
	obj := &flakyObject{data: data, failAt: []int{1000, 0, 0, 5000, 7}}
	got, err := readAllFrom(t, obj)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("resumed read returned wrong data")
	}
	if obj.opens != 6 {
		t.Fatalf("opened %d times, want 6", obj.opens)
	}
}

func TestReaderGivesUpWithoutProgress(t *testing.T) {
	obj := &flakyObject{data: make([]byte, 100), failAt: make([]int, maxConsecutiveResumes+1)}
	if _, err := readAllFrom(t, obj); err == nil {
		t.Fatal("read succeeded despite every attempt failing")
	}
	if obj.opens != maxConsecutiveResumes+1 {
		t.Fatalf("opened %d times, want %d", obj.opens, maxConsecutiveResumes+1)
	}
}

func TestReaderDoesNotRetryPermanentErrors(t *testing.T) {
	for _, permanent := range []error{ErrNotFound, ErrObjectChanged} {
		obj := &flakyObject{data: make([]byte, 10), openErr: permanent}
		if _, err := readAllFrom(t, obj); !errors.Is(err, permanent) {
			t.Errorf("err = %v, want %v", err, permanent)
		}
		if obj.opens != 1 {
			t.Errorf("%v: opened %d times, want 1", permanent, obj.opens)
		}
	}
}

func TestReaderStopsWhenContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	obj := &flakyObject{data: make([]byte, 10), openErr: errors.New("transient")}
	if _, err := io.ReadAll(NewReader(ctx, obj)); err == nil {
		t.Fatal("read succeeded")
	}
	if obj.opens != 1 {
		t.Fatalf("opened %d times, want 1", obj.opens)
	}
}

func TestReaderOfEmptyObjectNeverOpens(t *testing.T) {
	obj := &flakyObject{}
	got, err := io.ReadAll(NewReader(context.Background(), obj))
	if err != nil || len(got) != 0 || obj.opens != 0 {
		t.Fatalf("got %d bytes, err %v, %d opens", len(got), err, obj.opens)
	}
}

func TestReaderAt(t *testing.T) {
	data := []byte("abcdefghij")
	ra := NewReaderAt(context.Background(), &flakyObject{data: data})
	p := make([]byte, 4)
	if n, err := ra.ReadAt(p, 3); n != 4 || err != nil || string(p) != "defg" {
		t.Fatalf("ReadAt(3) = %d, %v, %q", n, err, p)
	}
	if n, err := ra.ReadAt(p, 8); n != 2 || err != io.EOF || string(p[:2]) != "ij" {
		t.Fatalf("ReadAt(8) = %d, %v, %q", n, err, p[:n])
	}
	if n, err := ra.ReadAt(p, 10); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt(10) = %d, %v", n, err)
	}
	if _, err := ra.ReadAt(p, -1); err == nil {
		t.Fatal("negative offset accepted")
	}
}
