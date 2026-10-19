// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	sarcio "github.com/iamvirul/sarc/io"
)

const recipientsTestPassword = "alice-password-123"

func newAgeIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// archiveForRecipients archives two files openable by password (empty for none) and recipients.
func archiveForRecipients(t *testing.T, password string, recipients ...age.Recipient) ([]byte, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	contents := map[string][]byte{
		"report.txt": compressibleText(50 * 1024),
		"data.bin":   randomContent(t, 200*1024),
	}
	var paths []string
	for name, content := range contents {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	var buf bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&buf, password, 2, nil, sarcio.WithAgeRecipients(recipients...))
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive(paths); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), contents
}

func extractWith(t *testing.T, data []byte, password string, identities ...age.Identity) (string, []sarcio.ExtractionResult, error) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), password, nil, sarcio.WithIdentities(identities...)).Extract(outDir)
	return outDir, results, err
}

func requireExtractsAll(t *testing.T, data []byte, contents map[string][]byte, password string, identities ...age.Identity) {
	t.Helper()
	outDir, results, err := extractWith(t, data, password, identities...)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(results) != len(contents) {
		t.Fatalf("got %d results, want %d", len(results), len(contents))
	}
	for name, want := range contents {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: content mismatch", name)
		}
	}
}

func requireNoAccess(t *testing.T, data []byte, password string, identities ...age.Identity) {
	t.Helper()
	outDir, results, err := extractWith(t, data, password, identities...)
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeAuthFailed || !ae.IsFatal() {
		t.Fatalf("want fatal %s, got %v", sarcio.ErrCodeAuthFailed, err)
	}
	if len(results) != 0 {
		t.Fatalf("got %d results without a valid credential", len(results))
	}
	if _, statErr := os.Stat(outDir); !os.IsNotExist(statErr) {
		t.Fatalf("output written without a valid credential: %v", statErr)
	}
}

func TestEachRecipientCanOpenTheWholeArchive(t *testing.T) {
	bob, carol := newAgeIdentity(t), newAgeIdentity(t)
	data, contents := archiveForRecipients(t, recipientsTestPassword, bob.Recipient(), carol.Recipient())

	requireExtractsAll(t, data, contents, recipientsTestPassword)
	requireExtractsAll(t, data, contents, "", bob)
	requireExtractsAll(t, data, contents, "", carol)
	requireExtractsAll(t, data, contents, "wrong-password-1", carol)

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), "", nil, sarcio.WithIdentities(bob)).List()
	if err != nil || len(results) != len(contents) {
		t.Fatalf("list with identity: %v %+v", err, results)
	}
}

func TestNonRecipientsCannotOpenTheArchive(t *testing.T) {
	data, _ := archiveForRecipients(t, recipientsTestPassword, newAgeIdentity(t).Recipient())
	requireNoAccess(t, data, "wrong-password-1")
	requireNoAccess(t, data, "", newAgeIdentity(t))
	requireNoAccess(t, data, "wrong-password-1", newAgeIdentity(t))
	requireNoAccess(t, data, "")
}

func TestRecipientOnlyArchiveRejectsAnyPassword(t *testing.T) {
	bob := newAgeIdentity(t)
	data, contents := archiveForRecipients(t, "", bob.Recipient())
	requireExtractsAll(t, data, contents, "", bob)
	requireNoAccess(t, data, recipientsTestPassword)
}

func TestArchiverRequiresACredential(t *testing.T) {
	_, err := sarcio.NewStreamingArchiver(&bytes.Buffer{}, "", nil)
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeInvalidOption {
		t.Fatalf("want %s, got %v", sarcio.ErrCodeInvalidOption, err)
	}
}

func TestIdentityCannotOpenVersion1Archive(t *testing.T) {
	_, results, err := extractWith(t, readV1Fixture(t), "", newAgeIdentity(t))
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeAuthFailed || len(results) != 0 {
		t.Fatalf("want fatal %s, got %v %+v", sarcio.ErrCodeAuthFailed, err, results)
	}
}

// bech32Data decodes the data part of a Bech32 string (such as an age1... key) into bytes.
func bech32Data(t *testing.T, s string) []byte {
	t.Helper()
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	s = strings.ToLower(s)
	sep := strings.LastIndexByte(s, '1')
	if sep < 1 || len(s)-sep-1 < 6 {
		t.Fatalf("not bech32: %s", s)
	}
	var out []byte
	var acc, bits uint
	for _, c := range s[sep+1 : len(s)-6] {
		v := strings.IndexRune(charset, c)
		if v < 0 {
			t.Fatalf("invalid bech32 character %q", c)
		}
		acc = acc<<5 | uint(v)
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out
}

// TestRecipientIdentitiesAreNotRevealed checks the archive contains no recipient public
// key in Bech32, raw, or base64 form: age stanzas carry only ephemeral shares.
func TestRecipientIdentitiesAreNotRevealed(t *testing.T) {
	bob, carol := newAgeIdentity(t), newAgeIdentity(t)
	data, _ := archiveForRecipients(t, recipientsTestPassword, bob.Recipient(), carol.Recipient())
	for _, id := range []*age.X25519Identity{bob, carol} {
		pub := id.Recipient().String()
		raw := bech32Data(t, pub)
		if len(raw) != 32 {
			t.Fatalf("decoded public key is %d bytes", len(raw))
		}
		for form, needle := range map[string][]byte{
			"bech32":    []byte(pub),
			"raw":       raw,
			"base64":    []byte(base64.RawStdEncoding.EncodeToString(raw)),
			"base64url": []byte(base64.RawURLEncoding.EncodeToString(raw)),
		} {
			if bytes.Contains(data, needle) {
				t.Fatalf("archive reveals a recipient public key (%s form)", form)
			}
		}
	}
}

// TestSameInputsProduceUnrelatedHeaders confirms two archives for the same recipients
// share no recipient-block bytes, so archives cannot be linked by their headers.
func TestSameInputsProduceUnrelatedHeaders(t *testing.T) {
	bob := newAgeIdentity(t)
	a, _ := archiveForRecipients(t, recipientsTestPassword, bob.Recipient())
	b, _ := archiveForRecipients(t, recipientsTestPassword, bob.Recipient())
	ha, hb := a[:archiveHeaderSize(a)], b[:archiveHeaderSize(b)]
	// The first stanza is the password wrap; its 32-byte salt follows magic, version,
	// block length, stanza count, stanza type, body length, and iteration count.
	const saltOffset = 4 + 2 + 4 + 2 + 1 + 4 + 4
	if bytes.Equal(ha[saltOffset:saltOffset+32], hb[saltOffset:saltOffset+32]) {
		t.Fatal("two archives share a password stanza salt")
	}
	if bytes.Equal(ha[saltOffset+32:], hb[saltOffset+32:]) {
		t.Fatal("two archives share recipient block bytes")
	}
}
