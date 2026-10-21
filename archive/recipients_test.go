// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

func newCEK(t *testing.T) [crypto.KeySize]byte {
	t.Helper()
	cek, err := crypto.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	return cek
}

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRecipientBlockEveryCredentialOpensIt(t *testing.T) {
	cek := newCEK(t)
	bob, carol := newIdentity(t), newIdentity(t)
	block, err := archive.SealRecipientBlock(cek, archive.Credentials{
		Passwords:     []string{"alice-password", "backup-password"},
		AgeRecipients: []age.Recipient{bob.Recipient(), carol.Recipient()},
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockers := map[string]archive.Unlockers{
		"first password":                    {Password: "alice-password"},
		"second password":                   {Password: "backup-password"},
		"bob":                               {Identities: []age.Identity{bob}},
		"carol":                             {Identities: []age.Identity{carol}},
		"wrong password but valid identity": {Password: "nope-nope", Identities: []age.Identity{carol}},
	}
	for name, u := range unlockers {
		got, err := archive.OpenRecipientBlock(block, u)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != cek {
			t.Fatalf("%s: wrong CEK", name)
		}
	}
}

func TestRecipientBlockRejectsNonMatchingCredentials(t *testing.T) {
	block, err := archive.SealRecipientBlock(newCEK(t), archive.Credentials{
		Passwords:     []string{"alice-password"},
		AgeRecipients: []age.Recipient{newIdentity(t).Recipient()},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, u := range map[string]archive.Unlockers{
		"wrong password":   {Password: "wrong-password"},
		"foreign identity": {Identities: []age.Identity{newIdentity(t)}},
		"nothing":          {},
		"wrong both":       {Password: "wrong-password", Identities: []age.Identity{newIdentity(t)}},
	} {
		if _, err := archive.OpenRecipientBlock(block, u); !errors.Is(err, archive.ErrNoMatchingCredential) {
			t.Fatalf("%s: want ErrNoMatchingCredential, got %v", name, err)
		}
	}
}

func TestPasswordOnlyBlockIgnoresIdentities(t *testing.T) {
	block, err := archive.SealRecipientBlock(newCEK(t), archive.Credentials{Passwords: []string{"pw-123456"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := archive.OpenRecipientBlock(block, archive.Unlockers{Identities: []age.Identity{newIdentity(t)}}); !errors.Is(err, archive.ErrNoMatchingCredential) {
		t.Fatalf("want ErrNoMatchingCredential, got %v", err)
	}
}

func TestSealRecipientBlockValidatesCredentials(t *testing.T) {
	cek := newCEK(t)
	tooMany := make([]string, archive.MaxPasswordRecipients+1)
	for i := range tooMany {
		tooMany[i] = "password"
	}
	for name, creds := range map[string]archive.Credentials{
		"none":           {},
		"empty password": {Passwords: []string{""}},
		"too many":       {Passwords: tooMany},
		"short key file": {KeyFiles: []archive.KeyFile{{Key: make([]byte, crypto.MinKeyFileSize-1)}}},
		"too many key files": {KeyFiles: func() []archive.KeyFile {
			kfs := make([]archive.KeyFile, archive.MaxKeyFileRecipients+1)
			for i := range kfs {
				kfs[i] = archive.KeyFile{Key: newKeyFile(t)}
			}
			return kfs
		}()},
	} {
		if _, err := archive.SealRecipientBlock(cek, creds); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func rawBlock(stanzas ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(stanzas)))
	for _, s := range stanzas {
		b = append(b, s...)
	}
	return b
}

func rawStanza(kind byte, body []byte) []byte {
	b := []byte{kind}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...)
}

func TestOpenRecipientBlockRejectsMalformedBlocks(t *testing.T) {
	passwordBody := make([]byte, 4+crypto.SaltSize+crypto.NonceSize+crypto.KeySize+crypto.GCMTagSize)
	keyFileStanzas := make([][]byte, archive.MaxKeyFileRecipients+1)
	for i := range keyFileStanzas {
		keyFileStanzas[i] = rawStanza(0x03, passwordBody[4:])
	}
	cases := map[string][]byte{
		"empty":                            {},
		"zero stanzas":                     rawBlock(),
		"truncated stanza":                 append(rawBlock(), 0x01, 0x00),
		"unknown stanza type":              rawBlock(rawStanza(0x7F, []byte("x"))),
		"short password body":              rawBlock(rawStanza(0x01, passwordBody[:10])),
		"two age stanzas":                  rawBlock(rawStanza(0x02, []byte("a")), rawStanza(0x02, []byte("b"))),
		"empty age stanza":                 rawBlock(rawStanza(0x02, nil)),
		"trailing bytes":                   append(rawBlock(rawStanza(0x01, passwordBody)), 0x00),
		"length past block":                append(rawBlock(), []byte{0x01, 0xFF, 0xFF, 0xFF, 0x7F}...),
		"count above maximum":              binary.LittleEndian.AppendUint16(nil, archive.MaxPasswordRecipients+2*archive.MaxKeyFileRecipients+2),
		"short key file body":              rawBlock(rawStanza(0x03, passwordBody)),
		"short key file and password body": rawBlock(rawStanza(0x04, passwordBody[:len(passwordBody)-1])),
		"too many key files":               rawBlock(keyFileStanzas...),
	}
	cases["length past block"][0] = 1 // count = 1, stanza declares a 2 GiB body
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := archive.OpenRecipientBlock(block, archive.Unlockers{Password: "pw", Identities: []age.Identity{newIdentity(t)}})
			if !errors.Is(err, archive.ErrMalformedRecipientBlock) {
				t.Fatalf("want ErrMalformedRecipientBlock, got %v", err)
			}
		})
	}
}

// TestHostileIterationCountIsRejectedQuickly patches a password stanza to declare 2^31
// PBKDF2 iterations; opening must fail fast instead of deriving for minutes.
func TestHostileIterationCountIsRejectedQuickly(t *testing.T) {
	block, err := archive.SealRecipientBlock(newCEK(t), archive.Credentials{Passwords: []string{"pw-123456"}})
	if err != nil {
		t.Fatal(err)
	}
	const iterationsOffset = 2 + 1 + 4 // count, stanza type, body length
	binary.LittleEndian.PutUint32(block[iterationsOffset:], 1<<31)

	start := time.Now()
	_, err = archive.OpenRecipientBlock(block, archive.Unlockers{Password: "pw-123456"})
	if !errors.Is(err, archive.ErrMalformedRecipientBlock) {
		t.Fatalf("want ErrMalformedRecipientBlock, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("rejection took %v", elapsed)
	}
}

func newKeyFile(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, crypto.MinKeyFileSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRecipientBlockKeyFileCredentials(t *testing.T) {
	cek := newCEK(t)
	solo, paired, bob := newKeyFile(t), newKeyFile(t), newIdentity(t)
	block, err := archive.SealRecipientBlock(cek, archive.Credentials{
		Passwords:     []string{"alice-password"},
		KeyFiles:      []archive.KeyFile{{Key: solo}, {Key: paired, Password: "second-factor"}},
		AgeRecipients: []age.Recipient{bob.Recipient()},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, u := range map[string]archive.Unlockers{
		"password":                     {Password: "alice-password"},
		"key file alone":               {KeyFiles: [][]byte{solo}},
		"key file among others":        {KeyFiles: [][]byte{newKeyFile(t), solo}},
		"paired key file and password": {KeyFiles: [][]byte{paired}, Password: "second-factor"},
		"age identity":                 {Identities: []age.Identity{bob}},
	} {
		got, err := archive.OpenRecipientBlock(block, u)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != cek {
			t.Fatalf("%s: wrong CEK", name)
		}
	}
}

func TestRecipientBlockKeyFileAndPasswordNeedsBoth(t *testing.T) {
	key := newKeyFile(t)
	block, err := archive.SealRecipientBlock(newCEK(t), archive.Credentials{
		KeyFiles: []archive.KeyFile{{Key: key, Password: "second-factor"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, u := range map[string]archive.Unlockers{
		"key file only":       {KeyFiles: [][]byte{key}},
		"password only":       {Password: "second-factor"},
		"key, wrong password": {KeyFiles: [][]byte{key}, Password: "wrong-factor"},
		"wrong key, password": {KeyFiles: [][]byte{newKeyFile(t)}, Password: "second-factor"},
	} {
		_, err := archive.OpenRecipientBlock(block, u)
		var noMatch *archive.NoMatchingCredentialError
		if !errors.As(err, &noMatch) || !errors.Is(err, archive.ErrNoMatchingCredential) {
			t.Fatalf("%s: want NoMatchingCredentialError, got %v", name, err)
		}
		if len(noMatch.Accepts) != 1 || noMatch.Accepts[0] != "key file + password" {
			t.Fatalf("%s: accepts %q", name, noMatch.Accepts)
		}
	}
}

func TestNoMatchingCredentialErrorListsAcceptedKinds(t *testing.T) {
	block, err := archive.SealRecipientBlock(newCEK(t), archive.Credentials{
		Passwords:     []string{"pw-one-1", "pw-two-2"},
		KeyFiles:      []archive.KeyFile{{Key: newKeyFile(t)}},
		AgeRecipients: []age.Recipient{newIdentity(t).Recipient()},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = archive.OpenRecipientBlock(block, archive.Unlockers{Password: "wrong-password"})
	var noMatch *archive.NoMatchingCredentialError
	if !errors.As(err, &noMatch) {
		t.Fatalf("want NoMatchingCredentialError, got %v", err)
	}
	if got, want := strings.Join(noMatch.Accepts, ", "), "password, key file, age or SSH identity"; got != want {
		t.Fatalf("accepts %q, want %q", got, want)
	}
}

// TestHostileKeyFilePasswordIterationsRejectedQuickly patches a key file and password
// stanza to declare 2^31 PBKDF2 iterations; opening must fail fast.
func TestHostileKeyFilePasswordIterationsRejectedQuickly(t *testing.T) {
	key := newKeyFile(t)
	block, err := archive.SealRecipientBlock(newCEK(t), archive.Credentials{
		KeyFiles: []archive.KeyFile{{Key: key, Password: "second-factor"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const iterationsOffset = 2 + 1 + 4 // count, stanza type, body length
	binary.LittleEndian.PutUint32(block[iterationsOffset:], 1<<31)

	start := time.Now()
	_, err = archive.OpenRecipientBlock(block, archive.Unlockers{KeyFiles: [][]byte{key}, Password: "second-factor"})
	if !errors.Is(err, archive.ErrMalformedRecipientBlock) {
		t.Fatalf("want ErrMalformedRecipientBlock, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("rejection took %v", elapsed)
	}
}

type failingIdentity struct{ err error }

func (f failingIdentity) Unwrap([]*age.Stanza) ([]byte, error) { return nil, f.err }

func TestIdentityFailureIsReportedUnlessAnotherCredentialMatches(t *testing.T) {
	cek := newCEK(t)
	block, err := archive.SealRecipientBlock(cek, archive.Credentials{
		Passwords:     []string{"alice-password"},
		AgeRecipients: []age.Recipient{newIdentity(t).Recipient()},
	})
	if err != nil {
		t.Fatal(err)
	}
	failing := []age.Identity{failingIdentity{err: errors.New("wrong passphrase")}}
	got, err := archive.OpenRecipientBlock(block, archive.Unlockers{Password: "alice-password", Identities: failing})
	if err != nil || got != cek {
		t.Fatalf("password did not open the block alongside a failing identity: %v", err)
	}
	_, err = archive.OpenRecipientBlock(block, archive.Unlockers{Password: "wrong-password", Identities: failing})
	var identityErr *crypto.IdentityError
	if !errors.As(err, &identityErr) || errors.Is(err, archive.ErrMalformedRecipientBlock) {
		t.Fatalf("want IdentityError, got %v", err)
	}
}
