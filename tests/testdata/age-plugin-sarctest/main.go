// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

// Command age-plugin-sarctest is a test-only age plugin standing in for a hardware token
// plugin such as age-plugin-yubikey. Its recipient and identity carry the same 32-byte
// secret, so it provides no security; it exists to exercise sarc's plugin client over
// the real age plugin protocol. Every wrap and unwrap displays a message, as a hardware
// plugin asking for a touch would.
//
// Run with -generate to print a new identity line and its recipient.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

const (
	name       = "sarctest"
	secretSize = 32
	nonceSize  = 12
)

func main() {
	p, err := plugin.New(name)
	if err != nil {
		log.Fatal(err)
	}
	p.RegisterFlags(nil)
	generate := flag.Bool("generate", false, "print a new identity and its recipient")
	flag.Parse()
	if *generate {
		secret := make([]byte, secretSize)
		if _, err := rand.Read(secret); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("# recipient: %s\n%s\n", plugin.EncodeRecipient(name, secret), plugin.EncodeIdentity(name, secret))
		return
	}

	p.HandleRecipient(func(data []byte) (age.Recipient, error) { return newToken(p, data) })
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) { return newToken(p, data) })
	p.HandleIdentity(func(data []byte) (age.Identity, error) { return newToken(p, data) })
	os.Exit(p.Main())
}

type token struct {
	p    *plugin.Plugin
	aead cipher.AEAD
}

func newToken(p *plugin.Plugin, secret []byte) (*token, error) {
	if len(secret) != secretSize {
		return nil, errors.New("sarctest key must be 32 bytes")
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &token{p: p, aead: aead}, nil
}

func (t *token) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	if err := t.p.DisplayMessage("sarctest token wrapping"); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize, nonceSize+len(fileKey)+t.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return []*age.Stanza{{Type: name, Body: t.aead.Seal(nonce, nonce, fileKey, nil)}}, nil
}

func (t *token) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if err := t.p.DisplayMessage("touch your sarctest token"); err != nil {
		return nil, err
	}
	for _, s := range stanzas {
		if s.Type != name || len(s.Body) < nonceSize {
			continue
		}
		if fileKey, err := t.aead.Open(nil, s.Body[:nonceSize], s.Body[nonceSize:], nil); err == nil {
			return fileKey, nil
		}
	}
	return nil, age.ErrIncorrectIdentity
}
