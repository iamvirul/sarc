// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Archive signatures use OpenSSH's signature format (PROTOCOL.sshsig): the signed data
// binds a namespace and a hash algorithm to the SHA-512 of the message, so any
// OpenSSH-compatible tool can check them (ssh-keygen -Y check-novalidate -n sarc-archive).
const (
	// SignatureNamespace separates archive signatures from SSH signatures made for any
	// other purpose with the same key.
	SignatureNamespace = "sarc-archive"

	sshsigMagic    = "SSHSIG"
	sshsigVersion  = 1
	sshsigHashAlgo = "sha512"
	armorBegin     = "-----BEGIN SSH SIGNATURE-----"
	armorEnd       = "-----END SSH SIGNATURE-----"
	armorLineLen   = 70
	minRSABits     = 2048
)

// ErrBadSignature is returned when a signature does not verify or cannot be parsed.
var ErrBadSignature = errors.New("crypto/signature: invalid signature")

// allowedSignatureFormats lists the signature algorithms accepted for each key type.
// RSA signatures must use SHA-512 (rsa-sha2-512), never SHA-1 (ssh-rsa). Security-key
// (sk-*) types can be verified but not created by sarc.
var allowedSignatureFormats = map[string]string{
	ssh.KeyAlgoED25519:    ssh.KeyAlgoED25519,
	ssh.KeyAlgoSKED25519:  ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoECDSA256:   ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384:   ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521:   ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoSKECDSA256: ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoRSA:        ssh.KeyAlgoRSASHA512,
}

// SignMessage returns an SSH signature by signer over message in the archive namespace.
// Ed25519, ECDSA, and RSA keys of at least 2048 bits are supported; RSA signs with
// SHA-512.
func SignMessage(signer ssh.Signer, message []byte) ([]byte, error) {
	pub := signer.PublicKey()
	format, ok := allowedSignatureFormats[pub.Type()]
	if !ok || pub.Type() == ssh.KeyAlgoSKED25519 || pub.Type() == ssh.KeyAlgoSKECDSA256 {
		return nil, fmt.Errorf("crypto/signature: unsupported signing key type %s", pub.Type())
	}
	if err := checkRSASize(pub); err != nil {
		return nil, err
	}
	data := signedData(message)
	var sig *ssh.Signature
	var err error
	if pub.Type() == ssh.KeyAlgoRSA {
		algoSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("crypto/signature: RSA key cannot sign with SHA-512")
		}
		sig, err = algoSigner.SignWithAlgorithm(rand.Reader, data, format)
	} else {
		sig, err = signer.Sign(rand.Reader, data)
	}
	if err != nil {
		return nil, fmt.Errorf("crypto/signature: sign: %w", err)
	}
	var blob []byte
	blob = append(blob, sshsigMagic...)
	blob = binary.BigEndian.AppendUint32(blob, sshsigVersion)
	blob = appendSSHString(blob, pub.Marshal())
	blob = appendSSHString(blob, []byte(SignatureNamespace))
	blob = appendSSHString(blob, nil)
	blob = appendSSHString(blob, []byte(sshsigHashAlgo))
	blob = appendSSHString(blob, ssh.Marshal(sig))
	return blob, nil
}

// VerifyMessage checks an SSH signature blob made by SignMessage (or by ssh-keygen -Y
// sign in the archive namespace with SHA-512) over message, and returns the signer's
// public key. It returns an error wrapping ErrBadSignature for any parse or verify
// failure, a wrong namespace or hash algorithm, or a disallowed key or signature type.
func VerifyMessage(blob, message []byte) (ssh.PublicKey, error) {
	p, err := parseSSHSig(blob)
	if err != nil {
		return nil, err
	}
	pub, err := ssh.ParsePublicKey(p.publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: public key: %v", ErrBadSignature, err)
	}
	format, ok := allowedSignatureFormats[pub.Type()]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported key type %s", ErrBadSignature, pub.Type())
	}
	if err := checkRSASize(pub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if p.namespace != SignatureNamespace || p.hashAlgo != sshsigHashAlgo {
		return nil, fmt.Errorf("%w: namespace or hash algorithm is not the archive's", ErrBadSignature)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(p.signature, &sig); err != nil {
		return nil, fmt.Errorf("%w: signature encoding: %v", ErrBadSignature, err)
	}
	if sig.Format != format {
		return nil, fmt.Errorf("%w: signature type %s not allowed for %s keys", ErrBadSignature, sig.Format, pub.Type())
	}
	if err := pub.Verify(signedData(message), &sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return pub, nil
}

// ArmorSignature encodes a signature blob in the PEM-like form ssh-keygen reads.
func ArmorSignature(blob []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(blob)
	var b bytes.Buffer
	b.WriteString(armorBegin + "\n")
	for len(enc) > armorLineLen {
		b.WriteString(enc[:armorLineLen] + "\n")
		enc = enc[armorLineLen:]
	}
	b.WriteString(enc + "\n" + armorEnd + "\n")
	return b.Bytes()
}

// DearmorSignature decodes the armored form produced by ArmorSignature or ssh-keygen.
func DearmorSignature(armored []byte) ([]byte, error) {
	s := string(bytes.TrimSpace(armored))
	if len(s) < len(armorBegin)+len(armorEnd) || s[:len(armorBegin)] != armorBegin || s[len(s)-len(armorEnd):] != armorEnd {
		return nil, fmt.Errorf("%w: not an armored SSH signature", ErrBadSignature)
	}
	body := bytes.Join(bytes.Fields([]byte(s[len(armorBegin):len(s)-len(armorEnd)])), nil)
	blob, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("%w: armor: %v", ErrBadSignature, err)
	}
	return blob, nil
}

// signedData returns the data an SSH signature in the archive namespace signs.
func signedData(message []byte) []byte {
	digest := sha512.Sum512(message)
	var d []byte
	d = append(d, sshsigMagic...)
	d = appendSSHString(d, []byte(SignatureNamespace))
	d = appendSSHString(d, nil)
	d = appendSSHString(d, []byte(sshsigHashAlgo))
	return appendSSHString(d, digest[:])
}

func checkRSASize(pub ssh.PublicKey) error {
	if pub.Type() != ssh.KeyAlgoRSA {
		return nil
	}
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return errors.New("crypto/signature: unreadable RSA key")
	}
	rsaKey, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() < minRSABits {
		return fmt.Errorf("crypto/signature: RSA keys must have at least %d bits", minRSABits)
	}
	return nil
}

func appendSSHString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

type sshsig struct {
	publicKey []byte
	namespace string
	hashAlgo  string
	signature []byte
}

func parseSSHSig(blob []byte) (sshsig, error) {
	var p sshsig
	if len(blob) < len(sshsigMagic)+4 || string(blob[:len(sshsigMagic)]) != sshsigMagic {
		return p, fmt.Errorf("%w: bad magic", ErrBadSignature)
	}
	rest := blob[len(sshsigMagic):]
	if binary.BigEndian.Uint32(rest) != sshsigVersion {
		return p, fmt.Errorf("%w: unsupported version", ErrBadSignature)
	}
	rest = rest[4:]
	fields := make([][]byte, 5)
	for i := range fields {
		if len(rest) < 4 {
			return p, fmt.Errorf("%w: truncated", ErrBadSignature)
		}
		n := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(n) > uint64(len(rest)) {
			return p, fmt.Errorf("%w: truncated", ErrBadSignature)
		}
		fields[i], rest = rest[:n], rest[n:]
	}
	if len(rest) != 0 {
		return p, fmt.Errorf("%w: trailing bytes", ErrBadSignature)
	}
	// fields[2] is the reserved string, which carries nothing in version 1.
	return sshsig{publicKey: fields[0], namespace: string(fields[1]), hashAlgo: string(fields[3]), signature: fields[4]}, nil
}
