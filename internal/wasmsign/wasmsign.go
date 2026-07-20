// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package wasmsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	RoleTEEPAgent = "teep-agent"
	RoleApp       = "app"

	TEEPAgentKID = "twep-demo-teep-agent-code-signing-v1"
	AppKID       = "twep-demo-app-code-signing-v1"
)

var (
	ErrMissingSignature  = errors.New("missing twep.sig custom section")
	ErrInvalidSignature  = errors.New("invalid twep.sig custom section")
	ErrRoleMismatch      = errors.New("twep.sig role mismatch")
	ErrSignatureRejected = errors.New("twep.sig signature rejected")
)

type signaturePayload struct {
	Alg  string `cbor:"alg"`
	KID  []byte `cbor:"kid"`
	Sig  []byte `cbor:"sig"`
	Role string `cbor:"role"`
}

type parsedSignature struct {
	payload     signaturePayload
	prefixBytes []byte
	sectionOff  int
}

func Sign(wasm []byte, privateCOSEKey []byte, role string, kid []byte) ([]byte, error) {
	if !validRole(role) {
		return nil, fmt.Errorf("unsupported role %q", role)
	}
	unsigned, err := StripSignature(wasm)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(privateCOSEKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(unsigned)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign wasm: %w", err)
	}
	payload := signaturePayload{
		Alg:  "ESP256",
		KID:  append([]byte(nil), kid...),
		Sig:  rawP256Signature(r, s),
		Role: role,
	}
	payloadBytes, err := encodeSignaturePayload(payload)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), unsigned...)
	out = append(out, 0x00)
	out = appendVaruint32(out, uint32(len("twep.sig")+len(payloadBytes)+1))
	out = appendVaruint32(out, uint32(len("twep.sig")))
	out = append(out, "twep.sig"...)
	out = append(out, payloadBytes...)
	return out, nil
}

func Verify(wasm []byte, privateOrPublicCOSEKey []byte, expectedRole string) error {
	if !validRole(expectedRole) {
		return fmt.Errorf("unsupported role %q", expectedRole)
	}
	parsed, err := parseSignature(wasm)
	if err != nil {
		return err
	}
	if parsed.payload.Role != expectedRole {
		return ErrRoleMismatch
	}
	if parsed.payload.Alg != "ESP256" || len(parsed.payload.KID) == 0 || len(parsed.payload.Sig) != 64 {
		return ErrInvalidSignature
	}
	key, err := parsePublicKey(privateOrPublicCOSEKey)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(parsed.prefixBytes)
	r := new(big.Int).SetBytes(parsed.payload.Sig[:32])
	s := new(big.Int).SetBytes(parsed.payload.Sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return ErrSignatureRejected
	}
	return nil
}

func StripSignature(wasm []byte) ([]byte, error) {
	if len(wasm) < 8 || !bytes.Equal(wasm[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		return nil, errors.New("malformed wasm header")
	}
	off := 8
	finalSigOff := -1
	for off < len(wasm) {
		sectionStart := off
		sectionID := wasm[off]
		off++
		size, next, ok := readVaruint32(wasm, off)
		if !ok {
			return nil, errors.New("malformed wasm section size")
		}
		off = next
		if int(size) > len(wasm)-off {
			return nil, errors.New("truncated wasm section")
		}
		payloadStart := off
		payloadEnd := off + int(size)
		if sectionID == 0 && customSectionName(wasm[payloadStart:payloadEnd]) == "twep.sig" {
			if payloadEnd != len(wasm) {
				return nil, errors.New("twep.sig custom section is not final")
			}
			finalSigOff = sectionStart
		}
		off = payloadEnd
	}
	if off != len(wasm) {
		return nil, errors.New("trailing wasm bytes")
	}
	if finalSigOff >= 0 {
		return append([]byte(nil), wasm[:finalSigOff]...), nil
	}
	return append([]byte(nil), wasm...), nil
}

func parseSignature(wasm []byte) (*parsedSignature, error) {
	if len(wasm) < 8 || !bytes.Equal(wasm[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		return nil, ErrInvalidSignature
	}
	off := 8
	for off < len(wasm) {
		sectionStart := off
		sectionID := wasm[off]
		off++
		size, next, ok := readVaruint32(wasm, off)
		if !ok {
			return nil, ErrInvalidSignature
		}
		off = next
		if int(size) > len(wasm)-off {
			return nil, ErrInvalidSignature
		}
		payloadStart := off
		payloadEnd := off + int(size)
		if sectionID == 0 {
			name, nameEnd, ok := readCustomSectionName(wasm[payloadStart:payloadEnd])
			if ok && name == "twep.sig" {
				if payloadEnd != len(wasm) {
					return nil, ErrInvalidSignature
				}
				var payload signaturePayload
				if err := cbor.Unmarshal(wasm[payloadStart+nameEnd:payloadEnd], &payload); err != nil {
					return nil, ErrInvalidSignature
				}
				return &parsedSignature{
					payload:     payload,
					prefixBytes: wasm[:sectionStart],
					sectionOff:  sectionStart,
				}, nil
			}
		}
		off = payloadEnd
	}
	return nil, ErrMissingSignature
}

func encodeSignaturePayload(payload signaturePayload) ([]byte, error) {
	out := make([]byte, 0, 96)
	out = append(out, 0xa4)
	out = appendText(out, "alg")
	out = appendText(out, payload.Alg)
	out = appendText(out, "kid")
	out = appendBytes(out, payload.KID)
	out = appendText(out, "sig")
	out = appendBytes(out, payload.Sig)
	out = appendText(out, "role")
	out = appendText(out, payload.Role)
	return out, nil
}

func parsePrivateKey(keyCBOR []byte) (*ecdsa.PrivateKey, error) {
	var key cose.Key
	if err := cbor.Unmarshal(keyCBOR, &key); err != nil {
		return nil, fmt.Errorf("decode cose key: %w", err)
	}
	x, y, d, err := coseKeyCoordinates(key, true)
	if err != nil {
		return nil, err
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
	if !priv.Curve.IsOnCurve(priv.X, priv.Y) || priv.D.Sign() <= 0 {
		return nil, errors.New("invalid P-256 private key")
	}
	return priv, nil
}

func parsePublicKey(keyCBOR []byte) (*ecdsa.PublicKey, error) {
	var key cose.Key
	if err := cbor.Unmarshal(keyCBOR, &key); err != nil {
		return nil, fmt.Errorf("decode cose key: %w", err)
	}
	x, y, _, err := coseKeyCoordinates(key, false)
	if err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("invalid P-256 public key")
	}
	return pub, nil
}

func coseKeyCoordinates(key cose.Key, needPrivate bool) ([]byte, []byte, []byte, error) {
	alg, err := key.AlgorithmOrDefault()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key algorithm: %w", err)
	}
	if alg != cose.AlgorithmESP256 {
		return nil, nil, nil, fmt.Errorf("key algorithm = %v, want ESP256", alg)
	}
	x, xOK := key.ParamBytes(cose.KeyLabelEC2X)
	y, yOK := key.ParamBytes(cose.KeyLabelEC2Y)
	if !xOK || !yOK || len(x) != 32 || len(y) != 32 {
		return nil, nil, nil, errors.New("missing P-256 public coordinates")
	}
	var d []byte
	if needPrivate {
		var dOK bool
		d, dOK = key.ParamBytes(cose.KeyLabelEC2D)
		if !dOK || len(d) != 32 {
			return nil, nil, nil, errors.New("missing P-256 private scalar")
		}
	}
	return x, y, d, nil
}

func readCustomSectionName(payload []byte) (string, int, bool) {
	nameLen, off, ok := readVaruint32(payload, 0)
	if !ok || int(nameLen) > len(payload)-off {
		return "", 0, false
	}
	return string(payload[off : off+int(nameLen)]), off + int(nameLen), true
}

func customSectionName(payload []byte) string {
	name, _, ok := readCustomSectionName(payload)
	if !ok {
		return ""
	}
	return name
}

func readVaruint32(buf []byte, off int) (uint32, int, bool) {
	var value uint32
	var shift uint
	for i := 0; i < 5; i++ {
		if off >= len(buf) {
			return 0, 0, false
		}
		b := buf[off]
		off++
		value |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, off, true
		}
		shift += 7
	}
	return 0, 0, false
}

func appendVaruint32(out []byte, value uint32) []byte {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func appendText(out []byte, value string) []byte {
	out = appendTypeLen(out, 3, len(value))
	return append(out, value...)
}

func appendBytes(out []byte, value []byte) []byte {
	out = appendTypeLen(out, 2, len(value))
	return append(out, value...)
}

func appendTypeLen(out []byte, major byte, value int) []byte {
	head := major << 5
	switch {
	case value < 24:
		return append(out, head|byte(value))
	case value <= 0xff:
		return append(out, head|24, byte(value))
	case value <= 0xffff:
		return append(out, head|25, byte(value>>8), byte(value))
	default:
		return append(out, head|26, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
}

func rawP256Signature(r, s *big.Int) []byte {
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func validRole(role string) bool {
	return role == RoleTEEPAgent || role == RoleApp
}
