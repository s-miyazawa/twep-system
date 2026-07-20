// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package wasmsign

import (
	"errors"
	"testing"

	"github.com/s-miyazawa/twep-system/internal/demokeys"
)

var minimalWasm = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

func TestSignVerifyRoundTrip(t *testing.T) {
	signed, err := Sign(minimalWasm, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), RoleApp, []byte(AppKID))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), RoleApp); err != nil {
		t.Fatalf("Verify = %v", err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	signed, err := Sign(minimalWasm, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), RoleApp, []byte(AppKID))
	if err != nil {
		t.Fatal(err)
	}
	signed[7] ^= 1
	if err := Verify(signed, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), RoleApp); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("Verify tampered = %v, want ErrSignatureRejected", err)
	}
}

func TestVerifyRejectsRoleMismatch(t *testing.T) {
	signed, err := Sign(minimalWasm, demokeys.DemoTEEPAgentCodeSigningESP256PrivateCOSEKey(), RoleTEEPAgent, []byte(TEEPAgentKID))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, demokeys.DemoTEEPAgentCodeSigningESP256PrivateCOSEKey(), RoleApp); !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("Verify role mismatch = %v, want ErrRoleMismatch", err)
	}
}

func TestStripResignIsIdempotent(t *testing.T) {
	signed, err := Sign(minimalWasm, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), RoleApp, []byte(AppKID))
	if err != nil {
		t.Fatal(err)
	}
	resigned, err := Sign(signed, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), RoleApp, []byte(AppKID))
	if err != nil {
		t.Fatal(err)
	}
	stripped, err := StripSignature(resigned)
	if err != nil {
		t.Fatal(err)
	}
	if string(stripped) != string(minimalWasm) {
		t.Fatalf("stripped resigned wasm = %x, want %x", stripped, minimalWasm)
	}
}

func TestRejectsNonFinalSignatureSection(t *testing.T) {
	signed, err := Sign(minimalWasm, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), RoleApp, []byte(AppKID))
	if err != nil {
		t.Fatal(err)
	}
	nonFinal := append([]byte(nil), signed...)
	nonFinal = append(nonFinal, 0x00, 0x01, 0x00)
	if err := Verify(nonFinal, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), RoleApp); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify non-final signature = %v, want ErrInvalidSignature", err)
	}
}
