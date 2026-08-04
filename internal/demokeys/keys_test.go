// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package demokeys

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func TestDemoCOSEKeysUseExpectedAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		want cose.Algorithm
	}{
		{name: "tam", key: DemoTAMESP256PrivateCOSEKey(), want: cose.AlgorithmESP256},
		{name: "trusted-agent", key: DemoTrustedAgentESP256PrivateCOSEKey(), want: cose.AlgorithmESP256},
		{name: "teep-agent-code-signing", key: DemoTEEPAgentCodeSigningESP256PrivateCOSEKey(), want: cose.AlgorithmESP256},
		{name: "app-code-signing", key: DemoAppCodeSigningESP256PrivateCOSEKey(), want: cose.AlgorithmESP256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key cose.Key
			if err := cbor.Unmarshal(tt.key, &key); err != nil {
				t.Fatalf("decode key: %v", err)
			}
			alg, err := key.AlgorithmOrDefault()
			if err != nil {
				t.Fatalf("algorithm: %v", err)
			}
			if alg != tt.want {
				t.Fatalf("algorithm = %v, want %v", alg, tt.want)
			}
			if _, err := key.Signer(); err != nil {
				t.Fatalf("signer: %v", err)
			}
		})
	}
}

func TestDemoKeyAccessorsReturnCopies(t *testing.T) {
	key := DemoTAMESP256PrivateCOSEKey()
	key[0] = 0x00
	next := DemoTAMESP256PrivateCOSEKey()
	if next[0] == 0x00 {
		t.Fatal("DemoTAMESP256PrivateCOSEKey returned shared mutable storage")
	}
	key = DemoAppCodeSigningESP256PrivateCOSEKey()
	key[0] = 0x00
	next = DemoAppCodeSigningESP256PrivateCOSEKey()
	if next[0] == 0x00 {
		t.Fatal("DemoAppCodeSigningESP256PrivateCOSEKey returned shared mutable storage")
	}
}
