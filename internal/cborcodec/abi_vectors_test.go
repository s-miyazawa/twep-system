// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cborcodec

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestCanonicalABIVectorsRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/abi/vectors.hex")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, encoded, ok := strings.Cut(line, "|")
		if !ok {
			t.Fatalf("invalid vector line %q", line)
		}
		want, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var value any
		if err := dec.Unmarshal(want, &value); err != nil {
			t.Fatalf("%s decode: %v", name, err)
		}
		got, err := enc.Marshal(value)
		if err != nil {
			t.Fatalf("%s encode: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is not canonical: got %x, want %x", name, got, want)
		}
	}
}

func TestTypedPublicABIVectorsRoundTrip(t *testing.T) {
	vectors := readNamedABIVectors(t)
	req, err := DecodeRequest(vectors["public-request"])
	if err != nil {
		t.Fatal(err)
	}
	gotRequest, err := EncodeRequest(req)
	if err != nil || !bytes.Equal(gotRequest, vectors["public-request"]) {
		t.Fatalf("public request round trip: err=%v got=%x", err, gotRequest)
	}
	resp, err := DecodeResponse(vectors["public-response"])
	if err != nil {
		t.Fatal(err)
	}
	gotResponse, err := EncodeResponse(resp)
	if err != nil || !bytes.Equal(gotResponse, vectors["public-response"]) {
		t.Fatalf("public response round trip: err=%v got=%x", err, gotResponse)
	}
}

func readNamedABIVectors(t *testing.T) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/abi/vectors.hex")
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte)
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, encoded, _ := strings.Cut(line, "|")
		out[name], err = hex.DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	return out
}
