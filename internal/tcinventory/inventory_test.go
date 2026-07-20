// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package tcinventory

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestLoadAndFormat(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, "components"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("Hello, World!")
	payloadSHA256 := sha256.Sum256(payload)
	metadata := Metadata{
		SchemaVersion:   1,
		ComponentIDCBOR: []byte{0x81, 0x49, 'h', 'e', 'l', 'l', 'o', '.', 't', 'x', 't'},
		SequenceNumber:  0,
		PayloadURI:      "#hello.txt",
		PayloadFile:     "components/hello.txt",
		PayloadSHA256:   payloadSHA256[:],
	}
	metadataBytes, err := cbor.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stateDir, "components", "install-metadata.cbor"), metadataBytes)
	writeFile(t, filepath.Join(stateDir, "components", "install-status.txt"), []byte("install=ready\n"))
	writeFile(t, filepath.Join(stateDir, "components", "hello.txt"), payload)

	inv, err := Load(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Size != 13 {
		t.Fatalf("Size = %d, want 13", inv.Size)
	}
	out := Format(inv)
	for _, want := range []string{
		"TC artifacts:",
		"payload_uri: #hello.txt",
		"payload_file: components/hello.txt",
		"payload_hash_status: ok",
		"status: install=ready",
		"size: 13",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Format output missing %q:\n%s", want, out)
		}
	}
	cborBytes, err := MarshalCBOR(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(cborBytes) == 0 || cborBytes[0]>>5 != 5 {
		t.Fatalf("MarshalCBOR = %x, want CBOR map", cborBytes)
	}
}

func TestLoadRejectsEscapingPayloadFile(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, "components"), 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{
		SchemaVersion:   1,
		ComponentIDCBOR: []byte{0x80},
		PayloadURI:      "#hello.txt",
		PayloadFile:     "../hello.txt",
		PayloadSHA256:   bytes32(0xbb),
	}
	metadataBytes, err := cbor.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stateDir, "components", "install-metadata.cbor"), metadataBytes)

	_, err = Load(stateDir)
	if err == nil || !strings.Contains(err.Error(), "escapes state directory") {
		t.Fatalf("Load error = %v, want escapes state directory", err)
	}
}

func TestLoadRejectsMissingMetadata(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, "components"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := Load(stateDir)
	if err == nil || !strings.Contains(err.Error(), "tc.inventory_empty") {
		t.Fatalf("Load error = %v, want tc.inventory_empty", err)
	}
}

func TestLoadRejectsShortPayloadHash(t *testing.T) {
	stateDir := t.TempDir()
	writeMetadata(t, stateDir, Metadata{
		SchemaVersion:   1,
		ComponentIDCBOR: []byte{0x80},
		PayloadURI:      "#hello.txt",
		PayloadFile:     "components/hello.txt",
		PayloadSHA256:   []byte{0xaa, 0xbb},
	})

	_, err := Load(stateDir)
	if err == nil || !strings.Contains(err.Error(), "payload_sha256 length = 2, want 32") {
		t.Fatalf("Load error = %v, want payload_sha256 length error", err)
	}
}

func TestLoadRejectsAbsolutePayloadFile(t *testing.T) {
	stateDir := t.TempDir()
	writeMetadata(t, stateDir, Metadata{
		SchemaVersion:   1,
		ComponentIDCBOR: []byte{0x80},
		PayloadURI:      "#hello.txt",
		PayloadFile:     "/tmp/hello.txt",
		PayloadSHA256:   bytes32(0xcc),
	})

	_, err := Load(stateDir)
	if err == nil || !strings.Contains(err.Error(), "payload_file is invalid") {
		t.Fatalf("Load error = %v, want payload_file is invalid", err)
	}
}

func TestLoadRejectsPayloadHashMismatch(t *testing.T) {
	stateDir := t.TempDir()
	writeMetadata(t, stateDir, Metadata{
		SchemaVersion:   1,
		ComponentIDCBOR: []byte{0x80},
		PayloadURI:      "#hello.txt",
		PayloadFile:     "components/hello.txt",
		PayloadSHA256:   bytes32(0xdd),
	})
	writeFile(t, filepath.Join(stateDir, "components", "install-status.txt"), []byte("install=ready\n"))
	writeFile(t, filepath.Join(stateDir, "components", "hello.txt"), []byte("Hello, World!"))

	_, err := Load(stateDir)
	if err == nil || !strings.Contains(err.Error(), "payload sha256 mismatch") {
		t.Fatalf("Load error = %v, want payload sha256 mismatch", err)
	}
}

func writeMetadata(t *testing.T, stateDir string, metadata Metadata) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(stateDir, "components"), 0o700); err != nil {
		t.Fatal(err)
	}
	metadataBytes, err := cbor.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stateDir, "components", "install-metadata.cbor"), metadataBytes)
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func bytes32(v byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = v
	}
	return out
}
