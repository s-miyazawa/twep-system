// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package suitfixture

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func TestGenerateProducesSignedTaggedEnvelope(t *testing.T) {
	artifact, err := Generate(Options{
		Command:             "remotehello",
		WasmFile:            "remotehello.wasm",
		Payload:             []byte("wasm bytes"),
		SequenceNumber:      7,
		InsecureAppMetadata: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	wantComponent := []byte{
		0x82,
		0x4b, 't', 'w', 'e', 'p', '-', 'a', 'p', 'p', '-', 'v', '1',
		0x4b, 'r', 'e', 'm', 'o', 't', 'e', 'h', 'e', 'l', 'l', 'o',
	}
	if !bytes.Equal(artifact.ComponentID, wantComponent) {
		t.Fatalf("component id = %x, want %x", artifact.ComponentID, wantComponent)
	}

	dec, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		t.Fatal(err)
	}
	var tag cbor.Tag
	if err := dec.Unmarshal(artifact.Envelope, &tag); err != nil {
		t.Fatalf("decode envelope tag: %v", err)
	}
	if tag.Number != 107 {
		t.Fatalf("envelope tag = %d, want 107", tag.Number)
	}
	envelope, ok := tag.Content.(map[any]any)
	if !ok {
		t.Fatalf("envelope content = %T, want map", tag.Content)
	}

	authWrapperBytes, ok := envelope[uint64(2)].([]byte)
	if !ok {
		t.Fatalf("auth wrapper = %T, want bytes", envelope[uint64(2)])
	}
	manifestBytes, ok := envelope[uint64(3)].([]byte)
	if !ok {
		t.Fatalf("manifest = %T, want bytes", envelope[uint64(3)])
	}
	if got, ok := envelope["#remotehello.wasm"].([]byte); !ok || !bytes.Equal(got, []byte("wasm bytes")) {
		t.Fatalf("payload = %x/%t, want wasm bytes", got, ok)
	}
	if _, ok := envelope["twep-app-v1-metadata"].([]byte); !ok {
		t.Fatalf("missing insecure app metadata")
	}

	var authWrapper [][]byte
	if err := dec.Unmarshal(authWrapperBytes, &authWrapper); err != nil {
		t.Fatalf("decode auth wrapper: %v", err)
	}
	if len(authWrapper) != 2 {
		t.Fatalf("auth wrapper len = %d, want 2", len(authWrapper))
	}
	var sign1 cose.Sign1Message
	if err := dec.Unmarshal(authWrapper[1], &sign1); err != nil {
		t.Fatalf("decode auth block: %v", err)
	}
	if sign1.Payload != nil {
		t.Fatalf("auth block payload is attached, want detached")
	}
	privateKey, _, err := demoDeveloperKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := cose.NewKeyFromPublic(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	publicKey.Algorithm = cose.AlgorithmESP256
	verifier, err := publicKey.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	sign1.Payload = authWrapper[0]
	if err := sign1.Verify(nil, verifier); err != nil {
		t.Fatalf("verify auth block: %v", err)
	}

	var manifest map[uint64]any
	if err := dec.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest[uint64(2)] != uint64(7) {
		t.Fatalf("sequence = %v, want 7", manifest[uint64(2)])
	}

	kidKey, err := cose.NewKeyFromPublic(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	kidKey.Algorithm = cose.AlgorithmESP256
	kid, err := kidKey.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(artifact.KID, kid) {
		t.Fatalf("kid = %x, want %x", artifact.KID, kid)
	}
}

func TestGenerateDemoTAMVerifiedUpdateProducesSignedUpdate(t *testing.T) {
	token := []byte{0xca, 0xfe}
	artifact, err := GenerateDemoTAMVerifiedUpdate(Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(artifact.Token, token) {
		t.Fatalf("token = %x, want %x", artifact.Token, token)
	}
	if len(artifact.Envelope) == 0 {
		t.Fatal("envelope is empty")
	}
	if len(artifact.UpdatePayload) == 0 {
		t.Fatal("update payload is empty")
	}
	if len(artifact.COSEUpdate) == 0 {
		t.Fatal("COSE update is empty")
	}

	dec, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		t.Fatal(err)
	}
	var update []any
	if err := dec.Unmarshal(artifact.UpdatePayload, &update); err != nil {
		t.Fatalf("decode update payload: %v", err)
	}
	if len(update) != 2 || update[0] != uint64(3) {
		t.Fatalf("update = %#v, want [3, map]", update)
	}

	var sign1 cose.Sign1Message
	if err := dec.Unmarshal(artifact.COSEUpdate, &sign1); err != nil {
		t.Fatalf("decode COSE update: %v", err)
	}
	if !bytes.Equal(sign1.Payload, artifact.UpdatePayload) {
		t.Fatalf("COSE payload mismatch")
	}
}

func TestGenerateCatalogProducesCatalogComponentID(t *testing.T) {
	artifact, err := GenerateCatalog(CatalogOptions{
		CatalogName:    "default",
		Payload:        []byte{0xa0},
		SequenceNumber: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantComponent := []byte{
		0x82,
		0x4f, 't', 'w', 'e', 'p', '-', 'c', 'a', 't', 'a', 'l', 'o', 'g', '-', 'v', '1',
		0x47, 'd', 'e', 'f', 'a', 'u', 'l', 't',
	}
	if !bytes.Equal(artifact.ComponentID, wantComponent) {
		t.Fatalf("component id = %x, want %x", artifact.ComponentID, wantComponent)
	}

	dec, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		t.Fatal(err)
	}
	var tag cbor.Tag
	if err := dec.Unmarshal(artifact.Envelope, &tag); err != nil {
		t.Fatalf("decode envelope tag: %v", err)
	}
	envelope, ok := tag.Content.(map[any]any)
	if !ok {
		t.Fatalf("envelope content = %T, want map", tag.Content)
	}
	if got, ok := envelope["#catalog.cbor"].([]byte); !ok || !bytes.Equal(got, []byte{0xa0}) {
		t.Fatalf("catalog payload = %x/%t, want a0", got, ok)
	}
	if _, ok := envelope["twep-app-v1-metadata"]; ok {
		t.Fatal("catalog fixture must not include app metadata")
	}
}

func TestCanonicalDefaultCatalogPayloadContainsMetadataOnly(t *testing.T) {
	payload, err := CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}

	dec, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		SchemaVersion uint64         `cbor:"schema_version"`
		GeneratedAt   string         `cbor:"generated_at"`
		Source        string         `cbor:"source"`
		Apps          map[string]any `cbor:"apps"`
	}
	if err := dec.Unmarshal(payload, &catalog); err != nil {
		t.Fatalf("decode canonical Catalog: %v", err)
	}
	if catalog.SchemaVersion != 1 || catalog.GeneratedAt == "" || catalog.Source == "" || len(catalog.Apps) != 0 {
		t.Fatalf("Catalog = %#v, want schema version 1 with no app entries", catalog)
	}

	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := enc.Marshal(map[string]any{
		"schema_version": uint64(1),
		"generated_at":   "2026-07-11T00:00:00Z",
		"source":         "local-dev",
		"apps":           map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, reencoded) {
		t.Fatalf("payload = %x, want canonical encoding %x", payload, reencoded)
	}
	if bytes.Contains(payload, []byte("wasm")) {
		t.Fatalf("metadata-only Catalog unexpectedly contains Wasm reference: %x", payload)
	}
}

func TestGenerateDemoTAMVerifiedCatalogUpdateSupportsReplacementSequence(t *testing.T) {
	payload, err := CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}
	token := []byte{0xca, 0x7a, 0x10}

	first, err := GenerateDemoTAMVerifiedCatalogUpdate(CatalogOptions{
		CatalogName:    "default",
		Payload:        payload,
		SequenceNumber: 1,
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := GenerateDemoTAMVerifiedCatalogUpdate(CatalogOptions{
		CatalogName:    "default",
		Payload:        payload,
		SequenceNumber: 2,
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.ComponentID, replacement.ComponentID) {
		t.Fatalf("replacement component id = %x, want %x", replacement.ComponentID, first.ComponentID)
	}
	if bytes.Equal(first.Envelope, replacement.Envelope) {
		t.Fatal("higher-sequence replacement envelope must differ")
	}
	if !bytes.Equal(replacement.Token, token) || len(replacement.COSEUpdate) == 0 {
		t.Fatal("replacement verified Update is incomplete")
	}
}

func TestGenerateDemoTAMVerifiedCatalogUpdateCanProduceNegativeInputs(t *testing.T) {
	canonical, err := CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		catalogName string
		payload     []byte
	}{
		{name: "wrong component name", catalogName: "not-default", payload: canonical},
		{name: "malformed catalog", catalogName: "default", payload: []byte{0xbf, 0xff}},
		{name: "oversized catalog", catalogName: "default", payload: bytes.Repeat([]byte{0}, 65537)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact, err := GenerateDemoTAMVerifiedCatalogUpdate(CatalogOptions{
				CatalogName:    tt.catalogName,
				Payload:        tt.payload,
				SequenceNumber: 1,
			}, []byte{1})
			if err != nil {
				t.Fatal(err)
			}
			if len(artifact.COSEUpdate) == 0 {
				t.Fatal("negative fixture has no signed Update")
			}
			if artifact.PayloadSHA256 != sha256.Sum256(tt.payload) {
				t.Fatal("negative fixture payload digest mismatch")
			}
		})
	}
}
