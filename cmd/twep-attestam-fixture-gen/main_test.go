// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/s-miyazawa/twep-system/internal/demokeys"
	"github.com/s-miyazawa/twep-system/internal/suitfixture"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func TestProtectedCredentialStoreFixtureUsesDistinctFixedDemoPublicKeys(t *testing.T) {
	storeCBOR, err := protectedCredentialStoreFixture()
	if err != nil {
		t.Fatal(err)
	}
	var store map[string]any
	if err := cbor.Unmarshal(storeCBOR, &store); err != nil {
		t.Fatal(err)
	}
	tamEntries, ok := store["attestam_message_verification_keys"].([]any)
	if !ok || len(tamEntries) != 1 {
		t.Fatalf("attestam entries = %#v", store["attestam_message_verification_keys"])
	}
	tamEntry, ok := tamEntries[0].(map[any]any)
	if !ok {
		t.Fatalf("attestam entry = %#v", tamEntries[0])
	}
	suitEntries, ok := store["suit_content_verification_keys"].([]any)
	if !ok || len(suitEntries) != 1 {
		t.Fatalf("suit entries = %#v", store["suit_content_verification_keys"])
	}
	suitEntry, ok := suitEntries[0].(map[any]any)
	if !ok {
		t.Fatalf("suit entry = %#v", suitEntries[0])
	}

	var tamKey cose.Key
	if err := cbor.Unmarshal(demokeys.DemoTAMESP256PrivateCOSEKey(), &tamKey); err != nil {
		t.Fatal(err)
	}
	wantX, _ := tamKey.ParamBytes(cose.KeyLabelEC2X)
	wantY, _ := tamKey.ParamBytes(cose.KeyLabelEC2Y)
	wantKID, err := tamKey.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	gotX, xOK := tamEntry["x"].([]byte)
	gotY, yOK := tamEntry["y"].([]byte)
	gotKID, kidOK := tamEntry["kid"].([]byte)
	if !xOK || !yOK || !kidOK || !bytes.Equal(gotX, wantX) || !bytes.Equal(gotY, wantY) || !bytes.Equal(gotKID, wantKID) {
		t.Fatalf("fixture public key does not match demo TAM key")
	}

	block, _ := pem.Decode(demokeys.DemoTCSignerESP256PrivateKeyPEM())
	if block == nil {
		t.Fatal("decode demo developer private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	developerKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("developer key = %T", parsed)
	}
	developerPublicKey, err := cose.NewKeyEC2(cose.AlgorithmESP256, developerKey.X.Bytes(), developerKey.Y.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantDeveloperKID, err := developerPublicKey.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	gotDeveloperX, xOK := suitEntry["x"].([]byte)
	gotDeveloperY, yOK := suitEntry["y"].([]byte)
	gotDeveloperKID, kidOK := suitEntry["kid"].([]byte)
	if !xOK || !yOK || !kidOK ||
		!bytes.Equal(gotDeveloperX, developerKey.X.Bytes()) ||
		!bytes.Equal(gotDeveloperY, developerKey.Y.Bytes()) ||
		!bytes.Equal(gotDeveloperKID, wantDeveloperKID) {
		t.Fatalf("fixture public key does not match demo developer key")
	}
	if bytes.Equal(gotKID, gotDeveloperKID) || bytes.Equal(gotX, gotDeveloperX) || bytes.Equal(gotY, gotDeveloperY) {
		t.Fatal("TAM and SUIT development credentials must be distinct")
	}
}

func TestCatalogFixturePayloadsCoverD047Boundaries(t *testing.T) {
	canonical, err := catalogFixturePayload("default")
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical) == 0 || len(canonical) > suitfixture.MaxCatalogPayloadSize {
		t.Fatalf("canonical Catalog length = %d", len(canonical))
	}
	malformed, err := catalogFixturePayload("malformed")
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := cbor.Unmarshal(malformed, &decoded); err == nil {
		t.Fatal("malformed Catalog decoded successfully")
	}
	oversized, err := catalogFixturePayload("oversized")
	if err != nil {
		t.Fatal(err)
	}
	if len(oversized) != suitfixture.MaxCatalogPayloadSize+1 {
		t.Fatalf("oversized Catalog length = %d", len(oversized))
	}
	if _, err := catalogFixturePayload("unknown"); err == nil {
		t.Fatal("unknown Catalog fixture accepted")
	}
}

func TestGenerateFixtureCreatesVerifiedCatalogWithoutWasm(t *testing.T) {
	payload, err := catalogFixturePayload("default")
	if err != nil {
		t.Fatal(err)
	}
	token := []byte{0xca, 0x7a, 0x10}
	artifact, update, err := generateFixture(fixtureOptions{
		catalog:       true,
		componentName: "default",
		payload:       payload,
		sequence:      1,
		verified:      true,
		token:         token,
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
		t.Fatalf("component ID = %x, want %x", artifact.ComponentID, wantComponent)
	}
	if artifact.PayloadSHA256 != sha256.Sum256(payload) || len(update) == 0 {
		t.Fatal("verified Catalog fixture is incomplete")
	}
	if bytes.Contains(payload, []byte("\x00asm")) {
		t.Fatal("Catalog payload embeds Wasm bytes")
	}
}

func TestGenerateFixtureSupportsCatalogReplacementAndWrongName(t *testing.T) {
	payload, err := catalogFixturePayload("default")
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := generateFixture(fixtureOptions{
		catalog: true, componentName: "default", payload: payload, sequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement, _, err := generateFixture(fixtureOptions{
		catalog: true, componentName: "default", payload: payload, sequence: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongName, _, err := generateFixture(fixtureOptions{
		catalog: true, componentName: "not-default", payload: payload, sequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Envelope, replacement.Envelope) {
		t.Fatal("higher-sequence Catalog envelope did not change")
	}
	if bytes.Equal(first.ComponentID, wrongName.ComponentID) {
		t.Fatal("wrong-name Catalog component ID matches default")
	}
}

func TestGenerateCatalogFixtureCoversD047InboundResponseBoundary(t *testing.T) {
	for _, target := range []int{
		suitfixture.MaxVerifiedTEEPResponseSize,
		suitfixture.MaxVerifiedTEEPResponseSize + 1,
	} {
		artifact, update, err := generateCatalogFixtureWithUpdateSize(fixtureOptions{
			catalog: true, componentName: "default", sequence: 1, verified: true, token: []byte{1},
		}, target)
		if err != nil {
			t.Fatalf("generate %d-byte Update: %v", target, err)
		}
		if artifact == nil || len(update) != target {
			t.Fatalf("Update length = %d, want %d", len(update), target)
		}
	}
}
