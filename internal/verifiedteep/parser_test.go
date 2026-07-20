// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package verifiedteep

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/s-miyazawa/twep-system/internal/suitfixture"
)

func TestParseUpdateCOSEExtractsAttesTAMUpdate(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := []byte{0xca, 0xfe}
	coseUpdate := mustCOSESign1(t, mustTEEPUpdate(t, token, artifact.Envelope))

	update, err := ParseUpdateCOSE(coseUpdate)
	if err != nil {
		t.Fatal(err)
	}

	if update.TEEPType != 3 {
		t.Fatalf("TEEPType = %d, want 3", update.TEEPType)
	}
	if update.ManifestCount != 1 {
		t.Fatalf("ManifestCount = %d, want 1", update.ManifestCount)
	}
	if !bytes.Equal(update.UpdateToken, token) {
		t.Fatalf("UpdateToken = %x, want %x", update.UpdateToken, token)
	}
	if !bytes.Equal(update.ComponentIDCBOR, artifact.ComponentID) {
		t.Fatalf("ComponentIDCBOR = %x, want %x", update.ComponentIDCBOR, artifact.ComponentID)
	}
	if update.ComponentKind != ComponentKindApp {
		t.Fatalf("ComponentKind = %q, want %q", update.ComponentKind, ComponentKindApp)
	}
	if update.AppCommand != "remotehello" {
		t.Fatalf("AppCommand = %q, want remotehello", update.AppCommand)
	}
	if update.CatalogName != "" {
		t.Fatalf("CatalogName = %q, want empty", update.CatalogName)
	}
	if !update.IsAppInstallCandidate() {
		t.Fatalf("IsAppInstallCandidate = false, want true")
	}
	if update.IsCatalogUpdateCandidate() {
		t.Fatalf("IsCatalogUpdateCandidate = true, want false for app TC")
	}
	if update.SequenceNumber != 7 {
		t.Fatalf("SequenceNumber = %d, want 7", update.SequenceNumber)
	}
	if update.PayloadURI != "#remotehello.wasm" {
		t.Fatalf("PayloadURI = %q, want #remotehello.wasm", update.PayloadURI)
	}
	if !bytes.Equal(update.Payload, []byte("wasm bytes")) {
		t.Fatalf("Payload = %q, want wasm bytes", update.Payload)
	}
	if update.PayloadSHA256 != artifact.PayloadSHA256 {
		t.Fatalf("PayloadSHA256 = %x, want %x", update.PayloadSHA256, artifact.PayloadSHA256)
	}
	if !bytes.Equal(update.SUITPayloadDigest, artifact.PayloadSHA256[:]) {
		t.Fatalf("SUITPayloadDigest = %x, want %x", update.SUITPayloadDigest, artifact.PayloadSHA256)
	}
	if len(update.SUITAuthDigestRaw) == 0 {
		t.Fatalf("SUITAuthDigestRaw is empty")
	}
	if len(update.SUITAuthBlock) == 0 {
		t.Fatalf("SUITAuthBlock is empty")
	}
	if update.Verified {
		t.Fatalf("Verified = true, want false until COSE/SUIT verification is implemented")
	}
	if !contains(update.VerificationRequired, "COSE_Sign1 signature") {
		t.Fatalf("VerificationRequired = %v, want COSE_Sign1 signature", update.VerificationRequired)
	}
}

func TestParseUpdateCOSEExtractsCatalogTC(t *testing.T) {
	catalogPayload, err := suitfixture.CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := suitfixture.GenerateCatalog(suitfixture.CatalogOptions{
		CatalogName:    "default",
		Payload:        catalogPayload,
		SequenceNumber: 11,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := []byte{0x01, 0x02, 0x03}
	update, err := ParseUpdateCOSE(mustCOSESign1(t, mustTEEPUpdate(t, token, artifact.Envelope)))
	if err != nil {
		t.Fatal(err)
	}

	if update.ComponentKind != ComponentKindCatalog {
		t.Fatalf("ComponentKind = %q, want %q", update.ComponentKind, ComponentKindCatalog)
	}
	if update.CatalogName != "default" {
		t.Fatalf("CatalogName = %q, want default", update.CatalogName)
	}
	if update.AppCommand != "" {
		t.Fatalf("AppCommand = %q, want empty", update.AppCommand)
	}
	if !update.IsCatalogUpdateCandidate() {
		t.Fatalf("IsCatalogUpdateCandidate = false, want true")
	}
	if update.IsAppInstallCandidate() {
		t.Fatalf("IsAppInstallCandidate = true, want false for Catalog TC")
	}
	if update.PayloadURI != "#catalog.cbor" {
		t.Fatalf("PayloadURI = %q, want #catalog.cbor", update.PayloadURI)
	}
	if !bytes.Equal(update.Payload, catalogPayload) {
		t.Fatalf("Payload = %x, want catalog payload", update.Payload)
	}
	if update.SequenceNumber != 11 {
		t.Fatalf("SequenceNumber = %d, want 11", update.SequenceNumber)
	}
	if update.Verified {
		t.Fatalf("Verified = true, want false until trust anchor binding exists")
	}
	if !contains(update.VerificationRequired, "COSE_Sign1 signature") {
		t.Fatalf("VerificationRequired = %v, want COSE_Sign1 signature", update.VerificationRequired)
	}
}

func TestVerifyFixtureCatalogUpdateCOSEStillNotFinalVerified(t *testing.T) {
	token := []byte{0xca, 0x7a}
	payload, err := suitfixture.CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedCatalogUpdate(suitfixture.CatalogOptions{
		CatalogName:    "default",
		Payload:        payload,
		SequenceNumber: 3,
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := suitfixture.DemoTAMVerifier()
	if err != nil {
		t.Fatal(err)
	}
	lastByComponent := map[string]uint64{}

	update, err := VerifyFixtureUpdateCOSE(artifact.COSEUpdate, FixtureVerifyOptions{
		TEEPMessageVerifier:     verifier,
		SUITAuthVerifier:        verifier,
		ExpectedSessionToken:    token,
		LastSequenceByComponent: lastByComponent,
	})
	if err != nil {
		t.Fatal(err)
	}

	if update.ComponentKind != ComponentKindCatalog {
		t.Fatalf("ComponentKind = %q, want %q", update.ComponentKind, ComponentKindCatalog)
	}
	if !update.FixtureVerified {
		t.Fatalf("FixtureVerified = false, want true")
	}
	if update.Verified {
		t.Fatalf("Verified = true, want false until final trust anchor binding")
	}
	if !update.IsCatalogUpdateCandidate() {
		t.Fatalf("IsCatalogUpdateCandidate = false, want true")
	}
	if update.IsAppInstallCandidate() {
		t.Fatalf("IsAppInstallCandidate = true, want false for Catalog TC")
	}
	if got := lastByComponent[string(update.ComponentIDCBOR)]; got != 3 {
		t.Fatalf("last sequence = %d, want 3", got)
	}
}

func TestVerifyFixtureAppUpdateWithMetadataIsNotCatalogUpdateCandidate(t *testing.T) {
	token := []byte{0xa9, 0x9c}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:             "remotehello",
		WasmFile:            "remotehello.wasm",
		Payload:             []byte("wasm bytes"),
		SequenceNumber:      5,
		InsecureAppMetadata: true,
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := suitfixture.DemoTAMVerifier()
	if err != nil {
		t.Fatal(err)
	}

	update, err := VerifyFixtureUpdateCOSE(artifact.COSEUpdate, FixtureVerifyOptions{
		TEEPMessageVerifier:     verifier,
		SUITAuthVerifier:        verifier,
		ExpectedSessionToken:    token,
		LastSequenceByComponent: map[string]uint64{},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !update.FixtureVerified {
		t.Fatalf("FixtureVerified = false, want true")
	}
	if update.Verified {
		t.Fatalf("Verified = true, want false until final trust anchor binding")
	}
	if !update.IsAppInstallCandidate() {
		t.Fatalf("IsAppInstallCandidate = false, want true")
	}
	if update.IsCatalogUpdateCandidate() {
		t.Fatalf("IsCatalogUpdateCandidate = true, want false for app TC")
	}
	if update.ComponentKind != ComponentKindApp {
		t.Fatalf("ComponentKind = %q, want %q", update.ComponentKind, ComponentKindApp)
	}
	if update.AppCommand != "remotehello" {
		t.Fatalf("AppCommand = %q, want remotehello", update.AppCommand)
	}
	if update.CatalogName != "" {
		t.Fatalf("CatalogName = %q, want empty", update.CatalogName)
	}
}

func TestParseComponentIDRejectsUnsupportedShape(t *testing.T) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	for name, componentID := range map[string]any{
		"text elements":     []string{"twep-catalog-v1", "default"},
		"unknown component": [][]byte{[]byte("other-component"), []byte("default")},
		"bad name":          [][]byte{[]byte("twep-catalog-v1"), []byte("../default")},
		"extra element":     [][]byte{[]byte("twep-catalog-v1"), []byte("default"), []byte("extra")},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := enc.Marshal(componentID)
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, err = ParseComponentID(raw)
			if err == nil {
				t.Fatal("ParseComponentID succeeded, want rejection")
			}
		})
	}
}

func TestVerifySUITAuthenticationWrapperAcceptsFixtureDeveloperSignature(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	update, err := ParseUpdateCOSE(mustCOSESign1(t, mustTEEPUpdate(t, nil, artifact.Envelope)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := suitfixture.DemoDeveloperVerifier()
	if err != nil {
		t.Fatal(err)
	}

	if err := update.VerifySUITAuthenticationWrapper(verifier); err != nil {
		t.Fatal(err)
	}

	if contains(update.VerificationRequired, "SUIT manifest authentication wrapper") {
		t.Fatalf("VerificationRequired = %v, want SUIT auth requirement removed", update.VerificationRequired)
	}
	if !contains(update.VerificationRequired, "COSE_Sign1 signature") {
		t.Fatalf("VerificationRequired = %v, want COSE_Sign1 still required", update.VerificationRequired)
	}
	if update.Verified {
		t.Fatalf("Verified = true, want false until remaining TEEP/COSE/freshness checks pass")
	}
}

func TestParseUpdateCOSEVerifiedAcceptsFixtureDeveloperSignature(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	coseUpdate, err := suitfixture.DemoDeveloperSign1(mustTEEPUpdate(t, []byte{0xca}, artifact.Envelope))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := suitfixture.DemoDeveloperVerifier()
	if err != nil {
		t.Fatal(err)
	}

	update, err := ParseUpdateCOSEVerified(coseUpdate, verifier)
	if err != nil {
		t.Fatal(err)
	}

	if contains(update.VerificationRequired, "COSE_Sign1 signature") {
		t.Fatalf("VerificationRequired = %v, want outer COSE requirement removed", update.VerificationRequired)
	}
	if !contains(update.VerificationRequired, "SUIT manifest authentication wrapper") {
		t.Fatalf("VerificationRequired = %v, want SUIT auth still required", update.VerificationRequired)
	}
	if !bytes.Equal(update.UpdateToken, []byte{0xca}) {
		t.Fatalf("UpdateToken = %x, want ca", update.UpdateToken)
	}
	if update.Verified {
		t.Fatalf("Verified = true, want false until remaining TEEP/SUIT/freshness checks pass")
	}
}

func TestVerifyFixtureUpdateCOSEAppliesAllFixtureChecks(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := []byte{0xca, 0xfe}
	coseUpdate, err := suitfixture.DemoDeveloperSign1(mustTEEPUpdate(t, token, artifact.Envelope))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := suitfixture.DemoDeveloperVerifier()
	if err != nil {
		t.Fatal(err)
	}
	lastByComponent := map[string]uint64{}

	update, err := VerifyFixtureUpdateCOSE(coseUpdate, FixtureVerifyOptions{
		TEEPMessageVerifier:     verifier,
		SUITAuthVerifier:        verifier,
		ExpectedSessionToken:    token,
		LastSequenceByComponent: lastByComponent,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !update.FixtureVerified {
		t.Fatalf("FixtureVerified = false, want true")
	}
	if update.Verified {
		t.Fatalf("Verified = true, want false for non-final fixture verification")
	}
	if len(update.VerificationRequired) != 0 {
		t.Fatalf("VerificationRequired = %v, want empty", update.VerificationRequired)
	}
	if got := lastByComponent[string(update.ComponentIDCBOR)]; got != 7 {
		t.Fatalf("last sequence = %d, want 7", got)
	}
}

func TestVerifyFixtureUpdateCOSERejectsTokenMismatchBeforeFreshnessUpdate(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	coseUpdate, err := suitfixture.DemoDeveloperSign1(mustTEEPUpdate(t, []byte{0xca}, artifact.Envelope))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := suitfixture.DemoDeveloperVerifier()
	if err != nil {
		t.Fatal(err)
	}
	lastByComponent := map[string]uint64{}

	_, err = VerifyFixtureUpdateCOSE(coseUpdate, FixtureVerifyOptions{
		TEEPMessageVerifier:     verifier,
		SUITAuthVerifier:        verifier,
		ExpectedSessionToken:    []byte{0xfe},
		LastSequenceByComponent: lastByComponent,
	})
	if err == nil || !strings.Contains(err.Error(), "token mismatch") {
		t.Fatalf("VerifyFixtureUpdateCOSE error = %v, want token mismatch", err)
	}
	if len(lastByComponent) != 0 {
		t.Fatalf("lastByComponent = %v, want unchanged empty map", lastByComponent)
	}
}

func TestVerifyFixtureUpdateCOSERejectsRollbackSequence(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	coseUpdate, err := suitfixture.DemoDeveloperSign1(mustTEEPUpdate(t, []byte{0xca}, artifact.Envelope))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := suitfixture.DemoDeveloperVerifier()
	if err != nil {
		t.Fatal(err)
	}
	update, err := ParseUpdateCOSE(mustCOSESign1(t, mustTEEPUpdate(t, []byte{0xca}, artifact.Envelope)))
	if err != nil {
		t.Fatal(err)
	}
	lastByComponent := map[string]uint64{string(update.ComponentIDCBOR): 7}

	_, err = VerifyFixtureUpdateCOSE(coseUpdate, FixtureVerifyOptions{
		TEEPMessageVerifier:     verifier,
		SUITAuthVerifier:        verifier,
		ExpectedSessionToken:    []byte{0xca},
		LastSequenceByComponent: lastByComponent,
	})
	if err == nil || !strings.Contains(err.Error(), "sequence rollback") {
		t.Fatalf("VerifyFixtureUpdateCOSE error = %v, want sequence rollback", err)
	}
}

func TestVerifySessionTokenAcceptsMatchingUpdateToken(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := []byte{0xca, 0xfe}
	update, err := ParseUpdateCOSE(mustCOSESign1(t, mustTEEPUpdate(t, token, artifact.Envelope)))
	if err != nil {
		t.Fatal(err)
	}

	if err := update.VerifySessionToken(token); err != nil {
		t.Fatal(err)
	}

	if contains(update.VerificationRequired, "TEEP token/session binding") {
		t.Fatalf("VerificationRequired = %v, want token binding requirement removed", update.VerificationRequired)
	}
	if !contains(update.VerificationRequired, "COSE_Sign1 signature") {
		t.Fatalf("VerificationRequired = %v, want COSE_Sign1 still required", update.VerificationRequired)
	}
	if update.Verified {
		t.Fatalf("Verified = true, want false until remaining COSE/SUIT/freshness checks pass")
	}
}

func TestVerifySessionTokenRejectsMismatchedUpdateToken(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	update, err := ParseUpdateCOSE(mustCOSESign1(t, mustTEEPUpdate(t, []byte{0xca}, artifact.Envelope)))
	if err != nil {
		t.Fatal(err)
	}

	err = update.VerifySessionToken([]byte{0xfe})
	if err == nil || !strings.Contains(err.Error(), "token mismatch") {
		t.Fatalf("VerifySessionToken error = %v, want token mismatch", err)
	}
	if !contains(update.VerificationRequired, "TEEP token/session binding") {
		t.Fatalf("VerificationRequired = %v, want token binding still required", update.VerificationRequired)
	}
}

func TestVerifySessionTokenRejectsMissingUpdateToken(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	update, err := ParseUpdateCOSE(mustCOSESign1(t, mustTEEPUpdate(t, nil, artifact.Envelope)))
	if err != nil {
		t.Fatal(err)
	}

	err = update.VerifySessionToken([]byte{0xca})
	if err == nil || !strings.Contains(err.Error(), "token is empty") {
		t.Fatalf("VerifySessionToken error = %v, want missing token rejection", err)
	}
}

func TestVerifySequenceFreshnessAcceptsIncreasingSequence(t *testing.T) {
	first := mustFixtureUpdate(t, "remotehello", 7, []byte{0xca})
	lastByComponent := map[string]uint64{}

	if err := first.VerifySequenceFreshness(lastByComponent); err != nil {
		t.Fatal(err)
	}

	if contains(first.VerificationRequired, "SUIT sequence freshness") {
		t.Fatalf("VerificationRequired = %v, want sequence freshness requirement removed", first.VerificationRequired)
	}
	if got := lastByComponent[string(first.ComponentIDCBOR)]; got != 7 {
		t.Fatalf("last sequence = %d, want 7", got)
	}
	if first.Verified {
		t.Fatalf("Verified = true, want false until remaining COSE/SUIT/token checks pass")
	}

	next := mustFixtureUpdate(t, "remotehello", 8, []byte{0xca})
	if err := next.VerifySequenceFreshness(lastByComponent); err != nil {
		t.Fatal(err)
	}
	if got := lastByComponent[string(next.ComponentIDCBOR)]; got != 8 {
		t.Fatalf("last sequence = %d, want 8", got)
	}
}

func TestVerifySequenceFreshnessRejectsSameSequence(t *testing.T) {
	update := mustFixtureUpdate(t, "remotehello", 7, []byte{0xca})
	lastByComponent := map[string]uint64{string(update.ComponentIDCBOR): 7}

	err := update.VerifySequenceFreshness(lastByComponent)
	if err == nil || !strings.Contains(err.Error(), "sequence rollback") {
		t.Fatalf("VerifySequenceFreshness error = %v, want rollback rejection", err)
	}
	if !contains(update.VerificationRequired, "SUIT sequence freshness") {
		t.Fatalf("VerificationRequired = %v, want sequence freshness still required", update.VerificationRequired)
	}
	if got := lastByComponent[string(update.ComponentIDCBOR)]; got != 7 {
		t.Fatalf("last sequence = %d, want unchanged 7", got)
	}
}

func TestVerifySequenceFreshnessRejectsRollbackSequence(t *testing.T) {
	update := mustFixtureUpdate(t, "remotehello", 6, []byte{0xca})
	lastByComponent := map[string]uint64{string(update.ComponentIDCBOR): 7}

	err := update.VerifySequenceFreshness(lastByComponent)
	if err == nil || !strings.Contains(err.Error(), "sequence rollback") {
		t.Fatalf("VerifySequenceFreshness error = %v, want rollback rejection", err)
	}
}

func TestVerifySequenceFreshnessTracksComponentsIndependently(t *testing.T) {
	remotehello := mustFixtureUpdate(t, "remotehello", 7, []byte{0xca})
	calcadd := mustFixtureUpdate(t, "calcadd", 1, []byte{0xca})
	lastByComponent := map[string]uint64{string(remotehello.ComponentIDCBOR): 7}

	if err := calcadd.VerifySequenceFreshness(lastByComponent); err != nil {
		t.Fatal(err)
	}

	if got := lastByComponent[string(remotehello.ComponentIDCBOR)]; got != 7 {
		t.Fatalf("remotehello last sequence = %d, want 7", got)
	}
	if got := lastByComponent[string(calcadd.ComponentIDCBOR)]; got != 1 {
		t.Fatalf("calcadd last sequence = %d, want 1", got)
	}
}

func TestParseUpdateCOSEVerifiedRejectsTamperedSignature(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	coseUpdate, err := suitfixture.DemoDeveloperSign1(mustTEEPUpdate(t, nil, artifact.Envelope))
	if err != nil {
		t.Fatal(err)
	}
	coseUpdate[len(coseUpdate)-1] ^= 0x01
	verifier, err := suitfixture.DemoDeveloperVerifier()
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseUpdateCOSEVerified(coseUpdate, verifier)
	if err == nil || !strings.Contains(err.Error(), "verify cose sign1") {
		t.Fatalf("ParseUpdateCOSEVerified error = %v, want signature rejection", err)
	}
}

func TestVerifySUITAuthenticationWrapperRejectsTamperedAuthBlock(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	update, err := ParseUpdateCOSE(mustCOSESign1(t, mustTEEPUpdate(t, nil, artifact.Envelope)))
	if err != nil {
		t.Fatal(err)
	}
	update.SUITAuthBlock[len(update.SUITAuthBlock)-1] ^= 0x01
	verifier, err := suitfixture.DemoDeveloperVerifier()
	if err != nil {
		t.Fatal(err)
	}

	err = update.VerifySUITAuthenticationWrapper(verifier)
	if err == nil || !strings.Contains(err.Error(), "verify suit auth cose sign1") {
		t.Fatalf("VerifySUITAuthenticationWrapper error = %v, want signature rejection", err)
	}
}

func TestParseUpdatePayloadRejectsNonUpdateMessage(t *testing.T) {
	enc := canonicalEncMode(t)
	payload, err := enc.Marshal([]any{uint64(4), map[uint64]any{}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseUpdatePayload(payload)
	if err == nil || !strings.Contains(err.Error(), "want Update") {
		t.Fatalf("ParseUpdatePayload error = %v, want non-Update rejection", err)
	}
}

func TestParseUpdatePayloadRejectsMissingManifestList(t *testing.T) {
	enc := canonicalEncMode(t)
	payload, err := enc.Marshal([]any{uint64(3), map[uint64]any{}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseUpdatePayload(payload)
	if err == nil || !strings.Contains(err.Error(), "missing manifest-list") {
		t.Fatalf("ParseUpdatePayload error = %v, want missing manifest-list rejection", err)
	}
}

func TestParseUpdatePayloadRejectsPayloadDigestMismatch(t *testing.T) {
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        "remotehello",
		WasmFile:       "remotehello.wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(artifact.Envelope, []byte("wasm bytes"), []byte("xxxx bytes"), 1)
	if bytes.Equal(tampered, artifact.Envelope) {
		t.Fatal("fixture envelope did not contain payload bytes")
	}

	_, err = ParseUpdatePayload(mustTEEPUpdate(t, nil, tampered))
	if err == nil || !strings.Contains(err.Error(), "payload digest mismatch") {
		t.Fatalf("ParseUpdatePayload error = %v, want payload digest mismatch", err)
	}
}

func mustTEEPUpdate(t *testing.T, token []byte, envelope []byte) []byte {
	t.Helper()
	options := map[uint64]any{
		9: []any{envelope},
	}
	if token != nil {
		options[19] = token
	}
	enc := canonicalEncMode(t)
	payload, err := enc.Marshal([]any{uint64(3), options})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func mustFixtureUpdate(t *testing.T, command string, sequence uint64, token []byte) *Update {
	t.Helper()
	artifact, err := suitfixture.Generate(suitfixture.Options{
		Command:        command,
		WasmFile:       command + ".wasm",
		Payload:        []byte("wasm bytes"),
		SequenceNumber: sequence,
	})
	if err != nil {
		t.Fatal(err)
	}
	update, err := ParseUpdateCOSE(mustCOSESign1(t, mustTEEPUpdate(t, token, artifact.Envelope)))
	if err != nil {
		t.Fatal(err)
	}
	return update
}

func mustCOSESign1(t *testing.T, payload []byte) []byte {
	t.Helper()
	enc := canonicalEncMode(t)
	out, err := enc.Marshal(cbor.Tag{
		Number: 18,
		Content: []any{
			[]byte{},
			map[any]any{},
			payload,
			[]byte{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func canonicalEncMode(t *testing.T) cbor.EncMode {
	t.Helper()
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
