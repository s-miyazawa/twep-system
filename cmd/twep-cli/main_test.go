// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAppOutputFileAtomicOverwrite(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "output.jpg")
	if err := os.WriteFile(outputPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	appOutput := []byte{
		0xa4,
		0x6e, 's', 'c', 'h', 'e', 'm', 'a', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x01,
		0x66, 's', 't', 'a', 't', 'u', 's', 0x62, 'o', 'k',
		0x65, 'f', 'i', 'l', 'e', 's', 0xa1,
		0x66, 'o', 'u', 't', 'p', 'u', 't', 0x44, 0xff, 0xd8, 0xff, 0xd9,
		0x68, 'm', 'e', 't', 'a', 'd', 'a', 't', 'a', 0xa1,
		0x6b, 'o', 'u', 't', 'p', 'u', 't', '_', 'm', 'i', 'm', 'e',
		0x6a, 'i', 'm', 'a', 'g', 'e', '/', 'j', 'p', 'e', 'g',
	}

	if err := writeAppOutputFile(appOutput, outputPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xff, 0xd8, 0xff, 0xd9}) {
		t.Fatalf("output bytes = %x", got)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".output.jpg.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func TestDiagnoseVerifiedPrintsArtifactsAndMissing(t *testing.T) {
	stateDir := t.TempDir()
	teepDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "verified-state.txt"), []byte("final-verified=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "credential-status.txt"), []byte("trust-anchor-bound=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "platform-status.txt"), []byte("sealed-storage-security=observation-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "agent-identity-status.txt"), []byte("agent-identity-bound=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "evidence-status.txt"), []byte("evidence-affirming=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runDiagnose([]string{"verified", "--state-dir", stateDir}, &out, ""); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"== verified-state ==\nfinal-verified=false\n",
		"== credential-status ==\ntrust-anchor-bound=false\n",
		"== platform-status ==\nsealed-storage-security=observation-only\n",
		"== evidence-status ==\nevidence-affirming=false\n",
		"== agent-identity-status ==\nagent-identity-bound=false\n",
		"== suit-auth-status ==\n(missing)\n",
		"== update-component-status ==\n(missing)\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("diagnose output missing %q in:\n%s", want, got)
		}
	}
}

func TestDiagnoseVerifiedPrintsJSON(t *testing.T) {
	stateDir := t.TempDir()
	teepDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "platform-status.txt"), []byte("platform-backend=linux\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runDiagnose([]string{"verified", "--state-dir", stateDir, "--output-format", "json"}, &out, ""); err != nil {
		t.Fatal(err)
	}
	var got diagnosticReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode json: %v\n%s", err, out.String())
	}
	if got.SchemaVersion != 1 || got.Target != "verified" || got.StateDir != stateDir {
		t.Fatalf("unexpected report metadata: %+v", got)
	}
	if len(got.Artifacts) != 7 {
		t.Fatalf("artifact count = %d, want 7", len(got.Artifacts))
	}
	var platform diagnosticArtifactSnapshot
	var missingVerified bool
	for _, artifact := range got.Artifacts {
		if artifact.Label == "platform-status" {
			platform = artifact
		}
		if artifact.Label == "verified-state" && artifact.Missing {
			missingVerified = true
		}
	}
	if platform.Missing || platform.Text != "platform-backend=linux\n" {
		t.Fatalf("platform artifact = %+v", platform)
	}
	if !missingVerified {
		t.Fatalf("verified-state missing flag not set in %+v", got.Artifacts)
	}
}

func TestDiagnoseVerifiedJSONSummarizesFinalBlockers(t *testing.T) {
	stateDir := t.TempDir()
	teepDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepDir, 0o700); err != nil {
		t.Fatal(err)
	}
	verifiedState := "cose-outer-verified=true\nsession-token-bound=true\nsuit-auth-verified=true\nsequence-fresh=true\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n"
	if err := os.WriteFile(filepath.Join(teepDir, "verified-state.txt"), []byte(verifiedState), 0o600); err != nil {
		t.Fatal(err)
	}
	credentialStatus := "credential-model-ready=true\ntrust-anchor-bound=false\nprotected-credential-store-bound=true\nissuer-allowlist-bound=true\nstore-freshness-bound=true\nrevocation-state-bound=false\nprotected-credential-store-rotation-policy=bound\nprotected-credential-store-revocation-status=matched-unbound\nprotected-credential-store-freshness=bound\n"
	if err := os.WriteFile(filepath.Join(teepDir, "credential-status.txt"), []byte(credentialStatus), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "evidence-status.txt"), []byte("evidence-binding=matched-unbound\nevidence-affirming=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "agent-identity-status.txt"), []byte("agent-identity-binding=matched-unbound\nagent-identity-bound=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	updateComponentStatus := "component-kind=twep-catalog-v1\ncomponent-name=default\npromotion=blocked-final-verified\n"
	if err := os.WriteFile(filepath.Join(teepDir, "update-component-status.txt"), []byte(updateComponentStatus), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runDiagnose([]string{"verified", "--state-dir", stateDir, "--output-format", "json"}, &out, ""); err != nil {
		t.Fatal(err)
	}
	var got diagnosticReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode json: %v\n%s", err, out.String())
	}
	if !got.Summary.FixtureVerified || got.Summary.FinalVerified {
		t.Fatalf("summary verification flags = %+v", got.Summary)
	}
	if got.Summary.MissingStep != "none" || got.Summary.FinalMissingStep != "teep.trust_anchor_unbound" {
		t.Fatalf("summary missing steps = %+v", got.Summary)
	}
	wantBlockers := []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	}
	if !stringSlicesEqual(got.Summary.FinalBlockers, wantBlockers) {
		t.Fatalf("final blockers = %v, want %v", got.Summary.FinalBlockers, wantBlockers)
	}
	wantBound := []string{
		"teep.protected_credential_store_bound",
		"teep.issuer_allowlist_bound",
		"teep.store_freshness_bound",
	}
	if !stringSlicesEqual(got.Summary.Bound, wantBound) {
		t.Fatalf("bound = %v, want %v", got.Summary.Bound, wantBound)
	}
	wantMatchedUnbound := []string{
		"teep.revocation_state_matched_unbound",
		"teep.evidence_matched_unbound",
		"teep.agent_identity_matched_unbound",
	}
	if !stringSlicesEqual(got.Summary.MatchedUnbound, wantMatchedUnbound) {
		t.Fatalf("matched_unbound = %v, want %v", got.Summary.MatchedUnbound, wantMatchedUnbound)
	}
	if got.Summary.SuitAuth != "ok" {
		t.Fatalf("suit_auth = %q, want ok", got.Summary.SuitAuth)
	}
	if got.Summary.UpdateComponent == nil {
		t.Fatalf("update_component missing")
	}
	wantUpdateComponent := verifiedUpdateComponentDiagnostic{
		ComponentKind: "twep-catalog-v1",
		ComponentName: "default",
		Promotion:     "blocked-final-verified",
	}
	if *got.Summary.UpdateComponent != wantUpdateComponent {
		t.Fatalf("update_component = %+v, want %+v", *got.Summary.UpdateComponent, wantUpdateComponent)
	}
}

func TestDiagnoseVerifiedJSONPrioritizesFixtureMissingStep(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "verified-state",
			Text:  "fixture-verified=false\nevidence-affirming=false\nagent-identity-bound=false\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=teep.session_unbound\nfinal-missing-step=teep.session_unbound\n",
		},
		{
			Label: "credential-status",
			Text:  "credential-model-ready=false\nprotected-credential-store-bound=false\nissuer-allowlist-bound=false\nstore-freshness-bound=false\nrevocation-state-bound=false\n",
		},
	})

	wantBlockers := []string{"teep.session_unbound"}
	if !stringSlicesEqual(summary.FinalBlockers, wantBlockers) {
		t.Fatalf("final blockers = %v, want %v", summary.FinalBlockers, wantBlockers)
	}
	if summary.FixtureVerified || summary.FinalVerified {
		t.Fatalf("summary verification flags = %+v, want false/false", summary)
	}
}

func TestDiagnoseVerifiedJSONSummarizesBoundRevocationState(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "credential-status",
			Text:  "credential-model-ready=true\nprotected-credential-store-bound=true\nissuer-allowlist-bound=true\nstore-freshness-bound=false\nrevocation-state-bound=true\nprotected-credential-store-rotation-policy=unverified\nprotected-credential-store-revocation-status=bound\nprotected-credential-store-freshness=unverified\n",
		},
	})

	wantBound := []string{
		"teep.protected_credential_store_bound",
		"teep.issuer_allowlist_bound",
		"teep.revocation_state_bound",
	}
	if !stringSlicesEqual(summary.Bound, wantBound) {
		t.Fatalf("bound = %v, want %v", summary.Bound, wantBound)
	}
	if len(summary.MatchedUnbound) != 0 {
		t.Fatalf("matched_unbound = %v, want empty", summary.MatchedUnbound)
	}
}

func TestDiagnoseVerifiedJSONSummarizesTrustAnchorBlockers(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "verified-state",
			Text:  "fixture-verified=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n",
		},
		{
			Label: "credential-status",
			Text:  "credential-model-ready=true\nprotected-credential-store-bound=true\nissuer-allowlist-bound=false\nstore-freshness-bound=false\nrevocation-state-bound=false\n",
		},
	})

	wantBlockers := []string{
		"teep.issuer_allowlist_unbound",
		"teep.store_freshness_unbound",
		"teep.revocation_state_unbound",
	}
	if !stringSlicesEqual(summary.TrustAnchorBlockers, wantBlockers) {
		t.Fatalf("trust anchor blockers = %v, want %v", summary.TrustAnchorBlockers, wantBlockers)
	}
}

func TestDiagnoseVerifiedJSONDoesNotPromoteTrustAnchorFromCredentialBounds(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "verified-state",
			Text:  "fixture-verified=true\nevidence-affirming=false\nagent-identity-bound=false\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n",
		},
		{
			Label: "credential-status",
			Text:  "credential-model-ready=true\nprotected-credential-store-bound=true\nissuer-allowlist-bound=true\nstore-freshness-bound=true\nrevocation-state-bound=true\nprotected-credential-store-rotation-policy=bound\nprotected-credential-store-revocation-status=bound\nprotected-credential-store-freshness=bound\n",
		},
	})

	wantBound := []string{
		"teep.protected_credential_store_bound",
		"teep.issuer_allowlist_bound",
		"teep.store_freshness_bound",
		"teep.revocation_state_bound",
	}
	if !stringSlicesEqual(summary.Bound, wantBound) {
		t.Fatalf("bound = %v, want %v", summary.Bound, wantBound)
	}
	wantBlockers := []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	}
	if !stringSlicesEqual(summary.FinalBlockers, wantBlockers) {
		t.Fatalf("final blockers = %v, want %v", summary.FinalBlockers, wantBlockers)
	}
}

func TestDiagnoseVerifiedJSONDoesNotPromoteEvidenceFromMatchedUnbound(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "verified-state",
			Text:  "fixture-verified=true\nevidence-affirming=false\nagent-identity-bound=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.evidence_unaffirmed\n",
		},
		{
			Label: "evidence-status",
			Text:  "evidence-binding=matched-unbound\nevidence-affirming=false\n",
		},
	})

	wantMatchedUnbound := []string{"teep.evidence_matched_unbound"}
	if !stringSlicesEqual(summary.MatchedUnbound, wantMatchedUnbound) {
		t.Fatalf("matched_unbound = %v, want %v", summary.MatchedUnbound, wantMatchedUnbound)
	}
	wantBlockers := []string{"teep.trust_anchor_unbound", "teep.evidence_unaffirmed"}
	if !stringSlicesEqual(summary.FinalBlockers, wantBlockers) {
		t.Fatalf("final blockers = %v, want %v", summary.FinalBlockers, wantBlockers)
	}
	wantBound := []string{"teep.agent_identity_bound"}
	if !stringSlicesEqual(summary.Bound, wantBound) {
		t.Fatalf("bound = %v, want %v", summary.Bound, wantBound)
	}
}

func TestDiagnoseVerifiedJSONDoesNotPromoteStaleAttestamEvidenceGeneration(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "verified-state",
			Text:  "fixture-verified=true\nevidence-affirming=false\nagent-identity-bound=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.evidence_unaffirmed\n",
		},
		{
			Label: "evidence-status",
			Text:  "evidence-source=verified-evidence-result\nevidence-result-load=loaded-unbound\nevidence-verifier-result=none\nevidence-decision-source=attestam-signed-update\nevidence-nonce-match=false\nevidence-cnf-key-match=false\nevidence-platform-match=false\nevidence-tam-response-verified=true\nevidence-challenge-response-bound=true\nevidence-acceptance-generation-current=false\nevidence-binding=unbound\nevidence-affirming=false\n",
		},
	})

	if len(summary.MatchedUnbound) != 0 {
		t.Fatalf("matched_unbound = %v, want empty for stale acceptance generation", summary.MatchedUnbound)
	}
	wantBlockers := []string{"teep.trust_anchor_unbound", "teep.evidence_unaffirmed"}
	if !stringSlicesEqual(summary.FinalBlockers, wantBlockers) {
		t.Fatalf("final blockers = %v, want %v", summary.FinalBlockers, wantBlockers)
	}
	wantBound := []string{"teep.agent_identity_bound"}
	if !stringSlicesEqual(summary.Bound, wantBound) {
		t.Fatalf("bound = %v, want %v", summary.Bound, wantBound)
	}
}

func TestDiagnoseVerifiedJSONDoesNotPromoteAgentIdentityFromMatchedUnbound(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "verified-state",
			Text:  "fixture-verified=true\nevidence-affirming=true\nagent-identity-bound=false\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.agent_identity_unbound\n",
		},
		{
			Label: "agent-identity-status",
			Text:  "agent-identity-binding=matched-unbound\nagent-identity-bound=false\n",
		},
	})

	wantMatchedUnbound := []string{"teep.agent_identity_matched_unbound"}
	if !stringSlicesEqual(summary.MatchedUnbound, wantMatchedUnbound) {
		t.Fatalf("matched_unbound = %v, want %v", summary.MatchedUnbound, wantMatchedUnbound)
	}
	wantBlockers := []string{"teep.trust_anchor_unbound", "teep.agent_identity_unbound"}
	if !stringSlicesEqual(summary.FinalBlockers, wantBlockers) {
		t.Fatalf("final blockers = %v, want %v", summary.FinalBlockers, wantBlockers)
	}
	wantBound := []string{"teep.evidence_affirming"}
	if !stringSlicesEqual(summary.Bound, wantBound) {
		t.Fatalf("bound = %v, want %v", summary.Bound, wantBound)
	}
}

func TestDiagnoseVerifiedJSONSummarizesTrustZoneEvidenceAffirming(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "platform-status",
			Text:  "platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n",
		},
		{
			Label: "verified-state",
			Text:  "fixture-verified=true\nevidence-affirming=true\nagent-identity-bound=false\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.agent_identity_unbound\n",
		},
		{
			Label: "credential-status",
			Text:  "credential-model-ready=true\nprotected-credential-store-bound=true\nissuer-allowlist-bound=true\nstore-freshness-bound=true\nrevocation-state-bound=true\nprotected-credential-store-rotation-policy=bound\nprotected-credential-store-revocation-status=bound\nprotected-credential-store-freshness=bound\n",
		},
		{
			Label: "evidence-status",
			Text:  "evidence-source=verified-evidence-result\nevidence-result-load=loaded-unbound\nevidence-verifier-result=none\nevidence-decision-source=attestam-signed-update\nevidence-nonce-match=false\nevidence-cnf-key-match=false\nevidence-platform-match=false\nevidence-tam-response-verified=true\nevidence-challenge-response-bound=true\nevidence-acceptance-generation-current=true\nevidence-binding=bound\nevidence-affirming=true\n",
		},
		{
			Label: "agent-identity-status",
			Text:  "agent-identity-binding=matched-unbound\nagent-identity-bound=false\n",
		},
	})

	if !summary.FixtureVerified || summary.FinalVerified {
		t.Fatalf("summary verification flags = %+v, want fixture true/final false", summary)
	}
	wantBound := []string{
		"teep.protected_credential_store_bound",
		"teep.issuer_allowlist_bound",
		"teep.store_freshness_bound",
		"teep.revocation_state_bound",
		"teep.evidence_affirming",
	}
	if !stringSlicesEqual(summary.Bound, wantBound) {
		t.Fatalf("bound = %v, want %v", summary.Bound, wantBound)
	}
	wantMatchedUnbound := []string{"teep.agent_identity_matched_unbound"}
	if !stringSlicesEqual(summary.MatchedUnbound, wantMatchedUnbound) {
		t.Fatalf("matched_unbound = %v, want %v", summary.MatchedUnbound, wantMatchedUnbound)
	}
	wantBlockers := []string{"teep.trust_anchor_unbound", "teep.agent_identity_unbound"}
	if !stringSlicesEqual(summary.FinalBlockers, wantBlockers) {
		t.Fatalf("final blockers = %v, want %v", summary.FinalBlockers, wantBlockers)
	}
}

func TestDiagnoseVerifiedJSONAllowsTrustZoneREEFSBoundFinalPolicy(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "platform-status",
			Text:  "platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n",
		},
		{
			Label: "verified-state",
			Text:  "fixture-verified=true\nevidence-affirming=true\nagent-identity-bound=true\ntrust-anchor-bound=true\nfinal-verified=true\nmissing-step=none\nfinal-missing-step=none\n",
		},
		{
			Label: "credential-status",
			Text:  "credential-model-ready=true\nprotected-credential-store-bound=true\nissuer-allowlist-bound=true\nstore-freshness-bound=true\nrevocation-state-bound=true\nprotected-credential-store-rotation-policy=bound\nprotected-credential-store-revocation-status=bound\nprotected-credential-store-freshness=bound\n",
		},
		{
			Label: "evidence-status",
			Text:  "evidence-binding=bound\nevidence-affirming=true\n",
		},
		{
			Label: "agent-identity-status",
			Text:  "agent-identity-binding=bound\nagent-identity-bound=true\n",
		},
	})

	if !summary.FixtureVerified || !summary.FinalVerified {
		t.Fatalf("summary verification flags = %+v, want true/true", summary)
	}
	if len(summary.FinalBlockers) != 0 {
		t.Fatalf("final blockers = %v, want empty", summary.FinalBlockers)
	}
	if len(summary.TrustAnchorBlockers) != 0 {
		t.Fatalf("trust anchor blockers = %v, want empty", summary.TrustAnchorBlockers)
	}
	wantBound := []string{
		"teep.protected_credential_store_bound",
		"teep.issuer_allowlist_bound",
		"teep.store_freshness_bound",
		"teep.revocation_state_bound",
		"teep.trust_anchor_bound",
		"teep.evidence_affirming",
		"teep.agent_identity_bound",
	}
	if !stringSlicesEqual(summary.Bound, wantBound) {
		t.Fatalf("bound = %v, want %v", summary.Bound, wantBound)
	}
	if len(summary.MatchedUnbound) != 0 {
		t.Fatalf("matched_unbound = %v, want empty", summary.MatchedUnbound)
	}
}

func TestDiagnoseVerifiedJSONKeepsLinuxObservationOnlyUnbound(t *testing.T) {
	summary := buildVerifiedDiagnosticSummary([]diagnosticArtifactSnapshot{
		{
			Label: "platform-status",
			Text:  "platform-backend=linux\nsealed-storage-security=observation-only\n",
		},
		{
			Label: "verified-state",
			Text:  "fixture-verified=true\nevidence-affirming=false\nagent-identity-bound=false\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n",
		},
		{
			Label: "credential-status",
			Text:  "credential-model-ready=true\nprotected-credential-store-bound=false\nissuer-allowlist-bound=false\nstore-freshness-bound=false\nrevocation-state-bound=false\nprotected-credential-store-rotation-policy=matched-unbound\nprotected-credential-store-revocation-status=matched-unbound\nprotected-credential-store-freshness=matched-unbound\n",
		},
		{
			Label: "evidence-status",
			Text:  "evidence-binding=matched-unbound\nevidence-affirming=false\n",
		},
		{
			Label: "agent-identity-status",
			Text:  "agent-identity-binding=matched-unbound\nagent-identity-bound=false\n",
		},
	})

	wantFinalBlockers := []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	}
	if !stringSlicesEqual(summary.FinalBlockers, wantFinalBlockers) {
		t.Fatalf("final blockers = %v, want %v", summary.FinalBlockers, wantFinalBlockers)
	}
	wantTrustAnchorBlockers := []string{
		"teep.protected_credential_store_unbound",
		"teep.issuer_allowlist_unbound",
		"teep.store_freshness_unbound",
		"teep.revocation_state_unbound",
	}
	if !stringSlicesEqual(summary.TrustAnchorBlockers, wantTrustAnchorBlockers) {
		t.Fatalf("trust anchor blockers = %v, want %v", summary.TrustAnchorBlockers, wantTrustAnchorBlockers)
	}
	wantMatchedUnbound := []string{
		"teep.credential_rotation_matched_unbound",
		"teep.revocation_state_matched_unbound",
		"teep.store_freshness_matched_unbound",
		"teep.evidence_matched_unbound",
		"teep.agent_identity_matched_unbound",
	}
	if !stringSlicesEqual(summary.MatchedUnbound, wantMatchedUnbound) {
		t.Fatalf("matched_unbound = %v, want %v", summary.MatchedUnbound, wantMatchedUnbound)
	}
	if len(summary.Bound) != 0 {
		t.Fatalf("bound = %v, want empty", summary.Bound)
	}
}

func TestDiagnoseVerifiedUsesInheritedOutputFormat(t *testing.T) {
	stateDir := t.TempDir()
	var out bytes.Buffer
	if err := runDiagnose([]string{"verified", "--state-dir", stateDir}, &out, "json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"target": "verified"`) {
		t.Fatalf("diagnose output = %s, want json", out.String())
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
