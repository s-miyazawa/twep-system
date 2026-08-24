// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package twepwr

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/s-miyazawa/twep-system/internal/cborcodec"
	"github.com/s-miyazawa/twep-system/internal/demokeys"
	"github.com/s-miyazawa/twep-system/internal/suitfixture"
	"github.com/s-miyazawa/twep-system/internal/teepbroker"
	"github.com/s-miyazawa/twep-system/internal/wasmsign"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func TestABIVersion(t *testing.T) {
	if got := LinkedABIVersion(); got != ABIVersion {
		t.Fatalf("ABI version = %d, want %d", got, ABIVersion)
	}
}

func TestExecuteFreesOwnedBytes(t *testing.T) {
	stateDir := t.TempDir()
	ctx, err := Init(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := ctx.Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Stdout) != "Hello, World!!\n" {
		t.Fatalf("stdout = %q", resp.Stdout)
	}
	if resp.RequestID != "r1" {
		t.Fatalf("request_id = %q, want r1", resp.RequestID)
	}
	for _, path := range []string{
		filepath.Join(stateDir, "catalog", "catalog.cbor"),
		filepath.Join(stateDir, "catalog", "catalog.dev.json"),
		filepath.Join(stateDir, "teep-agent", "teep-agent.wasm"),
		filepath.Join(stateDir, "tmp", "teep-agent-probe"),
		filepath.Join(stateDir, "apps", "helloworld.wasm"),
		filepath.Join(stateDir, "tmp"),
		filepath.Join(stateDir, "locks"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("state path %s: %v", path, err)
		}
	}
	probe, err := os.ReadFile(filepath.Join(stateDir, "tmp", "teep-agent-probe"))
	if err != nil {
		t.Fatal(err)
	}
	if string(probe) != "target_command=helloworld\n" {
		t.Fatalf("probe = %q, want target command", probe)
	}
}

func TestExecuteRejectsConfiguredRequestLimit(t *testing.T) {
	ctx, err := InitWithConfig(Config{
		StateDir:         t.TempDir(),
		ResolverMode:     "mock",
		MaxRequestBytes:  8,
		MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()

	_, err = ctx.ExecuteNormalized(NormalizedRequest{
		RequestID:    "r1",
		Command:      "helloworld",
		AppInputCBOR: []byte{0xa0},
	})
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("ExecuteNormalized error = %v, want StatusError", err)
	}
	if statusErr.Status != "daemon.request" {
		t.Fatalf("StatusError.Status = %q, want daemon.request", statusErr.Status)
	}
}

func TestExecuteRejectsConfiguredResponseLimit(t *testing.T) {
	ctx, err := InitWithConfig(Config{
		StateDir:         t.TempDir(),
		ResolverMode:     "mock",
		MaxRequestBytes:  1024,
		MaxResponseBytes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()

	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := ctx.Execute(req)
	if response != nil {
		t.Fatalf("Execute response length = %d, want nil", len(response))
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "app.runtime" {
		t.Fatalf("StatusError.Status = %q, want app.runtime", statusErr.Status)
	}
}

func TestInitRejectsInvalidResolverMode(t *testing.T) {
	ctx, err := InitWithConfig(Config{
		StateDir:     t.TempDir(),
		ResolverMode: "invalid",
		AttestamURL:  "",
	})
	if err == nil {
		if ctx != nil {
			ctx.Shutdown()
		}
		t.Fatal("InitWithConfig succeeded, want invalid argument")
	}
	if !strings.Contains(err.Error(), "invalid argument") {
		t.Fatalf("InitWithConfig error = %v, want invalid argument", err)
	}
}

func TestInitRejectsVerifiedInsecureDemo(t *testing.T) {
	ctx, err := InitWithConfig(Config{
		StateDir:     t.TempDir(),
		ResolverMode: "attestam-verified",
		AttestamURL:  "http://127.0.0.1:8080/tam",
		InsecureDemo: true,
	})
	if err == nil {
		if ctx != nil {
			ctx.Shutdown()
		}
		t.Fatal("InitWithConfig succeeded, want invalid argument")
	}
	if !strings.Contains(err.Error(), "invalid argument") {
		t.Fatalf("InitWithConfig error = %v, want invalid argument", err)
	}
}

func TestInitRejectsAlternateDemoAgentKeyOutsideDevelopmentAttesTAMModes(t *testing.T) {
	ctx, err := InitWithConfig(Config{
		StateDir:             t.TempDir(),
		ResolverMode:         "mock",
		InsecureDemoAgentKey: "alternate",
	})
	if err == nil {
		if ctx != nil {
			ctx.Shutdown()
		}
		t.Fatal("InitWithConfig succeeded, want alternate key mode rejection")
	}
	if !strings.Contains(err.Error(), "requires an explicitly configured development AttesTAM mode") {
		t.Fatalf("InitWithConfig error = %v, want alternate key mode rejection", err)
	}
}

func TestDevelopmentAttesTAMCallbackPolicy(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   bool
	}{
		{
			name: "verified PoC",
			config: Config{
				ResolverMode: "attestam-verified",
				InsecureDemo: false,
			},
			want: true,
		},
		{
			name: "insecure demo",
			config: Config{
				ResolverMode: "attestam-insecure",
				InsecureDemo: true,
			},
			want: true,
		},
		{
			name: "verified with insecure flag",
			config: Config{
				ResolverMode: "attestam-verified",
				InsecureDemo: true,
			},
		},
		{
			name: "insecure without demo flag",
			config: Config{
				ResolverMode: "attestam-insecure",
				InsecureDemo: false,
			},
		},
		{
			name: "generic app",
			config: Config{
				ResolverMode: "mock",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.allowsDevelopmentAttesTAMCallbacks(); got != tt.want {
				t.Fatalf("allowsDevelopmentAttesTAMCallbacks() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestInitAlternateDemoAgentKeyWritesPublicKey(t *testing.T) {
	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:             stateDir,
		ResolverMode:         "attestam-insecure",
		AttestamURL:          "http://127.0.0.1:8080/tam",
		InsecureDemo:         true,
		InsecureDemoAgentKey: "alternate",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	got, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "dev-agent-public-key.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := teepbroker.PublicCOSEKeyCBOR(teepbroker.AlternateDemoAgentKeyCBOR())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("dev agent public key = %x, want %x", got, want)
	}
}

func TestInitVerifiedAlternateDemoAgentKeyWritesPublicKey(t *testing.T) {
	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:             stateDir,
		ResolverMode:         "attestam-verified",
		AttestamURL:          "http://127.0.0.1:8080/tam",
		InsecureDemo:         false,
		InsecureDemoAgentKey: "alternate",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	got, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "dev-agent-public-key.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := teepbroker.PublicCOSEKeyCBOR(teepbroker.AlternateDemoAgentKeyCBOR())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("dev agent public key = %x, want %x", got, want)
	}
}

func TestAttestamVerifiedRejectsUnverifiedInstallPath(t *testing.T) {
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "remotehello", "remotehello.wasm", make([]byte, 32)))
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified must not use insecure HTTP callback")
		w.Header().Set("Content-Type", "application/teep+cbor")
		_, _ = w.Write([]byte{
			0xd2, 0x84,
			0x43, 0xa1, 0x01, 0x26,
			0xa0,
			0x49, 0x85, 0x01, 0xa1, 0x13, 0x41, 0xaa, 0x80, 0x80, 0x00,
			0x40,
		})
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "teep-agent-probe"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"))
	assertPathMissing(t, filepath.Join(stateDir, "catalog", "catalog.cbor"))
	assertPathMissing(t, filepath.Join(stateDir, "catalog", "catalog.dev.json"))
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(false, false, false, false, false, "teep.cose_outer_unverified", "teep.cose_outer_unverified"),
	)
	assertCredentialStatus(t, stateDir, credentialStatusNoKid())
	assertEvidenceStatus(t, stateDir, evidenceStatusExpectation{})
	assertAgentIdentityStatus(t, stateDir, agentIdentityStatusExpectation{})
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), "remotehello", "twep-app-v1-metadata")
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.dev.json"), "remotehello", "twep-app-v1-metadata")
}

func TestAttestamVerifiedDryRunStateAdvancesWithoutHTTP(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified dry-run must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	dryRunState := cborMap(nil, 6)
	dryRunState = cborText(dryRunState, "cose_outer_verified")
	dryRunState = cborBool(dryRunState, true)
	dryRunState = cborText(dryRunState, "session_token_bound")
	dryRunState = cborBool(dryRunState, true)
	dryRunState = cborText(dryRunState, "suit_auth_verified")
	dryRunState = cborBool(dryRunState, false)
	dryRunState = cborText(dryRunState, "sequence_fresh")
	dryRunState = cborBool(dryRunState, true)
	dryRunState = cborText(dryRunState, "evidence_affirming")
	dryRunState = cborBool(dryRunState, true)
	dryRunState = cborText(dryRunState, "agent_identity_bound")
	dryRunState = cborBool(dryRunState, true)
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-dry-run-state.cbor"), dryRunState, 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, false, true, false, "teep.suit_auth_unverified", "teep.suit_auth_unverified"),
	)
	assertEvidenceStatus(t, stateDir, evidenceStatusExpectation{})
	assertAgentIdentityStatus(t, stateDir, agentIdentityStatusExpectation{})
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "teep-agent-probe"))
}

func TestAttestamVerifiedObservesEvidenceResultWithoutAffirming(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified evidence observation must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-evidence-result.cbor"), evidenceResultCBOR("affirming", true, true, true), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(false, false, false, false, false, "teep.cose_outer_unverified", "teep.cose_outer_unverified"),
	)
	assertEvidenceStatus(t, stateDir, evidenceStatusExpectation{
		load:           "loaded-unbound",
		verifierResult: "affirming",
		nonceMatch:     true,
		cnfKeyMatch:    true,
		platformMatch:  true,
	})
}

func TestAttestamVerifiedObservesProtectedAgentIdentityWithoutBinding(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified agent identity observation must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	writePlatformSealedObject(t, stateDir, "protected-agent-identity.cbor", protectedAgentIdentityCBOR("linux", "", ""))
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertAgentIdentityStatus(t, stateDir, agentIdentityStatusExpectation{
		load:         "loaded-unbound",
		backendMatch: true,
	})
}

func TestAttestamVerifiedReportsMalformedDevTrustAnchors(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified malformed trust anchors must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-trust-anchors.cbor"), []byte("not-cbor"), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(t, stateDir, credentialStatusNoKid().withTrustAnchorLoad("malformed"))
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "teep-agent-probe"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"))
}

func TestAttestamVerifiedReportsUnsupportedDevTrustAnchors(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified unsupported trust anchors must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-trust-anchors.cbor"), []byte{0xa0}, 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(t, stateDir, credentialStatusNoKid().withTrustAnchorLoad("unsupported"))
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "teep-agent-probe"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"))
}

func TestAttestamVerifiedReportsDevTrustAnchorKidEntryMatch(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified dev trust anchor kid match must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	coseInput := mustDemoTAMCOSESign1(t, []byte{0x82, 0x01, 0xa0})
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), coseInput, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-trust-anchors.cbor"), devTrustAnchorsCBOR(demoTAMKeyID(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(
		t,
		stateDir,
		credentialStatusObservedUnbound(demoTAMKeyID(t)).
			withTrustAnchorLoad("loaded-unbound").
			withAttestamBinding("observed-kid-entry-unbound"),
	)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "teep-agent-probe"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"))
}

func TestAttestamVerifiedRejectsDevTrustAnchorPurposeMismatch(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified dev trust anchor purpose mismatch must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	coseInput := mustDemoTAMCOSESign1(t, []byte{0x82, 0x01, 0xa0})
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), coseInput, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-trust-anchors.cbor"), devTrustAnchorsCBORWithPurpose(demoTAMKeyID(t), "suit-content-verification"), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(
		t,
		stateDir,
		credentialStatusObservedUnbound(demoTAMKeyID(t)).withTrustAnchorLoad("unsupported"),
	)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "teep-agent-probe"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"))
}

func TestAttestamVerifiedInputCOSEAdvancesCoseOuterWithoutHTTP(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified COSE input must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	coseInput := mustDemoTAMCOSESign1(t, []byte{0x82, 0x01, 0xa0})
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), coseInput, 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "remotehello",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, false, false, false, false, "teep.session_unbound", "teep.session_unbound"),
	)
	assertCredentialStatus(t, stateDir, credentialStatusObservedUnbound(demoTAMKeyID(t)))
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "teep-agent-probe"))
}

func TestAttestamVerifiedInputUpdateCOSEObservesCandidateWithoutInstall(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified COSE input must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	componentID := twepAppComponentID(command)
	appPayload := []byte("not executed")
	appDigest := sha256.Sum256(appPayload)
	updateManifest := fixtureAppSUITManifest(componentID, "#remotehello.wasm", appPayload, appDigest[:], 2)
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	updatePayload := append([]byte{0x82, 0x03, 0xa2, 0x09, 0x81}, cborBstr(updateManifest)...)
	updatePayload = append(updatePayload, 0x13)
	updatePayload = append(updatePayload, cborBstr(updateToken)...)

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), mustDemoTAMCOSESign1(t, updatePayload), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, false, false, true, false, "teep.session_unbound", "teep.session_unbound"),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-input-payload.cbor"), updatePayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-0.cbor"), updateManifest)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-count.txt"), []byte("manifest-count=1\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-component-id.cbor"), componentID)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"), []byte("sequence-number=2\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-payload-0.bin"), appPayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-payload-sha256.bin"), appDigest[:])
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-payload-hash-status.txt"), []byte("payload-hash=ok\n"))
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedInputCatalogUpdateCOSEObservesWithoutPromotion(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified Catalog TC dry-run must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	updateToken := []byte{0xca, 0x7a, 0x10}
	catalogPayload, err := suitfixture.CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedCatalogUpdate(suitfixture.CatalogOptions{
		CatalogName:    "default",
		Payload:        catalogPayload,
		SequenceNumber: 4,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = cborBytes(devFreshness, artifact.ComponentID)
	devFreshness = cborUint(devFreshness, 3)
	if err := os.WriteFile(filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}

	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}

	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-component-id.cbor"), artifact.ComponentID)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-sequence-number.txt"), []byte("sequence-number=4\n"))
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-0.bin"), catalogPayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-sha256.bin"), artifact.PayloadSHA256[:])
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-hash-status.txt"), []byte("payload-hash=ok\n"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "apps", command+".wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "catalog", "catalog.cbor"))
	assertPathMissing(t, filepath.Join(teepAgentDir, "success.cose"))
}

func TestAttestamVerifiedInputCatalogNegativeFixturesNeverPromoteOnLinux(t *testing.T) {
	canonical, err := suitfixture.CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		catalogName string
		payload     []byte
	}{
		{name: "wrong component name", catalogName: "not-default", payload: canonical},
		{name: "malformed payload", catalogName: "default", payload: []byte{0xa1}},
		{name: "oversized payload", catalogName: "default", payload: bytes.Repeat([]byte{0}, suitfixture.MaxCatalogPayloadSize+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact, err := suitfixture.GenerateDemoTAMVerifiedCatalogUpdate(suitfixture.CatalogOptions{
				CatalogName:    tt.catalogName,
				Payload:        tt.payload,
				SequenceNumber: 2,
			}, []byte{0xca, 0x7a, 0x10})
			if err != nil {
				t.Fatal(err)
			}

			stateDir := t.TempDir()
			ctx, err := InitWithConfig(Config{
				StateDir:     stateDir,
				ResolverMode: "attestam-verified",
				AttestamURL:  "http://127.0.0.1:1/tam",
				InsecureDemo: false,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ctx.Shutdown()
			teepAgentDir := filepath.Join(stateDir, "teep-agent")
			if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), artifact.Token, 0o600); err != nil {
				t.Fatal(err)
			}

			req, err := cborcodec.EncodeRequest(cborcodec.Request{
				SchemaVersion: cborcodec.SchemaVersion,
				RequestID:     "r1",
				Command:       "remotehello",
				Cwd:           "/tmp",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ctx.Execute(req); err == nil {
				t.Fatal("negative verified Catalog fixture executed successfully")
			}
			assertPathMissing(t, filepath.Join(stateDir, "catalog", "catalog.cbor"))
			assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
			assertPathMissing(t, filepath.Join(teepAgentDir, "success.cose"))
		})
	}
}

func TestAttestamVerifiedInputUpdateCOSEBindsExpectedTokenWithoutInstall(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified COSE input must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	componentID := twepAppComponentID(command)
	appPayload := []byte("not executed")
	appDigest := sha256.Sum256(appPayload)
	updateManifest := fixtureAppSUITManifest(componentID, "#remotehello.wasm", appPayload, appDigest[:], 3)
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	updatePayload := append([]byte{0x82, 0x03, 0xa2, 0x09, 0x81}, cborBstr(updateManifest)...)
	updatePayload = append(updatePayload, 0x13)
	updatePayload = append(updatePayload, cborBstr(updateToken)...)

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), mustDemoTAMCOSESign1(t, updatePayload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = cborBytes(devFreshness, componentID)
	devFreshness = cborUint(devFreshness, 3)
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, false, false, false, "teep.suit_auth_unverified", "teep.suit_auth_unverified"),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-input-payload.cbor"), updatePayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"), []byte("sequence-number=3\n"))
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSEAcceptsTAMSignedUpdateAsUnboundObservation(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified COSE input must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	queryResponse := []byte("retained evidence query response")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 4,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-evidence-query-response.cose"), queryResponse, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = cborBytes(devFreshness, artifact.ComponentID)
	devFreshness = cborUint(devFreshness, 3)
	if err := os.WriteFile(filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}

	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(t, filepath.Join(teepAgentDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-sequence-number.txt"), []byte("sequence-number=4\n"))
	assertEvidenceStatus(t, stateDir, evidenceStatusExpectation{
		load: "absent",
	})
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(teepAgentDir, "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSEVerifiesSuitAuthWithoutInstall(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified COSE input must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 4,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = cborBytes(devFreshness, artifact.ComponentID)
	devFreshness = cborUint(devFreshness, 3)
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"), []byte("sequence-number=4\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedDemoTrustAnchorMatchStillDoesNotInstall(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified demo trust anchor fixture must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 5,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-trust-anchors.cbor"), devTrustAnchorsCBOR(demoTAMKeyID(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(
		t,
		stateDir,
		credentialStatusObservedUnbound(demoTAMKeyID(t)).
			withTrustAnchorLoad("loaded-unbound").
			withAttestamBinding("observed-kid-entry-unbound"),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"), []byte("sequence-number=5\n"))
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedProtectedCredentialStoreStillDoesNotInstall(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified protected credential store fixture must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 6,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "protected-credential-store.cbor"), protectedCredentialStoreCBOR(demoTAMKeyID(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(
		t,
		stateDir,
		credentialStatusObservedUnbound(demoTAMKeyID(t)).
			withProtectedCredentialStoreLoad("loaded-unbound").
			withProtectedCredentialStoreCounts(1, 1).
			withProtectedCredentialStoreBinding("observed-kid-entry-unbound"),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"), []byte("sequence-number=6\n"))
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedPrefersPlatformProtectedCredentialStore(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified platform protected credential store fixture must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 8,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "protected-credential-store.cbor"), []byte("not-cbor"), 0o600); err != nil {
		t.Fatal(err)
	}
	writePlatformSealedCredentialStore(t, stateDir, protectedCredentialStoreCBOR(demoTAMKeyID(t)))
	writePlatformSealedObject(t, stateDir, "protected-issuer-allowlist.cbor", platformIssuerAllowlistCBOR())
	writePlatformSealedObject(t, stateDir, "protected-store-freshness.cbor", platformStoreFreshnessCBOR())
	writePlatformSealedObject(t, stateDir, "protected-revocation-state.cbor", platformRevocationStateCBOR())
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(
		t,
		stateDir,
		credentialStatusObservedUnbound(demoTAMKeyID(t)).
			withProtectedCredentialStoreLoad("loaded-unbound").
			withProtectedCredentialStoreCounts(1, 1).
			withProtectedCredentialStoreBinding("observed-kid-entry-unbound").
			withPlatformPolicyLoads("loaded-unbound", "loaded-unbound", "loaded-unbound").
			withStoreFreshnessEpochMatch(true).
			withRevocationStateMatch(true).
			withIssuerAllowlistMatch(true),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertPlatformStatus(t, stateDir)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedPlatformIssuerAllowlistMismatchStaysUnbound(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified issuer allowlist mismatch must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 9,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	writePlatformSealedCredentialStore(t, stateDir, protectedCredentialStoreCBOR(demoTAMKeyID(t)))
	writePlatformSealedObject(t, stateDir, "protected-issuer-allowlist.cbor", platformIssuerAllowlistCBORFor([]byte("other-issuer")))
	writePlatformSealedObject(t, stateDir, "protected-store-freshness.cbor", platformStoreFreshnessCBOR())
	writePlatformSealedObject(t, stateDir, "protected-revocation-state.cbor", platformRevocationStateCBOR())
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(
		t,
		stateDir,
		credentialStatusObservedUnbound(demoTAMKeyID(t)).
			withProtectedCredentialStoreLoad("loaded-unbound").
			withProtectedCredentialStoreCounts(1, 1).
			withProtectedCredentialStoreBinding("observed-kid-entry-unbound").
			withPlatformPolicyLoads("loaded-unbound", "loaded-unbound", "loaded-unbound").
			withStoreFreshnessEpochMatch(true).
			withRevocationStateMatch(true).
			withIssuerAllowlistMatch(false),
	)
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedPlatformStoreFreshnessRollbackStaysUnbound(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified stale store freshness must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 10,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	writePlatformSealedCredentialStore(t, stateDir, protectedCredentialStoreCBOR(demoTAMKeyID(t)))
	writePlatformSealedObject(t, stateDir, "protected-issuer-allowlist.cbor", platformIssuerAllowlistCBOR())
	writePlatformSealedObject(t, stateDir, "protected-store-freshness.cbor", platformStoreFreshnessCBORFor(2))
	writePlatformSealedObject(t, stateDir, "protected-revocation-state.cbor", platformRevocationStateCBOR())
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(
		t,
		stateDir,
		credentialStatusObservedUnbound(demoTAMKeyID(t)).
			withProtectedCredentialStoreLoad("loaded-unbound").
			withProtectedCredentialStoreCounts(1, 1).
			withProtectedCredentialStoreBinding("observed-kid-entry-unbound").
			withPlatformPolicyLoads("loaded-unbound", "loaded-unbound", "loaded-unbound").
			withStoreFreshnessEpochMatch(false).
			withRevocationStateMatch(true).
			withIssuerAllowlistMatch(true),
	)
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedPlatformRevokedCredentialStaysUnbound(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified revoked protected credential must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 11,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	writePlatformSealedCredentialStore(t, stateDir, protectedCredentialStoreCBOR(demoTAMKeyID(t)))
	writePlatformSealedObject(t, stateDir, "protected-issuer-allowlist.cbor", platformIssuerAllowlistCBOR())
	writePlatformSealedObject(t, stateDir, "protected-store-freshness.cbor", platformStoreFreshnessCBOR())
	writePlatformSealedObject(t, stateDir, "protected-revocation-state.cbor", platformRevocationStateCBORFor([]byte("tam-entry")))
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertCredentialStatus(
		t,
		stateDir,
		credentialStatusObservedUnbound(demoTAMKeyID(t)).
			withProtectedCredentialStoreLoad("loaded-unbound").
			withProtectedCredentialStoreCounts(1, 1).
			withProtectedCredentialStoreBinding("observed-kid-entry-unbound").
			withPlatformPolicyLoads("loaded-unbound", "loaded-unbound", "loaded-unbound").
			withStoreFreshnessEpochMatch(true).
			withRevocationStateMatch(false).
			withIssuerAllowlistMatch(true),
	)
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedRejectsInvalidProtectedCredentialStoreWithoutInstall(t *testing.T) {
	cases := []struct {
		name      string
		storeCBOR func(t *testing.T) []byte
		wantLoad  string
	}{
		{
			name: "malformed",
			storeCBOR: func(t *testing.T) []byte {
				t.Helper()
				return []byte("not-cbor")
			},
			wantLoad: "malformed",
		},
		{
			name: "wrong-purpose",
			storeCBOR: func(t *testing.T) []byte {
				t.Helper()
				return protectedCredentialStoreCBORWithTAMKey(demoTAMKeyID(t), "suit-content-verification", "ESP256")
			},
			wantLoad: "unsupported",
		},
		{
			name: "wrong-alg",
			storeCBOR: func(t *testing.T) []byte {
				t.Helper()
				return protectedCredentialStoreCBORWithTAMKey(demoTAMKeyID(t), "attestam-message-verification", "ES256")
			},
			wantLoad: "unsupported",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				t.Errorf("attestam-verified invalid protected credential store must not use HTTP callback")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			command := "remotehello"
			appPayload := []byte("not executed")
			updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
			artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
				Command:        command,
				WasmFile:       "remotehello.wasm",
				Payload:        appPayload,
				SequenceNumber: 7,
			}, updateToken)
			if err != nil {
				t.Fatal(err)
			}

			stateDir := t.TempDir()
			ctx, err := InitWithConfig(Config{
				StateDir:     stateDir,
				ResolverMode: "attestam-verified",
				AttestamURL:  server.URL,
				InsecureDemo: false,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ctx.Shutdown()
			if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "protected-credential-store.cbor"), tc.storeCBOR(t), 0o600); err != nil {
				t.Fatal(err)
			}
			req, err := cborcodec.EncodeRequest(cborcodec.Request{
				SchemaVersion: cborcodec.SchemaVersion,
				RequestID:     "r1",
				Command:       command,
				Cwd:           "/tmp",
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ctx.Execute(req)
			var statusErr *StatusError
			if !errors.As(err, &statusErr) {
				t.Fatalf("Execute error = %v, want StatusError", err)
			}
			if statusErr.Status != "teep.verified_required" {
				t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
			}
			if posts.Load() != 0 {
				t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
			}
			assertCredentialStatus(
				t,
				stateDir,
				credentialStatusObservedUnbound(demoTAMKeyID(t)).
					withProtectedCredentialStoreLoad(tc.wantLoad),
			)
			assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
			assertFileBytes(
				t,
				filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
				verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
			)
			assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
			assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
			assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
			assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
		})
	}
}

func TestAttestamVerifiedInputUpdateCOSERejectsStaleSequenceWithoutInstall(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified stale COSE input must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 4,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = cborBytes(devFreshness, artifact.ComponentID)
	devFreshness = cborUint(devFreshness, 4)
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, false, false, "teep.sequence_unverified", "teep.sequence_unverified"),
	)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"), []byte("sequence-number=4\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedProtectedSequenceFreshnessPreferredOverDevFile(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified protected stale sequence must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	appPayload := []byte("not executed")
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        appPayload,
		SequenceNumber: 4,
	}, updateToken)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), updateToken, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := platformSequenceFreshnessCBOR(artifact.ComponentID, 3)
	if err := os.WriteFile(filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}
	writePlatformSealedObject(t, stateDir, "protected-sequence-freshness.cbor", platformSequenceFreshnessCBOR(artifact.ComponentID, 4))
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(t, filepath.Join(teepAgentDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "verified-state.txt"),
		verifiedStateBytes(true, true, true, false, false, "teep.sequence_unverified", "teep.sequence_unverified"),
	)
	assertFileBytes(t, filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "update-payload-0.bin"))
	assertPathMissing(t, filepath.Join(teepAgentDir, "success.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamVerifiedDryRunFixtureVerifiedStillRejectsInstall(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified fixture dry-run must not use HTTP callback")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-verified",
		AttestamURL:  server.URL,
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	dryRunState := cborMap(nil, 1)
	dryRunState = cborText(dryRunState, "fixture_verified")
	dryRunState = cborBool(dryRunState, true)
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "verified-dry-run-state.cbor"), dryRunState, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = cborBytes(devFreshness, twepAppComponentID(command))
	devFreshness = cborUint(devFreshness, 7)
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.verified_required" {
		t.Fatalf("StatusError.Status = %q, want teep.verified_required", statusErr.Status)
	}
	if posts.Load() != 0 {
		t.Fatalf("fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-state.txt"),
		verifiedStateBytes(true, true, true, true, true, "none", "teep.trust_anchor_unbound"),
	)
	assertCredentialStatus(t, stateDir, credentialStatusNoKid())
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness)
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertPathMissing(t, filepath.Join(stateDir, "tmp", "teep-agent-probe"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamInsecureRequiresInsecureDemo(t *testing.T) {
	ctx, err := InitWithConfig(Config{
		StateDir:     t.TempDir(),
		ResolverMode: "attestam-insecure",
		AttestamURL:  "http://127.0.0.1:8080/tam",
		InsecureDemo: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "teep error") {
		t.Fatalf("Execute error = %v, want teep error", err)
	}
}

func TestAttestamInsecureAllowsEmptyTEEPSession(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Accept"); got != "application/teep+cbor" {
			t.Errorf("Accept = %q, want application/teep+cbor", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/teep+cbor" {
			t.Errorf("Content-Type = %q, want application/teep+cbor", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if len(body) != 0 {
			t.Errorf("body len = %d, want 0", len(body))
		}
		posts.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-insecure",
		AttestamURL:  server.URL,
		InsecureDemo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := ctx.Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Stdout) != "Hello, World!!\n" {
		t.Fatalf("stdout = %q", resp.Stdout)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "tmp", "teep-agent-probe")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "catalog", "catalog.cbor.tmp")); !os.IsNotExist(err) {
		t.Fatalf("catalog.cbor.tmp stat error = %v, want not exist", err)
	}
	if posts.Load() == 0 {
		t.Fatal("AttesTAM fixture server received no POST")
	}
}

func TestAttestamInsecureNonEmptyTEEPResponseIsUnsupported(t *testing.T) {
	teepPayload := []byte{0x85, 0x01, 0xa1, 0x13, 0x41, 0xaa, 0x80, 0x80, 0x00}
	teepResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
		0x49, 0x85, 0x01, 0xa1, 0x13, 0x41, 0xaa, 0x80, 0x80, 0x00,
		0x40,
	}
	updateManifest := fixtureSUITManifest()
	updateToken := []byte{0xde, 0xad, 0xbe, 0xef}
	updatePayload := append([]byte{0x82, 0x03, 0xa2, 0x09, 0x81}, cborBstr(updateManifest)...)
	updatePayload = append(updatePayload, 0x13)
	updatePayload = append(updatePayload, cborBstr(updateToken)...)
	updateResponse := append([]byte{0xd2, 0x84, 0x40, 0xa0}, cborBstr(updatePayload)...)
	updateResponse = append(updateResponse, 0x40)
	var postedBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/teep+cbor")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		postedBodies = append(postedBodies, body)
		if len(postedBodies) == 1 {
			_, _ = w.Write(teepResponse)
			return
		}
		if len(postedBodies) == 2 {
			_, _ = w.Write(updateResponse)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-insecure",
		AttestamURL:  server.URL,
		InsecureDemo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.protocol" {
		t.Fatalf("StatusError.Status = %q, want teep.protocol", statusErr.Status)
	}
	saved, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, teepResponse) {
		t.Fatal("saved TEEP response does not match fixture response")
	}
	payload, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "last-teep-payload.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, teepPayload) {
		t.Fatal("saved TEEP payload does not match fixture payload")
	}
	messageType, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "last-teep-message-type.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(messageType) != "query-request\n" {
		t.Fatalf("saved TEEP message type = %q, want query-request", messageType)
	}
	queryResponse, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "last-query-response.cose"))
	if err != nil {
		t.Fatal(err)
	}
	if len(queryResponse) < 3 || queryResponse[0] != 0xd2 || queryResponse[1] != 0x84 {
		t.Fatalf("saved QueryResponse = %x, want tagged COSE_Sign1", queryResponse)
	}
	if len(postedBodies) != 2 {
		t.Fatalf("posted body count = %d, want 2", len(postedBodies))
	}
	if !bytes.Equal(postedBodies[0], nil) {
		t.Fatalf("first posted body = %x, want empty", postedBodies[0])
	}
	if !bytes.Equal(postedBodies[1], queryResponse) {
		t.Fatal("second posted body does not match saved signed QueryResponse")
	}
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "verified-evidence-query-response.cose"))
	status, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "last-query-response-status.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(status) != "host-status=ok\n" {
		t.Fatalf("saved QueryResponse status = %q, want host-status=ok", status)
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body.cose"), updateResponse)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body-payload.cbor"), updatePayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body-message-type.txt"), []byte("update\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-0.cbor"), updateManifest)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-count.txt"), []byte("manifest-count=1\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-component-id.cbor"), fixtureSUITComponentID())
	for _, path := range []string{
		filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"),
		filepath.Join(stateDir, "teep-agent", "update-manifest-payload-digest.cbor"),
		filepath.Join(stateDir, "teep-agent", "update-manifest-payload-digest-sha256.bin"),
		filepath.Join(stateDir, "teep-agent", "update-payload-0.bin"),
		filepath.Join(stateDir, "teep-agent", "update-payload-uri.txt"),
		filepath.Join(stateDir, "teep-agent", "update-payload-sha256.bin"),
		filepath.Join(stateDir, "teep-agent", "update-payload-hash-status.txt"),
		filepath.Join(stateDir, "tmp", "update-payload-0.bin"),
		filepath.Join(stateDir, "tmp", "update-staging-metadata.cbor"),
		filepath.Join(stateDir, "tmp", "update-staging-status.txt"),
		filepath.Join(stateDir, "teep-agent", "success-payload.cbor"),
		filepath.Join(stateDir, "teep-agent", "success.cose"),
		filepath.Join(stateDir, "teep-agent", "success-status.txt"),
		filepath.Join(stateDir, "teep-agent", "last-session-result.txt"),
		filepath.Join(stateDir, "components", "hello.txt"),
		filepath.Join(stateDir, "components", "install-metadata.cbor"),
		filepath.Join(stateDir, "components", "install-status.txt"),
	} {
		assertPathMissing(t, path)
	}
	assertDemoTCArtifactNotPromoted(t, stateDir)
}

func TestAttestamInsecureChallengeQueryRequestPostsMockEvidenceQueryResponse(t *testing.T) {
	command := "remotehello"
	teepPayload := []byte{
		0x85, 0x01, 0xa1, 0x02, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x80, 0x80, 0x01,
	}
	teepResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
	}
	teepResponse = append(teepResponse, cborBstr(teepPayload)...)
	teepResponse = append(teepResponse, 0x40)
	var postedBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/teep+cbor")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		postedBodies = append(postedBodies, body)
		switch len(postedBodies) {
		case 1:
			_, _ = w.Write(teepResponse)
			return
		case 2:
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Errorf("unexpected POST %d", len(postedBodies))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-insecure",
		AttestamURL:  server.URL,
		InsecureDemo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.protocol" {
		t.Fatalf("StatusError.Status = %q, want teep.protocol", statusErr.Status)
	}
	if len(postedBodies) != 2 {
		t.Fatalf("posted body count = %d, want 2", len(postedBodies))
	}
	if !bytes.Equal(postedBodies[0], nil) {
		t.Fatalf("first posted body = %x, want empty", postedBodies[0])
	}
	if len(postedBodies[1]) == 0 {
		t.Fatal("second posted body is empty, want signed QueryResponse")
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"), teepResponse)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-payload.cbor"), teepPayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-message-type.txt"), []byte("query-request\n"))
	queryResponse, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "last-query-response.cose"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(postedBodies[1], queryResponse) {
		t.Fatal("second posted body does not match saved signed QueryResponse")
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-evidence-query-response.cose"), queryResponse)
	queryPayload := mustCOSESign1Payload(t, queryResponse)
	assertCOSESign1Algorithm(t, queryResponse, int64(cose.Algorithm(-9)))
	attestationPayload := mustTEEPQueryResponseAttestationPayload(t, queryPayload)
	assertCOSESign1Algorithm(t, attestationPayload, int64(cose.AlgorithmES256))
	evidencePayload := mustCOSESign1Payload(t, attestationPayload)
	assertEATNonce(t, evidencePayload, teepPayload[5:21])
	assertEATUEID(t, evidencePayload, teepbroker.DemoAgentEATUEID())
	assertEATCNFKeyAlgorithm(t, evidencePayload, -9)
	assertEATMeasurementDigest(t, evidencePayload, teepbroker.DemoAgentEATMeasurementDigest())
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-status.txt"), []byte("host-status=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-session-result.txt"), []byte("session-result=no-content\n"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "verified-evidence-result.cbor"))
	for _, path := range []string{
		filepath.Join(stateDir, "teep-agent", "last-query-response-body.cose"),
		filepath.Join(stateDir, "teep-agent", "success.cose"),
		filepath.Join(stateDir, "teep-agent", "success-status.txt"),
		filepath.Join(stateDir, "apps", "remotehello.wasm"),
	} {
		assertPathMissing(t, path)
	}
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamInsecureAlternateAgentKeyObservesChallengeAfterToken(t *testing.T) {
	tokenQueryPayload := []byte{0x85, 0x01, 0xa1, 0x13, 0x41, 0xaa, 0x80, 0x80, 0x00}
	tokenQueryResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
		0x49, 0x85, 0x01, 0xa1, 0x13, 0x41, 0xaa, 0x80, 0x80, 0x00,
		0x40,
	}
	challengeQueryPayload := []byte{
		0x85, 0x01, 0xa1, 0x02, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x80, 0x80, 0x01,
	}
	challengeQueryResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
	}
	challengeQueryResponse = append(challengeQueryResponse, cborBstr(challengeQueryPayload)...)
	challengeQueryResponse = append(challengeQueryResponse, 0x40)
	var postedBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/teep+cbor")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		postedBodies = append(postedBodies, body)
		switch len(postedBodies) {
		case 1:
			_, _ = w.Write(tokenQueryResponse)
		case 2:
			_, _ = w.Write(challengeQueryResponse)
		case 3:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected POST %d", len(postedBodies))
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:             stateDir,
		ResolverMode:         "attestam-insecure",
		AttestamURL:          server.URL,
		InsecureDemo:         true,
		InsecureDemoAgentKey: "alternate",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.protocol" {
		t.Fatalf("StatusError.Status = %q, want teep.protocol", statusErr.Status)
	}
	if len(postedBodies) != 3 {
		t.Fatalf("posted body count = %d, want 3", len(postedBodies))
	}
	if !bytes.Equal(postedBodies[0], nil) {
		t.Fatalf("first posted body = %x, want empty", postedBodies[0])
	}
	if len(postedBodies[2]) == 0 {
		t.Fatal("third posted body is empty, want signed attestation QueryResponse")
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "dev-agent-public-key.cbor"), mustPublicCOSEKeyCBOR(t, teepbroker.AlternateDemoAgentKeyCBOR()))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"), tokenQueryResponse)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-payload.cbor"), tokenQueryPayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-message-type.txt"), []byte("query-request\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-status.txt"), []byte("host-status=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body.cose"), challengeQueryResponse)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body-payload.cbor"), challengeQueryPayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body-message-type.txt"), []byte("query-request\n"))
	attestationResponse, err := os.ReadFile(filepath.Join(stateDir, "teep-agent", "last-attestation-query-response.cose"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(postedBodies[2], attestationResponse) {
		t.Fatal("third posted body does not match saved signed attestation QueryResponse")
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-evidence-query-response.cose"), attestationResponse)
	attestationQueryPayload := mustCOSESign1Payload(t, attestationResponse)
	assertCOSESign1Algorithm(t, attestationResponse, int64(cose.Algorithm(-9)))
	attestationPayload := mustTEEPQueryResponseAttestationPayload(t, attestationQueryPayload)
	assertCOSESign1Algorithm(t, attestationPayload, int64(cose.AlgorithmES256))
	evidencePayload := mustCOSESign1Payload(t, attestationPayload)
	assertEATNonce(t, evidencePayload, challengeQueryPayload[5:21])
	assertEATUEID(t, evidencePayload, teepbroker.DemoAgentEATUEID())
	assertEATCNFKeyAlgorithm(t, evidencePayload, -9)
	assertEATMeasurementDigest(t, evidencePayload, teepbroker.DemoAgentEATMeasurementDigest())
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-attestation-query-response-status.txt"), []byte("host-status=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-session-result.txt"), []byte("session-result=no-content\n"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "verified-evidence-result.cbor"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "last-attestation-query-response-body.cose"))
}

func TestAttestamInsecureChallengeBoundSignedUpdateWritesLinuxObservation(t *testing.T) {
	command := "helloworld"
	appPayload := readFileBytes(t, filepath.Join("..", "..", "build", "helloworld.wasm"))
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	tokenQueryResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
		0x49, 0x85, 0x01, 0xa1, 0x13, 0x41, 0xaa, 0x80, 0x80, 0x00,
		0x40,
	}
	challengeQueryPayload := []byte{
		0x85, 0x01, 0xa1, 0x02, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x80, 0x80, 0x01,
	}
	challengeQueryResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
	}
	challengeQueryResponse = append(challengeQueryResponse, cborBstr(challengeQueryPayload)...)
	challengeQueryResponse = append(challengeQueryResponse, 0x40)
	var postedBodies [][]byte
	var artifact *suitfixture.VerifiedUpdateArtifact
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/teep+cbor")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		postedBodies = append(postedBodies, body)
		switch len(postedBodies) {
		case 1:
			_, _ = w.Write(tokenQueryResponse)
		case 2:
			_, _ = w.Write(challengeQueryResponse)
		case 3:
			artifact, err = suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
				Command:        command,
				WasmFile:       "helloworld.wasm",
				Payload:        appPayload,
				SequenceNumber: 4,
			}, updateToken)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(artifact.COSEUpdate)
		case 4:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected POST %d", len(postedBodies))
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:             stateDir,
		ResolverMode:         "attestam-insecure",
		AttestamURL:          server.URL,
		InsecureDemo:         true,
		InsecureDemoAgentKey: "alternate",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := ctx.Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Stdout) != "Hello, World!!\n" {
		t.Fatalf("stdout = %q, want helloworld output", resp.Stdout)
	}
	if len(postedBodies) != 4 {
		t.Fatalf("posted body count = %d, want 4", len(postedBodies))
	}
	if artifact == nil {
		t.Fatal("fixture did not generate bound Update artifact")
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "verified-evidence-query-response.cose"), postedBodies[2])
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "verified-input.cose"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "verified-input-payload.cbor"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "suit-auth-status.txt"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"), []byte("sequence-number=4\n"))
	assertAttestamSignedUpdateEvidenceResult(
		t,
		filepath.Join(stateDir, "teep-agent", "verified-evidence-result.cbor"),
	)
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "verified-state.txt"))
	assertFileBytes(t, filepath.Join(stateDir, "apps", "helloworld.wasm"), appPayload)
}

func TestAttestamInsecureChallengeAffirmingUpdateInstallsApp(t *testing.T) {
	command := "helloworld"
	componentID := twepAppComponentID(command)
	appPayload := readFileBytes(t, filepath.Join("..", "..", "build", "helloworld.wasm"))
	appDigest := sha256.Sum256(appPayload)
	updateManifest := fixtureAppSUITManifest(componentID, "#helloworld.wasm", appPayload, appDigest[:], 1)
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	updatePayload := append([]byte{0x82, 0x03, 0xa2, 0x09, 0x81}, cborBstr(updateManifest)...)
	updatePayload = append(updatePayload, 0x13)
	updatePayload = append(updatePayload, cborBstr(updateToken)...)
	updateResponse := append([]byte{0xd2, 0x84, 0x40, 0xa0}, cborBstr(updatePayload)...)
	updateResponse = append(updateResponse, 0x40)
	tokenQueryResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
		0x49, 0x85, 0x01, 0xa1, 0x13, 0x41, 0xaa, 0x80, 0x80, 0x00,
		0x40,
	}
	challengeQueryPayload := []byte{
		0x85, 0x01, 0xa1, 0x02, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x80, 0x80, 0x01,
	}
	challengeQueryResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
	}
	challengeQueryResponse = append(challengeQueryResponse, cborBstr(challengeQueryPayload)...)
	challengeQueryResponse = append(challengeQueryResponse, 0x40)
	var postedBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/teep+cbor")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		postedBodies = append(postedBodies, body)
		switch len(postedBodies) {
		case 1:
			_, _ = w.Write(tokenQueryResponse)
		case 2:
			_, _ = w.Write(challengeQueryResponse)
		case 3:
			_, _ = w.Write(updateResponse)
		case 4:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected POST %d", len(postedBodies))
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:             stateDir,
		ResolverMode:         "attestam-insecure",
		AttestamURL:          server.URL,
		InsecureDemo:         true,
		InsecureDemoAgentKey: "alternate",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := ctx.Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Stdout) != "Hello, World!!\n" {
		t.Fatalf("stdout = %q, want helloworld output", resp.Stdout)
	}
	if len(postedBodies) != 4 {
		t.Fatalf("posted body count = %d, want 4", len(postedBodies))
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-attestation-query-response-body.cose"), updateResponse)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-attestation-query-response-status.txt"), []byte("host-status=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-component-id.cbor"), componentID)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-payload-hash-status.txt"), []byte("payload-hash=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "success-status.txt"), []byte("host-status=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-session-result.txt"), []byte("session-result=no-content\n"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "verified-evidence-result.cbor"))
	assertFileBytes(t, filepath.Join(stateDir, "apps", "helloworld.wasm"), appPayload)
}

func TestAttestamInsecureRejectsRollbackSequenceFromDevState(t *testing.T) {
	command := "remotehello"
	componentID := twepAppComponentID(command)
	appPayload := []byte("not executed")
	appDigest := sha256.Sum256(appPayload)
	updateManifest := fixtureAppSUITManifest(componentID, "#remotehello.wasm", appPayload, appDigest[:], 1)
	updateToken := []byte{0xca, 0xfe, 0xba, 0xbe}
	updatePayload := append([]byte{0x82, 0x03, 0xa2, 0x09, 0x81}, cborBstr(updateManifest)...)
	updatePayload = append(updatePayload, 0x13)
	updatePayload = append(updatePayload, cborBstr(updateToken)...)
	updateResponse := append([]byte{0xd2, 0x84, 0x40, 0xa0}, cborBstr(updatePayload)...)
	updateResponse = append(updateResponse, 0x40)
	teepResponse := []byte{
		0xd2, 0x84,
		0x43, 0xa1, 0x01, 0x26,
		0xa0,
		0x49, 0x85, 0x01, 0xa1, 0x13, 0x41, 0xaa, 0x80, 0x80, 0x00,
		0x40,
	}
	var postedBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/teep+cbor")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		postedBodies = append(postedBodies, body)
		if len(postedBodies) == 1 {
			_, _ = w.Write(teepResponse)
			return
		}
		if len(postedBodies) == 2 {
			_, _ = w.Write(updateResponse)
			return
		}
		t.Errorf("unexpected POST %d", len(postedBodies))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	ctx, err := InitWithConfig(Config{
		StateDir:     stateDir,
		ResolverMode: "attestam-insecure",
		AttestamURL:  server.URL,
		InsecureDemo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	if err := os.MkdirAll(filepath.Join(stateDir, "teep-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = cborBytes(devFreshness, componentID)
	devFreshness = cborUint(devFreshness, 1)
	if err := os.WriteFile(filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.protocol" {
		t.Fatalf("StatusError.Status = %q, want teep.protocol", statusErr.Status)
	}
	if len(postedBodies) != 2 {
		t.Fatalf("posted body count = %d, want 2", len(postedBodies))
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor"), devFreshness)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-sequence-number.txt"), []byte("sequence-number=1\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-payload-hash-status.txt"), []byte("payload-hash=ok\n"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success.cose"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "success-status.txt"))
	assertPathMissing(t, filepath.Join(stateDir, "teep-agent", "last-session-result.txt"))
	assertPathMissing(t, filepath.Join(stateDir, "apps", "remotehello.wasm"))
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, "remotehello.wasm")
}

func TestAttestamInsecureNetworkErrorMapsStatus(t *testing.T) {
	ctx, err := InitWithConfig(Config{
		StateDir:     t.TempDir(),
		ResolverMode: "attestam-insecure",
		AttestamURL:  "http://127.0.0.1:1/tam",
		InsecureDemo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctx.Execute(req)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "teep.network" {
		t.Fatalf("StatusError.Status = %q, want teep.network", statusErr.Status)
	}
}

func TestExecuteCalcAdd(t *testing.T) {
	stateDir := t.TempDir()
	ctx, err := Init(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "calcadd",
		Argv:          []string{"3", "4", "5"},
		Inferred:      cborcodec.InferArgv([]string{"3", "4", "5"}),
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := ctx.Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Stdout) != "12\n" {
		t.Fatalf("stdout = %q", resp.Stdout)
	}
	probe, err := os.ReadFile(filepath.Join(stateDir, "tmp", "teep-agent-probe"))
	if err != nil {
		t.Fatal(err)
	}
	if string(probe) != "target_command=calcadd\n" {
		t.Fatalf("probe = %q, want target command", probe)
	}
}

func TestExecuteCalcAddWithoutIntsErrors(t *testing.T) {
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "calcadd",
		Argv:          []string{"abc"},
		Inferred:      cborcodec.InferArgv([]string{"abc"}),
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := ctx.Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "error" || resp.Error == nil || resp.Error.Code != "app.invalid_argument" {
		t.Fatalf("response = %+v, want app.invalid_argument", resp)
	}
	details, ok := resp.Error.Details.(map[string]any)
	if !ok || details["return_code"] != uint64(2) || details["command"] != "calcadd" || details["wasm_file"] != "calcadd.wasm" {
		t.Fatalf("error details = %#v", resp.Error.Details)
	}
}

func TestExecuteReportsCatalogErrorForMissingCatalogApp(t *testing.T) {
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "helloworld", "missing.wasm", make([]byte, 32)))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "wasm load error") {
		t.Fatalf("Execute error = %v, want wasm load error", err)
	}
}

func TestExecuteReportsWasmABIMismatch(t *testing.T) {
	wasmFile, abi2SHA := writeSignedBuildWasmForTest(t, "abi2", abi2Wasm)
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "helloworld", wasmFile, abi2SHA[:]))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "wasm abi error") {
		t.Fatalf("Execute error = %v, want wasm abi error", err)
	}
}

func TestExecuteUnknownCommandReturnsCatalogError(t *testing.T) {
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "unknown",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "catalog error") {
		t.Fatalf("Execute error = %v, want catalog error", err)
	}
}

func TestExecuteRejectsHashMismatch(t *testing.T) {
	stateDir := t.TempDir()
	ctx, err := Init(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err != nil {
		t.Fatal(err)
	}
	appPath := filepath.Join(stateDir, "apps", "helloworld.wasm")
	f, err := os.OpenFile(appPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "security error") {
		t.Fatalf("Execute error = %v, want security error", err)
	}
}

func TestExecuteRejectsUnsignedGeneralAppWithMatchingCatalogHash(t *testing.T) {
	wasmFile := writeBuildWasmForTest(t, "unsigned-app", abi2Wasm)
	wasmSHA := sha256.Sum256(abi2Wasm)
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "unsigned", wasmFile, wasmSHA[:]))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req := mustRequestCBOR(t, "unsigned")
	var statusErr *StatusError
	if _, err := ctx.Execute(req); !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "app.signature_unverified" {
		t.Fatalf("StatusError.Status = %q, want app.signature_unverified", statusErr.Status)
	}
}

func TestExecuteRejectsGeneralAppSignedWithTEEPAgentKey(t *testing.T) {
	signed, err := wasmsign.Sign(abi2Wasm, demokeys.DemoTEEPAgentCodeSigningESP256PrivateCOSEKey(), wasmsign.RoleTEEPAgent, []byte(wasmsign.TEEPAgentKID))
	if err != nil {
		t.Fatal(err)
	}
	wasmFile, wasmSHA := writeBuildWasmBytesForTest(t, "teep-signed-app", signed)
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "wrongrole", wasmFile, wasmSHA[:]))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req := mustRequestCBOR(t, "wrongrole")
	var statusErr *StatusError
	if _, err := ctx.Execute(req); !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "app.signature_unverified" {
		t.Fatalf("StatusError.Status = %q, want app.signature_unverified", statusErr.Status)
	}
}

func TestExecuteRejectsTamperedGeneralAppSignatureWithMatchingCatalogHash(t *testing.T) {
	signed, err := wasmsign.Sign(abi2Wasm, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), wasmsign.RoleApp, []byte(wasmsign.AppKID))
	if err != nil {
		t.Fatal(err)
	}
	signed[len(signed)-1] ^= 1
	wasmFile, wasmSHA := writeBuildWasmBytesForTest(t, "tampered-app", signed)
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "tampered", wasmFile, wasmSHA[:]))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req := mustRequestCBOR(t, "tampered")
	var statusErr *StatusError
	if _, err := ctx.Execute(req); !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "app.signature_unverified" {
		t.Fatalf("StatusError.Status = %q, want app.signature_unverified", statusErr.Status)
	}
}

func TestExecuteRejectsUnsignedTEEPAgentBeforeCapability(t *testing.T) {
	stateDir := t.TempDir()
	ctx, err := Init(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	agentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agentDir, "teep-agent.wasm"), abi2Wasm, 0o600); err != nil {
		t.Fatal(err)
	}
	req := mustRequestCBOR(t, "helloworld")
	var statusErr *StatusError
	if _, err := ctx.Execute(req); !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "app.signature_unverified" {
		t.Fatalf("StatusError.Status = %q, want app.signature_unverified", statusErr.Status)
	}
}

func TestExecuteRejectsAppKeySignedTEEPAgentBeforeCapability(t *testing.T) {
	stateDir := t.TempDir()
	ctx, err := Init(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	signed, err := wasmsign.Sign(abi2Wasm, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), wasmsign.RoleApp, []byte(wasmsign.AppKID))
	if err != nil {
		t.Fatal(err)
	}
	agentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agentDir, "teep-agent.wasm"), signed, 0o600); err != nil {
		t.Fatal(err)
	}
	req := mustRequestCBOR(t, "helloworld")
	var statusErr *StatusError
	if _, err := ctx.Execute(req); !errors.As(err, &statusErr) {
		t.Fatalf("Execute error = %v, want StatusError", err)
	}
	if statusErr.Status != "app.signature_unverified" {
		t.Fatalf("StatusError.Status = %q, want app.signature_unverified", statusErr.Status)
	}
}

func TestExecuteRejectsCatalogPathTraversal(t *testing.T) {
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "helloworld", "../evil.wasm", make([]byte, 32)))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "catalog error") {
		t.Fatalf("Execute error = %v, want catalog error", err)
	}
}

func TestGeneralAppCannotUseOldEnvHostcall(t *testing.T) {
	wasmFile, envImportSHA := writeSignedBuildWasmForTest(t, "env-import", envImportWasm)
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "envhost", wasmFile, envImportSHA[:]))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "envhost",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "wasm runtime error") {
		t.Fatalf("Execute error = %v, want unresolved env hostcall runtime error", err)
	}
}

func TestGeneralAppCannotUseTeepHostcallWithoutCapability(t *testing.T) {
	wasmFile, teepImportSHA := writeSignedBuildWasmForTest(t, "teep-import", teepImportWasm)
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBOR(t, "teephost", wasmFile, teepImportSHA[:]))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "teephost",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := ctx.Execute(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "error" || resp.Error == nil || resp.Error.Code != "app.invalid_argument" {
		t.Fatalf("response = %+v, want denied hostcall surfaced as app.invalid_argument", resp)
	}
	details, ok := resp.Error.Details.(map[string]any)
	if !ok || details["return_code"] != uint64(2) || details["command"] != "teephost" || details["wasm_file"] != wasmFile {
		t.Fatalf("error details = %#v", resp.Error.Details)
	}
}

func TestExecuteAppliesCatalogMaxOutputLimit(t *testing.T) {
	wasmBytes, err := os.ReadFile(filepath.Clean("../../build/helloworld.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBORWithLimits(t, "helloworld", "helloworld.wasm", sha256.Sum256(wasmBytes), map[string]uint64{
		"stack_bytes":      65536,
		"heap_bytes":       1048576,
		"max_output_bytes": 8,
	}))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "wasm runtime error") {
		t.Fatalf("Execute error = %v, want wasm runtime error", err)
	}
}

func TestExecuteAppliesCatalogTimeoutLimit(t *testing.T) {
	wasmFile, loopSHA := writeSignedBuildWasmForTest(t, "loop", loopWasm)
	t.Setenv("TWEP_CATALOG_CBOR", writeCatalogCBORWithLimits(t, "loop", wasmFile, loopSHA, map[string]uint64{
		"stack_bytes":      65536,
		"heap_bytes":       1048576,
		"timeout_ms":       1,
		"max_output_bytes": 1024,
	}))
	ctx, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Shutdown()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       "loop",
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Execute(req); err == nil || !strings.Contains(err.Error(), "wasm runtime error") {
		t.Fatalf("Execute error = %v, want wasm runtime error", err)
	}
}

func writeCatalogCBORWithLimits(t *testing.T, command, wasmFile string, sha [32]byte, limits map[string]uint64) string {
	t.Helper()
	return writeCatalogCBORBytes(t, command, wasmFile, sha[:], limits)
}

func writeCatalogCBOR(t *testing.T, command, wasmFile string, sha []byte) string {
	t.Helper()
	return writeCatalogCBORBytes(t, command, wasmFile, sha, nil)
}

func writeCatalogCBORBytes(t *testing.T, command, wasmFile string, sha []byte, limits map[string]uint64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "catalog.cbor")
	var b []byte
	b = cborMap(b, 3)
	b = cborText(b, "apps")
	b = cborMap(b, 1)
	b = cborText(b, command)
	entryPairs := 7
	if len(limits) != 0 {
		entryPairs++
	}
	b = cborMap(b, entryPairs)
	b = cborText(b, "abi")
	b = cborText(b, "twep-app-v1")
	b = cborText(b, "sha256")
	b = cborBytes(b, sha)
	b = cborText(b, "version")
	b = cborText(b, "0.1.0")
	b = cborText(b, "wasm_file")
	b = cborText(b, wasmFile)
	if len(limits) != 0 {
		b = cborText(b, "resource_limits")
		b = cborMap(b, len(limits))
		for k, v := range limits {
			b = cborText(b, k)
			b = cborUint(b, v)
		}
	}
	b = cborText(b, "component_id")
	b = cborText(b, "twep.example."+command)
	b = cborText(b, "source")
	b = cborText(b, "test")
	b = cborText(b, "schema_version")
	b = append(b, 0x01)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeBuildWasmForTest(t *testing.T, prefix string, wasm []byte) string {
	t.Helper()
	sum := sha256.Sum256(wasm)
	wasmFile := fmt.Sprintf("%s-%x.wasm", prefix, sum[:4])
	buildPath := filepath.Clean(filepath.Join("..", "..", "build", wasmFile))
	if err := os.MkdirAll(filepath.Dir(buildPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(buildPath, wasm, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(buildPath)
	})
	return wasmFile
}

func writeSignedBuildWasmForTest(t *testing.T, prefix string, wasm []byte) (string, [32]byte) {
	t.Helper()
	signed, err := wasmsign.Sign(wasm, demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), wasmsign.RoleApp, []byte(wasmsign.AppKID))
	if err != nil {
		t.Fatalf("sign test wasm: %v", err)
	}
	sum := sha256.Sum256(signed)
	wasmFile := fmt.Sprintf("%s-%x.wasm", prefix, sum[:4])
	buildPath := filepath.Clean(filepath.Join("..", "..", "build", wasmFile))
	if err := os.MkdirAll(filepath.Dir(buildPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(buildPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(buildPath)
	})
	return wasmFile, sum
}

func writeBuildWasmBytesForTest(t *testing.T, prefix string, wasm []byte) (string, [32]byte) {
	t.Helper()
	sum := sha256.Sum256(wasm)
	wasmFile := fmt.Sprintf("%s-%x.wasm", prefix, sum[:4])
	buildPath := filepath.Clean(filepath.Join("..", "..", "build", wasmFile))
	if err := os.MkdirAll(filepath.Dir(buildPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(buildPath, wasm, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(buildPath)
	})
	return wasmFile, sum
}

func mustRequestCBOR(t *testing.T, command string) []byte {
	t.Helper()
	req, err := cborcodec.EncodeRequest(cborcodec.Request{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     "r1",
		Command:       command,
		Cwd:           "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func mustDemoTAMCOSESign1(t *testing.T, payload []byte) []byte {
	t.Helper()
	signed, err := suitfixture.DemoTAMSign1(payload)
	if err != nil {
		t.Fatalf("sign demo TAM COSE_Sign1: %v", err)
	}
	return signed
}

func demoTAMKeyID(t *testing.T) []byte {
	t.Helper()
	var key cose.Key
	if err := cbor.Unmarshal(demokeys.DemoTAMESP256PrivateCOSEKey(), &key); err != nil {
		t.Fatalf("decode demo TAM key: %v", err)
	}
	kid, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("derive demo TAM kid: %v", err)
	}
	return kid
}

func mustPublicCOSEKeyCBOR(t *testing.T, privateKeyCBOR []byte) []byte {
	t.Helper()
	publicKey, err := teepbroker.PublicCOSEKeyCBOR(privateKeyCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func cborMap(out []byte, n int) []byte {
	return append(out, 0xa0|byte(n))
}

func cborArray(out []byte, n int) []byte {
	return append(out, 0x80|byte(n))
}

func cborText(out []byte, s string) []byte {
	if len(s) < 24 {
		out = append(out, 0x60|byte(len(s)))
	} else {
		out = append(out, 0x78, byte(len(s)))
	}
	return append(out, s...)
}

func cborBytes(out []byte, b []byte) []byte {
	if len(b) < 24 {
		out = append(out, 0x40|byte(len(b)))
	} else {
		out = append(out, 0x58, byte(len(b)))
	}
	return append(out, b...)
}

func cborUint(out []byte, n uint64) []byte {
	switch {
	case n < 24:
		return append(out, byte(n))
	case n <= 0xff:
		return append(out, 0x18, byte(n))
	case n <= 0xffff:
		return append(out, 0x19, byte(n>>8), byte(n))
	default:
		return append(out, 0x1a, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func cborBool(out []byte, value bool) []byte {
	if value {
		return append(out, 0xf5)
	}
	return append(out, 0xf4)
}

func devTrustAnchorsCBOR(attestamKID []byte) []byte {
	return devTrustAnchorsCBORWithPurpose(attestamKID, "attestam-message-verification")
}

func devTrustAnchorsCBORWithPurpose(attestamKID []byte, purpose string) []byte {
	coordinate := bytes.Repeat([]byte{0x07}, 32)
	var out []byte
	out = cborMap(out, 2)
	out = cborText(out, "attestam_message_verification_keys")
	out = cborArray(out, 1)
	out = cborMap(out, 6)
	out = cborText(out, "kid")
	out = cborBytes(out, attestamKID)
	out = cborText(out, "purpose")
	out = cborText(out, purpose)
	out = cborText(out, "alg")
	out = cborText(out, "ESP256")
	out = cborText(out, "crv")
	out = cborText(out, "P-256")
	out = cborText(out, "x")
	out = cborBytes(out, coordinate)
	out = cborText(out, "y")
	out = cborBytes(out, coordinate)
	out = cborText(out, "suit_content_verification_keys")
	out = cborArray(out, 0)
	return out
}

func protectedCredentialStoreCBOR(attestamKID []byte) []byte {
	return protectedCredentialStoreCBORWithTAMKey(attestamKID, "attestam-message-verification", "ESP256")
}

func protectedCredentialStoreCBORWithTAMKey(attestamKID []byte, attestamPurpose, attestamAlg string) []byte {
	var out []byte
	out = cborMap(out, 4)
	out = cborText(out, "schema_version")
	out = cborUint(out, 1)
	out = cborText(out, "store_epoch")
	out = cborUint(out, 1)
	out = cborText(out, "attestam_message_verification_keys")
	out = cborArray(out, 1)
	out = protectedPublicKeyCredential(out, "tam-entry", attestamKID, attestamPurpose, attestamAlg)
	out = cborText(out, "suit_content_verification_keys")
	out = cborArray(out, 1)
	out = protectedPublicKeyCredential(out, "suit-entry", []byte("suit-key"), "suit-content-verification", "ESP256")
	return out
}

func writePlatformSealedCredentialStore(t *testing.T, stateDir string, contents []byte) {
	t.Helper()
	writePlatformSealedObject(t, stateDir, "protected-credential-store.cbor", contents)
}

func writePlatformSealedObject(t *testing.T, stateDir string, objectName string, contents []byte) {
	t.Helper()
	sealedDir := filepath.Join(stateDir, "platform", "linux", "sealed")
	if err := os.MkdirAll(sealedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sealedDir, objectName), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func platformIssuerAllowlistCBOR() []byte {
	return platformIssuerAllowlistCBORFor([]byte("issuer"))
}

func platformIssuerAllowlistCBORFor(issuerID []byte) []byte {
	var out []byte
	out = cborMap(out, 2)
	out = cborText(out, "schema_version")
	out = cborUint(out, 1)
	out = cborText(out, "issuer_ids")
	out = cborArray(out, 1)
	out = cborBytes(out, issuerID)
	return out
}

func platformStoreFreshnessCBOR() []byte {
	return platformStoreFreshnessCBORFor(1)
}

func platformStoreFreshnessCBORFor(maxEpoch uint64) []byte {
	var out []byte
	out = cborMap(out, 2)
	out = cborText(out, "schema_version")
	out = cborUint(out, 1)
	out = cborText(out, "max_store_epoch")
	out = cborUint(out, maxEpoch)
	return out
}

func platformRevocationStateCBOR() []byte {
	return platformRevocationStateCBORFor([]byte("revoked-entry"))
}

func platformRevocationStateCBORFor(entryID []byte) []byte {
	var out []byte
	out = cborMap(out, 2)
	out = cborText(out, "schema_version")
	out = cborUint(out, 1)
	out = cborText(out, "revoked_entry_ids")
	out = cborArray(out, 1)
	out = cborBytes(out, entryID)
	return out
}

func evidenceResultCBOR(verifierResult string, nonceMatch bool, cnfKeyMatch bool, platformMatch bool) []byte {
	var out []byte
	out = cborMap(out, 5)
	out = cborText(out, "schema_version")
	out = cborUint(out, 1)
	out = cborText(out, "verifier_result")
	out = cborText(out, verifierResult)
	out = cborText(out, "nonce_match")
	out = cborBool(out, nonceMatch)
	out = cborText(out, "cnf_key_match")
	out = cborBool(out, cnfKeyMatch)
	out = cborText(out, "platform_match")
	out = cborBool(out, platformMatch)
	return out
}

func protectedAgentIdentityCBOR(platformBackend string, runtimeLocation string, teepAgentLocation string) []byte {
	pairs := 2
	if runtimeLocation != "" {
		pairs++
	}
	if teepAgentLocation != "" {
		pairs++
	}
	var out []byte
	out = cborMap(out, pairs)
	out = cborText(out, "schema_version")
	out = cborUint(out, 1)
	out = cborText(out, "platform_backend")
	out = cborText(out, platformBackend)
	if runtimeLocation != "" {
		out = cborText(out, "runtime_location")
		out = cborText(out, runtimeLocation)
	}
	if teepAgentLocation != "" {
		out = cborText(out, "teep_agent_location")
		out = cborText(out, teepAgentLocation)
	}
	return out
}

func platformSequenceFreshnessCBOR(componentID []byte, lastSequence uint64) []byte {
	var out []byte
	out = cborMap(out, 1)
	out = cborBytes(out, componentID)
	out = cborUint(out, lastSequence)
	return out
}

func protectedPublicKeyCredential(out []byte, entryID string, kid []byte, purpose, alg string) []byte {
	x := bytes.Repeat([]byte{0x08}, 32)
	y := bytes.Repeat([]byte{0x08}, 32)
	if purpose == "attestam-message-verification" && alg == "ESP256" {
		x, y = demoTAMPublicCoordinates()
	}
	out = cborMap(out, 11)
	out = protectedCommonCredentialFields(out, entryID, kid, purpose, alg)
	out = cborText(out, "x")
	out = cborBytes(out, x)
	out = cborText(out, "y")
	out = cborBytes(out, y)
	return out
}

func demoTAMPublicCoordinates() ([]byte, []byte) {
	var key cose.Key
	if err := cbor.Unmarshal(demokeys.DemoTAMESP256PrivateCOSEKey(), &key); err != nil {
		panic(fmt.Sprintf("decode demo TAM key: %v", err))
	}
	x, xOK := key.ParamBytes(cose.KeyLabelEC2X)
	y, yOK := key.ParamBytes(cose.KeyLabelEC2Y)
	if !xOK || !yOK || len(x) != 32 || len(y) != 32 {
		panic("demo TAM key does not contain P-256 public coordinates")
	}
	return x, y
}

func protectedCommonCredentialFields(out []byte, entryID string, kid []byte, purpose, alg string) []byte {
	out = cborText(out, "entry_id")
	out = cborBytes(out, []byte(entryID))
	out = cborText(out, "issuer_id")
	out = cborBytes(out, []byte("issuer"))
	out = cborText(out, "kid")
	out = cborBytes(out, kid)
	out = cborText(out, "purpose")
	out = cborText(out, purpose)
	out = cborText(out, "alg")
	out = cborText(out, alg)
	out = cborText(out, "crv")
	out = cborText(out, "P-256")
	out = cborText(out, "not_before")
	out = cborUint(out, 1)
	out = cborText(out, "not_after")
	out = cborUint(out, 2)
	out = cborText(out, "provisioning_epoch")
	out = cborUint(out, 1)
	return out
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got := readFileBytes(t, path)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func verifiedStateBytes(coseOuterVerified, sessionTokenBound, suitAuthVerified, sequenceFresh, fixtureVerified bool, missingStep, finalMissingStep string) []byte {
	return []byte(fmt.Sprintf(
		"cose-outer-verified=%t\nsession-token-bound=%t\nsuit-auth-verified=%t\nsequence-fresh=%t\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=%t\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=%s\nfinal-missing-step=%s\n",
		coseOuterVerified,
		sessionTokenBound,
		suitAuthVerified,
		sequenceFresh,
		fixtureVerified,
		missingStep,
		finalMissingStep,
	))
}

type credentialStatusExpectation struct {
	observedAttestamKID                  []byte
	attestamBinding                      string
	trustAnchorLoad                      string
	protectedCredentialStoreLoad         string
	protectedCredentialStoreAttestamKeys int
	protectedCredentialStoreSUITKeys     int
	protectedCredentialStoreBinding      string
	platformIssuerAllowlistLoad          string
	platformStoreFreshnessLoad           string
	platformRevocationStateLoad          string
	protectedStorageBinding              string
	issuerAllowlistMatch                 bool
	storeFreshnessEpochMatch             bool
	revocationStateMatch                 bool
}

func credentialStatusNoKid() credentialStatusExpectation {
	return credentialStatusExpectation{
		attestamBinding:                 "no-kid",
		trustAnchorLoad:                 "absent",
		protectedCredentialStoreLoad:    "absent",
		protectedCredentialStoreBinding: "no-kid",
		platformIssuerAllowlistLoad:     "absent",
		platformStoreFreshnessLoad:      "absent",
		platformRevocationStateLoad:     "absent",
		protectedStorageBinding:         "observation-only",
	}
}

func credentialStatusObservedUnbound(kid []byte) credentialStatusExpectation {
	return credentialStatusExpectation{
		observedAttestamKID:             kid,
		attestamBinding:                 "observed-kid-unbound",
		trustAnchorLoad:                 "absent",
		protectedCredentialStoreLoad:    "absent",
		protectedCredentialStoreBinding: "observed-kid-unbound",
		platformIssuerAllowlistLoad:     "absent",
		platformStoreFreshnessLoad:      "absent",
		platformRevocationStateLoad:     "absent",
		protectedStorageBinding:         "observation-only",
	}
}

func (want credentialStatusExpectation) withTrustAnchorLoad(status string) credentialStatusExpectation {
	want.trustAnchorLoad = status
	return want
}

func (want credentialStatusExpectation) withAttestamBinding(binding string) credentialStatusExpectation {
	want.attestamBinding = binding
	return want
}

func (want credentialStatusExpectation) withProtectedCredentialStoreLoad(status string) credentialStatusExpectation {
	want.protectedCredentialStoreLoad = status
	return want
}

func (want credentialStatusExpectation) withProtectedCredentialStoreCounts(attestamKeys, suitKeys int) credentialStatusExpectation {
	want.protectedCredentialStoreAttestamKeys = attestamKeys
	want.protectedCredentialStoreSUITKeys = suitKeys
	return want
}

func (want credentialStatusExpectation) withProtectedCredentialStoreBinding(binding string) credentialStatusExpectation {
	want.protectedCredentialStoreBinding = binding
	return want
}

func (want credentialStatusExpectation) withPlatformPolicyLoads(issuerAllowlist, storeFreshness, revocationState string) credentialStatusExpectation {
	want.platformIssuerAllowlistLoad = issuerAllowlist
	want.platformStoreFreshnessLoad = storeFreshness
	want.platformRevocationStateLoad = revocationState
	return want
}

func (want credentialStatusExpectation) withIssuerAllowlistMatch(match bool) credentialStatusExpectation {
	want.issuerAllowlistMatch = match
	return want
}

func (want credentialStatusExpectation) withStoreFreshnessEpochMatch(match bool) credentialStatusExpectation {
	want.storeFreshnessEpochMatch = match
	return want
}

func (want credentialStatusExpectation) withRevocationStateMatch(match bool) credentialStatusExpectation {
	want.revocationStateMatch = match
	return want
}

func (want credentialStatusExpectation) withProtectedStorageBinding(binding string) credentialStatusExpectation {
	want.protectedStorageBinding = binding
	return want
}

func assertCredentialStatus(t *testing.T, stateDir string, want credentialStatusExpectation) {
	t.Helper()
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "credential-status.txt"), want.bytes())
}

func assertPlatformStatus(t *testing.T, stateDir string) {
	t.Helper()
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "platform-status.txt"), []byte("platform-backend=linux\nsealed-storage-security=observation-only\nsealed-storage-rollback-protected=false\nprotected-storage-supported=true\nfile-io=true\nrandom=true\ntime=true\n"))
}

type evidenceStatusExpectation struct {
	load                        string
	verifierResult              string
	decisionSource              string
	nonceMatch                  bool
	cnfKeyMatch                 bool
	platformMatch               bool
	tamVerified                 bool
	transcriptBound             bool
	acceptanceGenerationCurrent bool
}

func assertEvidenceStatus(t *testing.T, stateDir string, want evidenceStatusExpectation) {
	t.Helper()
	if want.load == "" {
		want.load = "absent"
	}
	if want.verifierResult == "" {
		want.verifierResult = "none"
	}
	if want.decisionSource == "" {
		if want.load == "loaded-unbound" {
			want.decisionSource = "legacy-direct-result"
		} else {
			want.decisionSource = "none"
		}
	}
	source := "none"
	if want.load == "loaded-unbound" {
		source = "verified-evidence-result"
	}
	binding := "unbound"
	legacyMatchReady := want.decisionSource == "legacy-direct-result" || want.decisionSource == "direct-verifier"
	if want.load == "loaded-unbound" && want.verifierResult == "affirming" && want.nonceMatch && want.cnfKeyMatch && want.platformMatch && legacyMatchReady {
		binding = "matched-unbound"
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "evidence-status.txt"), []byte(fmt.Sprintf("evidence-model-ready=true\nevidence-source=%s\nevidence-result-load=%s\nevidence-verifier-result=%s\nevidence-decision-source=%s\nevidence-nonce-match=%t\nevidence-cnf-key-match=%t\nevidence-platform-match=%t\nevidence-tam-response-verified=%t\nevidence-challenge-response-bound=%t\nevidence-acceptance-generation-current=%t\nevidence-binding=%s\nevidence-affirming=false\n",
		source,
		want.load,
		want.verifierResult,
		want.decisionSource,
		want.nonceMatch,
		want.cnfKeyMatch,
		want.platformMatch,
		want.tamVerified,
		want.transcriptBound,
		want.acceptanceGenerationCurrent,
		binding,
	)))
}

func assertAttestamSignedUpdateEvidenceResult(t *testing.T, path string) {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := cbor.Unmarshal(bytes, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"schema_version":           uint64(2),
		"decision_source":          "attestam-signed-update",
		"tam_response_verified":    true,
		"challenge_response_bound": true,
		"acceptance_generation":    uint64(0),
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("%s = %#v, want %#v", key, got[key], wantValue)
		}
	}
	for _, legacyKey := range []string{"verifier_result", "nonce_match", "cnf_key_match", "platform_match"} {
		if _, ok := got[legacyKey]; ok {
			t.Fatalf("%s present in AttesTAM acceptance result", legacyKey)
		}
	}
}

type agentIdentityStatusExpectation struct {
	load           string
	backendMatch   bool
	runtimeMatch   bool
	teepAgentMatch bool
	measurement    string
}

func assertAgentIdentityStatus(t *testing.T, stateDir string, want agentIdentityStatusExpectation) {
	t.Helper()
	if want.load == "" {
		want.load = "absent"
	}
	if want.measurement == "" {
		want.measurement = "absent"
	}
	binding := "unbound"
	if want.load == "loaded-unbound" && want.backendMatch {
		binding = "matched-unbound"
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "agent-identity-status.txt"), []byte(fmt.Sprintf("agent-identity-model-ready=true\nplatform-backend=linux\nruntime-location=unknown\nteep-agent-location=unknown\nsealed-storage-rollback-protected=false\nagent-identity-source=platform-status-linux\nagent-identity-observed=true\nprotected-agent-identity-load=%s\nprotected-agent-identity-backend-match=%t\nprotected-agent-identity-runtime-match=%t\nprotected-agent-identity-teep-agent-match=%t\nprotected-agent-identity-measurement=%s\nagent-identity-binding=%s\nagent-identity-bound=false\n",
		want.load,
		want.backendMatch,
		want.runtimeMatch,
		want.teepAgentMatch,
		want.measurement,
		binding,
	)))
}

func (want credentialStatusExpectation) bytes() []byte {
	kidText := "none"
	if want.observedAttestamKID != nil {
		kidText = hex.EncodeToString(want.observedAttestamKID)
	}
	teeProtected := want.protectedStorageBinding == "tee-protected"
	teeReeFS := want.protectedStorageBinding == "tee-ree-fs-secure-storage"
	storageCanBindCredentialAndIssuer := teeProtected || teeReeFS
	protectedStoreBound := storageCanBindCredentialAndIssuer &&
		want.protectedCredentialStoreLoad == "loaded-unbound" &&
		want.protectedCredentialStoreAttestamKeys > 0 &&
		want.protectedCredentialStoreSUITKeys > 0 &&
		(want.protectedCredentialStoreBinding == "observed-kid-entry-unbound" ||
			want.protectedCredentialStoreBinding == "observed-kid-entry-protected-storage-bound")
	issuerBound := storageCanBindCredentialAndIssuer &&
		want.platformIssuerAllowlistLoad == "loaded-unbound" &&
		want.issuerAllowlistMatch
	storeFreshnessBound := (teeProtected || teeReeFS) &&
		want.platformStoreFreshnessLoad == "loaded-unbound" &&
		want.storeFreshnessEpochMatch
	revocationBound := (teeProtected || teeReeFS) &&
		want.platformRevocationStateLoad == "loaded-unbound" &&
		want.revocationStateMatch
	issuerBinding := "unverified"
	if issuerBound {
		issuerBinding = "bound"
	}
	rotationPolicy := "unverified"
	if storeFreshnessBound {
		rotationPolicy = "bound"
	} else if want.storeFreshnessEpochMatch {
		rotationPolicy = "matched-unbound"
	}
	revocationStatus := "unverified"
	if revocationBound {
		revocationStatus = "bound"
	} else if want.revocationStateMatch {
		revocationStatus = "matched-unbound"
	}
	freshness := "unverified"
	if storeFreshnessBound {
		freshness = "bound"
	} else if want.storeFreshnessEpochMatch {
		freshness = "matched-unbound"
	}
	trustAnchorBound := protectedStoreBound && issuerBound && storeFreshnessBound && revocationBound
	return []byte(fmt.Sprintf("credential-model-ready=true\nverified-teep-required-credentials=2\nattestam-message-verification-key=unbound\nsuit-content-verification-key=unbound\nattestam-message-verification-key-binding=%s\nobserved-attestam-kid=%s\ntrust-anchor-load=%s\nprotected-credential-store-load=%s\nprotected-credential-store-attestam-message-verification-keys=%d\nprotected-credential-store-suit-content-verification-keys=%d\nprotected-credential-store-attestam-key-binding=%s\nprotected-credential-store-issuer-binding=%s\nprotected-credential-store-issuer-allowlist-match=%t\nprotected-credential-store-rotation-policy=%s\nprotected-credential-store-revocation-status=%s\nprotected-revocation-state-match=%t\nprotected-credential-store-freshness=%s\nprotected-store-freshness-epoch-match=%t\nplatform-issuer-allowlist-load=%s\nplatform-store-freshness-load=%s\nplatform-revocation-state-load=%s\nprotected-storage-binding=%s\nprotected-credential-store-bound=%t\nissuer-allowlist-bound=%t\nstore-freshness-bound=%t\nrevocation-state-bound=%t\ntrust-anchor-bound=%t\n",
		want.attestamBinding,
		kidText,
		want.trustAnchorLoad,
		want.protectedCredentialStoreLoad,
		want.protectedCredentialStoreAttestamKeys,
		want.protectedCredentialStoreSUITKeys,
		want.protectedCredentialStoreBinding,
		issuerBinding,
		want.issuerAllowlistMatch,
		rotationPolicy,
		revocationStatus,
		want.revocationStateMatch,
		freshness,
		want.storeFreshnessEpochMatch,
		want.platformIssuerAllowlistLoad,
		want.platformStoreFreshnessLoad,
		want.platformRevocationStateLoad,
		want.protectedStorageBinding,
		protectedStoreBound,
		issuerBound,
		storeFreshnessBound,
		revocationBound,
		trustAnchorBound,
	))
}

func assertDemoTCArtifactNotPromoted(t *testing.T, stateDir string) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(stateDir, "apps", "hello.txt"),
		filepath.Join(stateDir, "apps", "hello.wasm"),
		filepath.Join(stateDir, "catalog", "catalog.cbor.tmp"),
	} {
		assertPathMissing(t, path)
	}
	assertCatalogDoesNotReferenceDemoTC(t, filepath.Join(stateDir, "catalog", "catalog.cbor"))
	assertCatalogDoesNotReferenceDemoTC(t, filepath.Join(stateDir, "catalog", "catalog.dev.json"))
}

func assertCatalogDoesNotReferenceDemoTC(t *testing.T, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("hello.txt"),
		[]byte("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"),
		fixtureSUITPayloadDigestBytes(),
	} {
		if bytes.Contains(got, forbidden) {
			t.Fatalf("%s references non-Wasm demo TC artifact %q", path, forbidden)
		}
	}
}

func assertCatalogDoesNotReference(t *testing.T, path string, values ...string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if bytes.Contains(got, []byte(value)) {
			t.Fatalf("%s references rejected value %q", path, value)
		}
	}
}

func assertCatalogReferences(t *testing.T, path string, values ...string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if !bytes.Contains(got, []byte(value)) {
			t.Fatalf("%s does not reference expected value %q", path, value)
		}
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s stat error = %v, want not exist", path, err)
	}
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assertCOSESign1Payload(t *testing.T, input []byte, want []byte) {
	t.Helper()
	got, ok := coseSign1Payload(input)
	if !ok {
		t.Fatalf("COSE_Sign1 payload not found in %x", input)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("COSE_Sign1 payload mismatch: got %x want %x", got, want)
	}
}

func mustCOSESign1Payload(t *testing.T, input []byte) []byte {
	t.Helper()
	got, ok := coseSign1Payload(input)
	if !ok {
		t.Fatalf("COSE_Sign1 payload not found in %x", input)
	}
	return append([]byte(nil), got...)
}

func assertCOSESign1Algorithm(t *testing.T, input []byte, want int64) {
	t.Helper()
	got, ok := coseSign1Algorithm(input)
	if !ok {
		t.Fatalf("COSE_Sign1 algorithm not found in %x", input)
	}
	if got != want {
		t.Fatalf("COSE_Sign1 alg = %d, want %d", got, want)
	}
}

func mustTEEPQueryResponseAttestationPayload(t *testing.T, input []byte) []byte {
	t.Helper()
	off := 0
	major, value, ok := cborHead(input, &off)
	if !ok || major != 4 || value < 2 {
		t.Fatalf("TEEP QueryResponse head = major %d value %d ok %v, want array len >= 2", major, value, ok)
	}
	major, value, ok = cborHead(input, &off)
	if !ok || major != 0 || value != 2 {
		t.Fatalf("TEEP message type = major %d value %d ok %v, want query-response type 2", major, value, ok)
	}
	major, pairs, ok := cborHead(input, &off)
	if !ok || major != 5 {
		t.Fatalf("TEEP options head = major %d value %d ok %v, want map", major, pairs, ok)
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, &off)
		if !ok {
			t.Fatal("TEEP options key missing")
		}
		if keyMajor == 0 && key == 6 {
			payload, ok := cborBytesView(input, &off)
			if !ok {
				t.Fatal("attestation-payload is not a CBOR bstr")
			}
			return append([]byte(nil), payload...)
		}
		if !cborSkip(input, &off) {
			t.Fatal("failed to skip TEEP option value")
		}
	}
	t.Fatal("attestation-payload option not found")
	return nil
}

func assertEATNonce(t *testing.T, input []byte, want []byte) {
	t.Helper()
	off := 0
	major, pairs, ok := cborHead(input, &off)
	if !ok || major != 5 {
		t.Fatalf("EAT head = major %d value %d ok %v, want map", major, pairs, ok)
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, &off)
		if !ok {
			t.Fatal("EAT key missing")
		}
		if keyMajor == 0 && key == 10 {
			got, ok := cborBytesView(input, &off)
			if !ok {
				t.Fatal("EAT nonce is not a CBOR bstr")
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("EAT nonce = %x, want %x", got, want)
			}
			return
		}
		if !cborSkip(input, &off) {
			t.Fatal("failed to skip EAT claim")
		}
	}
	t.Fatal("EAT nonce claim not found")
}

func assertEATUEID(t *testing.T, input []byte, want []byte) {
	t.Helper()
	off := 0
	major, pairs, ok := cborHead(input, &off)
	if !ok || major != 5 {
		t.Fatalf("EAT head = major %d value %d ok %v, want map", major, pairs, ok)
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, &off)
		if !ok {
			t.Fatal("EAT key missing")
		}
		if keyMajor == 0 && key == 256 {
			got, ok := cborBytesView(input, &off)
			if !ok {
				t.Fatal("EAT UEID is not a CBOR bstr")
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("EAT UEID = %x, want %x", got, want)
			}
			return
		}
		if !cborSkip(input, &off) {
			t.Fatal("failed to skip EAT claim")
		}
	}
	t.Fatal("EAT UEID claim not found")
}

func assertEATMeasurementDigest(t *testing.T, input []byte, want []byte) {
	t.Helper()
	off := 0
	major, pairs, ok := cborHead(input, &off)
	if !ok || major != 5 {
		t.Fatalf("EAT head = major %d value %d ok %v, want map", major, pairs, ok)
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, &off)
		if !ok {
			t.Fatal("EAT key missing")
		}
		if keyMajor == 0 && key == 273 {
			assertMeasurementDigestArray(t, input, &off, want)
			return
		}
		if !cborSkip(input, &off) {
			t.Fatal("failed to skip EAT claim")
		}
	}
	t.Fatal("EAT measurements claim not found")
}

func assertEATCNFKeyAlgorithm(t *testing.T, input []byte, want int64) {
	t.Helper()
	off := 0
	major, pairs, ok := cborHead(input, &off)
	if !ok || major != 5 {
		t.Fatalf("EAT head = major %d value %d ok %v, want map", major, pairs, ok)
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, &off)
		if !ok {
			t.Fatal("EAT key missing")
		}
		if keyMajor == 0 && key == 8 {
			got, ok := eatCNFKeyAlgorithm(input, &off)
			if !ok {
				t.Fatal("EAT cnf.key alg not found")
			}
			if got != want {
				t.Fatalf("EAT cnf.key alg = %d, want %d", got, want)
			}
			return
		}
		if !cborSkip(input, &off) {
			t.Fatal("failed to skip EAT claim")
		}
	}
	t.Fatal("EAT cnf claim not found")
}

func eatCNFKeyAlgorithm(input []byte, off *int) (int64, bool) {
	major, pairs, ok := cborHead(input, off)
	if !ok || major != 5 {
		return 0, false
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, off)
		if !ok {
			return 0, false
		}
		if keyMajor == 0 && key == 1 {
			return coseKeyAlgorithm(input, off)
		}
		if !cborSkip(input, off) {
			return 0, false
		}
	}
	return 0, false
}

func coseKeyAlgorithm(input []byte, off *int) (int64, bool) {
	major, pairs, ok := cborHead(input, off)
	if !ok || major != 5 {
		return 0, false
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, off)
		if !ok {
			return 0, false
		}
		if keyMajor == 0 && key == 3 {
			return cborSignedInt(input, off)
		}
		if !cborSkip(input, off) {
			return 0, false
		}
	}
	return 0, false
}

func assertMeasurementDigestArray(t *testing.T, input []byte, off *int, want []byte) {
	t.Helper()
	major, measurements, ok := cborHead(input, off)
	if !ok || major != 4 || measurements == 0 {
		t.Fatalf("EAT measurements head = major %d value %d ok %v, want non-empty array", major, measurements, ok)
	}
	major, measurementFields, ok := cborHead(input, off)
	if !ok || major != 4 || measurementFields != 2 {
		t.Fatalf("EAT measurement head = major %d value %d ok %v, want array len 2", major, measurementFields, ok)
	}
	major, measurementType, ok := cborHead(input, off)
	if !ok || major != 0 || measurementType != 600 {
		t.Fatalf("EAT measurement type = major %d value %d ok %v, want 600", major, measurementType, ok)
	}
	measuredComponent, ok := cborBytesView(input, off)
	if !ok {
		t.Fatal("EAT measured component is not a CBOR bstr")
	}
	assertMeasuredComponentDigest(t, measuredComponent, want)
}

func assertMeasuredComponentDigest(t *testing.T, input []byte, want []byte) {
	t.Helper()
	off := 0
	major, pairs, ok := cborHead(input, &off)
	if !ok || major != 5 {
		t.Fatalf("measured component head = major %d value %d ok %v, want map", major, pairs, ok)
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, &off)
		if !ok {
			t.Fatal("measured component key missing")
		}
		if keyMajor == 0 && key == 2 {
			major, digestFields, ok := cborHead(input, &off)
			if !ok || major != 4 || digestFields != 2 {
				t.Fatalf("measurement digest head = major %d value %d ok %v, want array len 2", major, digestFields, ok)
			}
			major, alg, ok := cborHead(input, &off)
			if !ok || major != 0 || alg != 1 {
				t.Fatalf("measurement digest alg = major %d value %d ok %v, want sha-256", major, alg, ok)
			}
			got, ok := cborBytesView(input, &off)
			if !ok {
				t.Fatal("measurement digest value is not a CBOR bstr")
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("measurement digest = %x, want %x", got, want)
			}
			return
		}
		if !cborSkip(input, &off) {
			t.Fatal("failed to skip measured component field")
		}
	}
	t.Fatal("measurement digest field not found")
}

func coseSign1Payload(input []byte) ([]byte, bool) {
	off := 0
	major, value, ok := cborHead(input, &off)
	if !ok {
		return nil, false
	}
	if major == 6 {
		if value != 18 {
			return nil, false
		}
		major, value, ok = cborHead(input, &off)
		if !ok {
			return nil, false
		}
	}
	if major != 4 || value != 4 {
		return nil, false
	}
	if _, ok := cborBytesView(input, &off); !ok {
		return nil, false
	}
	if !cborSkip(input, &off) {
		return nil, false
	}
	payload, ok := cborBytesView(input, &off)
	return payload, ok
}

func coseSign1Algorithm(input []byte) (int64, bool) {
	off := 0
	major, value, ok := cborHead(input, &off)
	if !ok {
		return 0, false
	}
	if major == 6 {
		if value != 18 {
			return 0, false
		}
		major, value, ok = cborHead(input, &off)
		if !ok {
			return 0, false
		}
	}
	if major != 4 || value != 4 {
		return 0, false
	}
	protected, ok := cborBytesView(input, &off)
	if !ok {
		return 0, false
	}
	return coseProtectedAlgorithm(protected)
}

func coseProtectedAlgorithm(input []byte) (int64, bool) {
	off := 0
	major, pairs, ok := cborHead(input, &off)
	if !ok || major != 5 {
		return 0, false
	}
	for i := 0; i < pairs; i++ {
		keyMajor, key, ok := cborHead(input, &off)
		if !ok {
			return 0, false
		}
		if keyMajor == 0 && key == 1 {
			return cborSignedInt(input, &off)
		}
		if !cborSkip(input, &off) {
			return 0, false
		}
	}
	return 0, false
}

func cborSignedInt(input []byte, off *int) (int64, bool) {
	major, value, ok := cborHead(input, off)
	if !ok {
		return 0, false
	}
	switch major {
	case 0:
		return int64(value), true
	case 1:
		return -1 - int64(value), true
	default:
		return 0, false
	}
}

func coseSign1DetachPayload(input []byte) ([]byte, bool) {
	off := 0
	major, value, ok := cborHead(input, &off)
	if !ok {
		return nil, false
	}
	if major == 6 {
		if value != 18 {
			return nil, false
		}
		major, value, ok = cborHead(input, &off)
		if !ok {
			return nil, false
		}
	}
	if major != 4 || value != 4 {
		return nil, false
	}
	if !cborSkip(input, &off) || !cborSkip(input, &off) {
		return nil, false
	}
	payloadStart := off
	if !cborSkip(input, &off) {
		return nil, false
	}
	out := append([]byte(nil), input[:payloadStart]...)
	out = append(out, 0xf6)
	out = append(out, input[off:]...)
	return out, true
}

func cborBytesView(input []byte, off *int) ([]byte, bool) {
	major, value, ok := cborHead(input, off)
	if !ok || major != 2 || value > len(input)-*off {
		return nil, false
	}
	start := *off
	*off += value
	return input[start:*off], true
}

func cborSkip(input []byte, off *int) bool {
	major, value, ok := cborHead(input, off)
	if !ok {
		return false
	}
	switch major {
	case 0, 1, 7:
		return true
	case 2, 3:
		if value > len(input)-*off {
			return false
		}
		*off += value
		return true
	case 4:
		for i := 0; i < value; i++ {
			if !cborSkip(input, off) {
				return false
			}
		}
		return true
	case 5:
		for i := 0; i < value; i++ {
			if !cborSkip(input, off) || !cborSkip(input, off) {
				return false
			}
		}
		return true
	case 6:
		return cborSkip(input, off)
	default:
		return false
	}
}

func cborHead(input []byte, off *int) (byte, int, bool) {
	if *off >= len(input) {
		return 0, 0, false
	}
	head := input[*off]
	*off = *off + 1
	major := head >> 5
	add := head & 0x1f
	switch {
	case add < 24:
		return major, int(add), true
	case add == 24:
		if *off >= len(input) {
			return 0, 0, false
		}
		value := int(input[*off])
		*off = *off + 1
		return major, value, true
	case add == 25:
		if *off+1 >= len(input) {
			return 0, 0, false
		}
		value := int(input[*off])<<8 | int(input[*off+1])
		*off += 2
		return major, value, true
	default:
		return 0, 0, false
	}
}

func cborBstr(value []byte) []byte {
	out := []byte{}
	if len(value) < 24 {
		out = append(out, 0x40|byte(len(value)))
	} else if len(value) <= 0xff {
		out = append(out, 0x58, byte(len(value)))
	} else {
		out = append(out, 0x59, byte(len(value)>>8), byte(len(value)))
	}
	return append(out, value...)
}

func twepAppComponentID(command string) []byte {
	out := []byte{0x82}
	out = append(out, cborBstr([]byte("twep-app-v1"))...)
	out = append(out, cborBstr([]byte(command))...)
	return out
}

func fixtureSUITComponentID() []byte {
	return []byte{
		0x81,
		0x49, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74,
	}
}

func fixtureSUITPayloadDigestBytes() []byte {
	return []byte{
		0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0,
		0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
		0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b,
		0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f,
	}
}

func fixtureSUITManifestDigestBytes() []byte {
	return []byte{
		0x43, 0x13, 0x16, 0x04, 0x84, 0x18, 0x2f, 0x04,
		0x11, 0x97, 0xf6, 0x95, 0xa4, 0x12, 0xb7, 0xc5,
		0x91, 0xcb, 0x11, 0x2c, 0xca, 0xaa, 0x5d, 0x60,
		0xc0, 0x32, 0x85, 0xef, 0x7e, 0x20, 0xfc, 0xb0,
	}
}

func fixtureSUITManifestDigest() []byte {
	return append([]byte{0x82, 0x2f, 0x58, 0x20}, fixtureSUITManifestDigestBytes()...)
}

func fixtureStagingMetadata() []byte {
	return fixtureUpdateMetadata("tmp/update-payload-0.bin")
}

func fixtureUpdateMetadata(payloadFile string) []byte {
	out := []byte{0xa6}
	out = cborText(out, "schema_version")
	out = append(out, 0x01)
	out = cborText(out, "component_id_cbor")
	out = append(out, cborBstr(fixtureSUITComponentID())...)
	out = cborText(out, "sequence_number")
	out = append(out, 0x00)
	out = cborText(out, "payload_uri")
	out = cborText(out, "#hello.txt")
	out = cborText(out, "payload_file")
	out = cborText(out, payloadFile)
	out = cborText(out, "payload_sha256")
	out = append(out, cborBstr(fixtureSUITPayloadDigestBytes())...)
	return out
}

func fixtureSuccessPayload(token []byte) []byte {
	report := fixtureSuccessReport()
	out := []byte{0x82, 0x04, 0xa2, 0x12, 0x81}
	out = append(out, cborBstr(report)...)
	out = append(out, 0x13)
	out = append(out, cborBstr(token)...)
	return out
}

func fixtureSuccessReport() []byte {
	out := []byte{0xa3}
	out = cborUint(out, 99)
	out = append(out, 0x82)
	out = cborText(out, "")
	out = append(out, fixtureSUITManifestDigest()...)
	out = append(out, 0x03, 0x81, 0xa3, 0x00)
	out = append(out, fixtureSUITComponentID()...)
	out = append(out, 0x0e)
	out = cborUint(out, uint64(len(fixtureSUITPayload())))
	out = append(out, 0x03)
	out = append(out, cborBstr(fixtureSUITPayloadDigest())...)
	out = append(out, 0x04, 0xf5)
	return out
}

func fixtureSUITPayload() []byte {
	return []byte("Hello, World!")
}

func fixtureSUITPayloadDigest() []byte {
	return append([]byte{0x82, 0x2f, 0x58, 0x20}, fixtureSUITPayloadDigestBytes()...)
}

func fixtureSUITManifest() []byte {
	componentID := fixtureSUITComponentID()
	payloadDigest := fixtureSUITPayloadDigest()
	sharedSequence := append([]byte{0x82, 0x14, 0xa1, 0x03}, cborBstr(payloadDigest)...)
	common := append([]byte{0xa2, 0x02, 0x81}, componentID...)
	common = append(common, 0x04)
	common = append(common, cborBstr(sharedSequence)...)
	payloadFetch := []byte{0x82, 0x14, 0xa1, 0x15}
	payloadFetch = append(payloadFetch, []byte{0x6a}...)
	payloadFetch = append(payloadFetch, []byte("#hello.txt")...)
	manifest := []byte{0xa3, 0x02, 0x00, 0x03}
	manifest = append(manifest, cborBstr(common)...)
	manifest = append(manifest, 0x10)
	manifest = append(manifest, cborBstr(payloadFetch)...)
	authWrapper := []byte{0x82}
	authWrapper = append(authWrapper, cborBstr(fixtureSUITManifestDigest())...)
	authWrapper = append(authWrapper, cborBstr([]byte{0})...)
	envelope := []byte{0xd8, 0x6b, 0xa3, 0x02}
	envelope = append(envelope, cborBstr(authWrapper)...)
	envelope = append(envelope, 0x03)
	envelope = append(envelope, cborBstr(manifest)...)
	envelope = append(envelope, 0x6a)
	envelope = append(envelope, []byte("#hello.txt")...)
	envelope = append(envelope, cborBstr(fixtureSUITPayload())...)
	return envelope
}

func fixtureAppSUITManifest(componentID []byte, payloadURI string, payload []byte, payloadSHA256 []byte, sequence uint64) []byte {
	manifest := fixtureAppSUITManifestBody(componentID, payloadURI, payloadSHA256, sequence)
	return fixtureAppSUITEnvelope(manifest, payloadURI, payload, fixtureSUITManifestDigest(), []byte{0})
}

func fixtureAppSUITManifestBody(componentID []byte, payloadURI string, payloadSHA256 []byte, sequence uint64) []byte {
	payloadDigest := append([]byte{0x82, 0x2f}, cborBstr(payloadSHA256)...)
	sharedSequence := append([]byte{0x82, 0x14, 0xa1, 0x03}, cborBstr(payloadDigest)...)
	common := append([]byte{0xa2, 0x02, 0x81}, componentID...)
	common = append(common, 0x04)
	common = append(common, cborBstr(sharedSequence)...)
	payloadFetch := []byte{0x82, 0x14, 0xa1, 0x15}
	payloadFetch = cborText(payloadFetch, payloadURI)
	manifest := []byte{0xa3, 0x02}
	manifest = cborUint(manifest, sequence)
	manifest = append(manifest, 0x03)
	manifest = append(manifest, cborBstr(common)...)
	manifest = append(manifest, 0x10)
	manifest = append(manifest, cborBstr(payloadFetch)...)
	return manifest
}

func fixtureAppSUITEnvelope(manifest []byte, payloadURI string, payload []byte, manifestDigest []byte, authBlock []byte) []byte {
	authWrapper := []byte{0x82}
	authWrapper = append(authWrapper, cborBstr(manifestDigest)...)
	authWrapper = append(authWrapper, cborBstr(authBlock)...)
	envelope := []byte{0xd8, 0x6b, 0xa3, 0x02}
	envelope = append(envelope, cborBstr(authWrapper)...)
	envelope = append(envelope, 0x03)
	envelope = append(envelope, cborBstr(manifest)...)
	envelope = cborText(envelope, payloadURI)
	envelope = append(envelope, cborBstr(payload)...)
	return envelope
}

var abi2Wasm = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60,
	0x00, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x18, 0x01, 0x14, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x61, 0x62, 0x69, 0x5f,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x0a, 0x06, 0x01,
	0x04, 0x00, 0x41, 0x02, 0x0b,
}

var envImportWasm = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x05, 0x60,
	0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, 0x60, 0x01, 0x7f,
	0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x03, 0x7f, 0x7f, 0x7f,
	0x01, 0x7f, 0x02, 0x18, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x10, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x72, 0x61, 0x6e, 0x64,
	0x6f, 0x6d, 0x00, 0x00, 0x03, 0x05, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x03, 0x01, 0x00, 0x01, 0x07, 0x52, 0x05, 0x06, 0x6d, 0x65, 0x6d, 0x6f,
	0x72, 0x79, 0x02, 0x00, 0x14, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70,
	0x70, 0x5f, 0x61, 0x62, 0x69, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x00, 0x01, 0x0e, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70,
	0x5f, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x02, 0x0d, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x66, 0x72, 0x65, 0x65, 0x00, 0x03,
	0x0d, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x6d, 0x61,
	0x69, 0x6e, 0x00, 0x04, 0x0a, 0x22, 0x04, 0x04, 0x00, 0x41, 0x01, 0x0b,
	0x05, 0x00, 0x41, 0x80, 0x08, 0x0b, 0x02, 0x00, 0x0b, 0x12, 0x00, 0x41,
	0x10, 0x41, 0x01, 0x10, 0x00, 0x45, 0x04, 0x7f, 0x41, 0xff, 0x00, 0x05,
	0x41, 0x02, 0x0b, 0x0b,
}

var teepImportWasm = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x05, 0x60,
	0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, 0x60, 0x01, 0x7f,
	0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x03, 0x7f, 0x7f, 0x7f,
	0x01, 0x7f, 0x02, 0x22, 0x01, 0x0d, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x74,
	0x65, 0x65, 0x70, 0x5f, 0x65, 0x6e, 0x76, 0x10, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d,
	0x00, 0x00, 0x03, 0x05, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x03, 0x01,
	0x00, 0x01, 0x07, 0x52, 0x05, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79,
	0x02, 0x00, 0x14, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f,
	0x61, 0x62, 0x69, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00,
	0x01, 0x0e, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x61,
	0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x02, 0x0d, 0x74, 0x77, 0x65, 0x70, 0x5f,
	0x61, 0x70, 0x70, 0x5f, 0x66, 0x72, 0x65, 0x65, 0x00, 0x03, 0x0d, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x6d, 0x61, 0x69, 0x6e,
	0x00, 0x04, 0x0a, 0x22, 0x04, 0x04, 0x00, 0x41, 0x01, 0x0b, 0x05, 0x00,
	0x41, 0x80, 0x08, 0x0b, 0x02, 0x00, 0x0b, 0x12, 0x00, 0x41, 0x10, 0x41,
	0x01, 0x10, 0x00, 0x45, 0x04, 0x7f, 0x41, 0xff, 0x00, 0x05, 0x41, 0x02,
	0x0b, 0x0b,
}

var loopWasm = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x16, 0x04, 0x60,
	0x00, 0x01, 0x7f, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f,
	0x00, 0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x05, 0x04, 0x00,
	0x01, 0x02, 0x03, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x52, 0x05, 0x06,
	0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x14, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x61, 0x62, 0x69, 0x5f, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x0e, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x01,
	0x0d, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x66, 0x72,
	0x65, 0x65, 0x00, 0x02, 0x0d, 0x74, 0x77, 0x65, 0x70, 0x5f, 0x61, 0x70,
	0x70, 0x5f, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x03, 0x0a, 0x19, 0x04, 0x04,
	0x00, 0x41, 0x01, 0x0b, 0x05, 0x00, 0x41, 0x80, 0x08, 0x0b, 0x02, 0x00,
	0x0b, 0x09, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x41, 0x00, 0x0b,
}
