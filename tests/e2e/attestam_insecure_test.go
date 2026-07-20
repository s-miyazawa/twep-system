// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/s-miyazawa/twep-system/internal/demokeys"
	"github.com/s-miyazawa/twep-system/internal/suitfixture"
	"github.com/s-miyazawa/twep-system/internal/wasmsign"
)

func TestAttestamInsecureTwepdCLI(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

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
		posts.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-insecure",
		"--attestam-url", server.URL,
		"--insecure-demo-mode",
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		"helloworld",
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("twep-cli failed: %v\n%s\ntwepd:\n%s", err, cliOut, twepdOut.Bytes())
	}
	if string(cliOut) != "Hello, World!!\n" {
		t.Fatalf("twep-cli output = %q, want Hello, World!!", cliOut)
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}

	if _, err := os.Stat(filepath.Join(stateDir, "catalog", "catalog.cbor.tmp")); !os.IsNotExist(err) {
		t.Fatalf("catalog.cbor.tmp stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "tmp", "teep-agent-probe")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "apps", "helloworld.wasm")); err != nil {
		t.Fatal(err)
	}
	if posts.Load() == 0 {
		t.Fatal("AttesTAM fixture server received no POST")
	}
}

func TestAttestamInsecureNonEmptyTEEPResponseIsUnsupported(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

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
	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-insecure",
		"--attestam-url", server.URL,
		"--insecure-demo-mode",
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		"helloworld",
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.protocol error\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.protocol") {
		t.Fatalf("twep-cli output = %q, want teep.protocol\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "catalog", "catalog.cbor.tmp")); !os.IsNotExist(err) {
		t.Fatalf("catalog.cbor.tmp stat error = %v, want not exist", err)
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-response.cose"), teepResponse)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-payload.cbor"), teepPayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-teep-message-type.txt"), []byte("query-request\n"))
	queryResponse := readFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response.cose"))
	if len(queryResponse) < 3 || queryResponse[0] != 0xd2 || queryResponse[1] != 0x84 {
		t.Fatalf("saved QueryResponse = %x, want tagged COSE_Sign1", queryResponse)
	}
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-status.txt"), []byte("host-status=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body.cose"), updateResponse)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body-payload.cbor"), updatePayload)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-query-response-body-message-type.txt"), []byte("update\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-0.cbor"), updateManifest)
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-count.txt"), []byte("manifest-count=1\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-manifest-component-id.cbor"), fixtureSUITComponentID())
	if len(postedBodies) != 2 {
		t.Fatalf("posted body count = %d, want 2", len(postedBodies))
	}
	if !bytes.Equal(postedBodies[0], nil) {
		t.Fatalf("first posted body = %x, want empty", postedBodies[0])
	}
	if !bytes.Equal(postedBodies[1], queryResponse) {
		t.Fatal("second posted body does not match saved signed QueryResponse")
	}
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

func TestAttestamInsecurePromotesWasmAppUpdate(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	appPayload := readFileBytes(t, filepath.Join(repoRoot, "build", "helloworld.wasm"))
	appDigest := sha256.Sum256(appPayload)
	appCommand := "remotehello"
	appWasmFile := "remotehello.wasm"
	componentID := twepAppComponentID(appCommand)
	payloadURI := "#remotehello.wasm"
	updateManifest := fixtureSUITManifestFor(componentID, payloadURI, appPayload, appDigest[:], nil)
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
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-insecure",
		"--attestam-url", server.URL,
		"--insecure-demo-mode",
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		appCommand,
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("twep-cli failed: %v\n%s\ntwepd:\n%s", err, cliOut, twepdOut.Bytes())
	}
	if string(cliOut) != "Hello, World!!\n" {
		t.Fatalf("twep-cli output = %q, want Hello, World!!", cliOut)
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if len(postedBodies) != 3 {
		t.Fatalf("posted body count = %d, want 3", len(postedBodies))
	}
	assertFileBytes(t, filepath.Join(stateDir, "apps", appWasmFile), appPayload)
	assertFileBytes(t, filepath.Join(stateDir, "components", "install-metadata.cbor"), fixtureUpdateMetadataFor(componentID, 0, payloadURI, "apps/"+appWasmFile, appDigest[:]))
	assertFileBytes(t, filepath.Join(stateDir, "components", "install-status.txt"), []byte("install=ready\n"))
	assertPromotedCatalogEntry(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), appCommand, appWasmFile, appDigest[:])
	assertPathMissing(t, filepath.Join(stateDir, "apps", appWasmFile+".tmp"))
	assertPathMissing(t, filepath.Join(stateDir, "catalog", "catalog.cbor.tmp"))
}

func TestAttestamInsecureRejectsInvalidWasmAppUpdates(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	appPayload := readFileBytes(t, filepath.Join(repoRoot, "build", "helloworld.wasm"))
	appDigest := sha256.Sum256(appPayload)
	unsignedPayload, err := wasmsign.StripSignature(appPayload)
	if err != nil {
		t.Fatal(err)
	}
	unsignedDigest := sha256.Sum256(unsignedPayload)
	badDigest := append([]byte(nil), appDigest[:]...)
	badDigest[0] ^= 0xff

	tests := []struct {
		name          string
		command       string
		wasmFile      string
		payload       []byte
		payloadSHA256 []byte
	}{
		{
			name:          "payload hash mismatch",
			command:       "badhash",
			wasmFile:      "badhash.wasm",
			payload:       appPayload,
			payloadSHA256: badDigest,
		},
		{
			name:          "missing code signature",
			command:       "unsignedremote",
			wasmFile:      "unsignedremote.wasm",
			payload:       unsignedPayload,
			payloadSHA256: unsignedDigest[:],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			componentID := twepAppComponentID(tt.command)
			payloadURI := "#" + tt.wasmFile
			updateManifest := fixtureSUITManifestFor(componentID, payloadURI, tt.payload, tt.payloadSHA256, nil)
			updateToken := []byte{0xba, 0xad, 0xf0, 0x0d}
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
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			stateDir := t.TempDir()
			socketPath := filepath.Join(stateDir, "run", "twepd.sock")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			twepd := exec.CommandContext(ctx,
				filepath.Join(binDir, "twepd"),
				"--socket", socketPath,
				"--state-dir", stateDir,
				"--resolver-mode", "attestam-insecure",
				"--attestam-url", server.URL,
				"--insecure-demo-mode",
				"--once",
			)
			twepd.Dir = repoRoot
			var twepdOut bytes.Buffer
			twepd.Stdout = &twepdOut
			twepd.Stderr = &twepdOut
			if err := twepd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if twepd.ProcessState == nil {
					_ = twepd.Process.Kill()
					_ = twepd.Wait()
				}
			}()
			waitForSocket(t, socketPath)

			cli := exec.CommandContext(ctx,
				filepath.Join(binDir, "twep-cli"),
				"--socket", socketPath,
				tt.command,
			)
			cli.Dir = repoRoot
			cliOut, err := cli.CombinedOutput()
			if err == nil {
				t.Fatalf("twep-cli succeeded, want teep.protocol error\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
			}
			if !strings.Contains(string(cliOut), "teep.protocol") {
				t.Fatalf("twep-cli output = %q, want teep.protocol\ntwepd:\n%s", cliOut, twepdOut.Bytes())
			}
			if err := twepd.Wait(); err != nil {
				t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
			}
			if len(postedBodies) != 2 {
				t.Fatalf("posted body count = %d, want 2", len(postedBodies))
			}
			assertPathMissing(t, filepath.Join(stateDir, "apps", tt.wasmFile))
			assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), tt.command, tt.wasmFile)
			assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.dev.json"), tt.command, tt.wasmFile)
			assertPathMissing(t, filepath.Join(stateDir, "catalog", "catalog.cbor.tmp"))
			if tt.name == "payload hash mismatch" {
				assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-payload-hash-status.txt"), []byte("payload-hash=mismatch\n"))
			}
		})
	}
}

func TestAttestamInsecureWithoutDemoModeRejectsHTTP(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-insecure",
		"--attestam-url", server.URL,
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		"helloworld",
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.protocol error\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.protocol") {
		t.Fatalf("twep-cli output = %q, want teep.protocol\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "catalog", "catalog.cbor.tmp")); !os.IsNotExist(err) {
		t.Fatalf("catalog.cbor.tmp stat error = %v, want not exist", err)
	}
}

func TestAttestamInsecureNetworkError(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	attestamURL := unusedLocalHTTPURL(t)
	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-insecure",
		"--attestam-url", attestamURL,
		"--insecure-demo-mode",
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		"helloworld",
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.network error\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.network") {
		t.Fatalf("twep-cli output = %q, want teep.network\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "catalog", "catalog.cbor.tmp")); !os.IsNotExist(err) {
		t.Fatalf("catalog.cbor.tmp stat error = %v, want not exist", err)
	}
}

func TestAttestamVerifiedRejectsInsecureDemoAtStartup(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-verified",
		"--attestam-url", "http://127.0.0.1:1/tam",
		"--insecure-demo-mode",
		"--once",
	)
	twepd.Dir = repoRoot
	out, err := twepd.CombinedOutput()
	if err == nil {
		t.Fatalf("twepd succeeded, want startup rejection\n%s", out)
	}
	if !strings.Contains(string(out), "invalid argument") {
		t.Fatalf("twepd output = %q, want invalid argument", out)
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket stat error = %v, want not exist", err)
	}
}

func TestAttestamVerifiedDryRunDoesNotPromoteAppE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dryRunState := cborMap(nil, 1)
	dryRunState = append(dryRunState, cborText("fixture_verified")...)
	dryRunState = cborBool(dryRunState, true)
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-dry-run-state.cbor"), dryRunState, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = append(devFreshness, cborBstr(twepAppComponentID("remotehello"))...)
	devFreshness = cborUint(devFreshness, 7)
	if err := os.WriteFile(filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-verified",
		"--attestam-url", server.URL,
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		"remotehello",
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.verified_required\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.verified_required") {
		t.Fatalf("twep-cli output = %q, want teep.verified_required\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "verified-state.txt"),
		[]byte("cose-outer-verified=true\nsession-token-bound=true\nsuit-auth-verified=true\nsequence-fresh=true\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n"),
	)
	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"== verified-state ==\n",
		"missing-step=none\n",
		"final-missing-step=teep.trust_anchor_unbound\n",
		"== credential-status ==\n",
		"trust-anchor-bound=false\n",
		"== platform-status ==\n",
		"sealed-storage-security=observation-only\n",
		"== evidence-status ==\n",
		"evidence-result-load=absent\n",
		"evidence-affirming=false\n",
		"== agent-identity-status ==\n",
		"agent-identity-source=platform-status-linux\n",
		"agent-identity-bound=false\n",
		"== suit-auth-status ==\n",
		"(missing)\n",
		"== update-component-status ==\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertFileBytes(t, filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness)
	assertVerifiedNoPromotion(t, stateDir, "remotehello", "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSEDoesNotPromoteAppE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified COSE dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	token := []byte{0xca, 0xfe, 0xba, 0xbe}
	payload := []byte("not executed")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        payload,
		SequenceNumber: 4,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), token, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = append(devFreshness, cborBstr(artifact.ComponentID)...)
	devFreshness = cborUint(devFreshness, 3)
	if err := os.WriteFile(filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-verified",
		"--attestam-url", server.URL,
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		command,
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.verified_required\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.verified_required") {
		t.Fatalf("twep-cli output = %q, want teep.verified_required\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "verified-state.txt"),
		[]byte("cose-outer-verified=true\nsession-token-bound=true\nsuit-auth-verified=true\nsequence-fresh=true\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n"),
	)
	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"== verified-state ==\n",
		"missing-step=none\n",
		"final-missing-step=teep.trust_anchor_unbound\n",
		"== credential-status ==\n",
		"trust-anchor-bound=false\n",
		"== platform-status ==\n",
		"sealed-storage-security=observation-only\n",
		"== evidence-status ==\n",
		"evidence-result-load=absent\n",
		"evidence-affirming=false\n",
		"== agent-identity-status ==\n",
		"agent-identity-source=platform-status-linux\n",
		"agent-identity-bound=false\n",
		"== suit-auth-status ==\n",
		"suit-auth=ok\n",
		"== update-component-status ==\n",
		"component-kind=twep-app-v1\n",
		"component-name=remotehello\n",
		"promotion=blocked-final-verified\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-component-id.cbor"), artifact.ComponentID)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-sequence-number.txt"), []byte("sequence-number=4\n"))
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-0.bin"), payload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-sha256.bin"), artifact.PayloadSHA256[:])
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-hash-status.txt"), []byte("payload-hash=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "update-component-status.txt"),
		[]byte("component-kind=twep-app-v1\ncomponent-name=remotehello\npromotion=blocked-final-verified\n"),
	)
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, devFreshness, nil)
	assertVerifiedNoPromotion(t, stateDir, command, "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSEDoesNotCreateAcceptanceWithoutLiveCommitE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified TAM signed evidence dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	token := []byte{0xca, 0xfe, 0x42, 0x01}
	queryResponse := []byte("retained evidence query response")
	payload := []byte("TAM signed evidence is not final")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        payload,
		SequenceNumber: 8,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	writeVerifiedInputUpdate(t, stateDir, artifact.COSEUpdate, token)
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-evidence-query-response.cose"), queryResponse, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := writeDevSequenceFreshness(t, stateDir, artifact.ComponentID, 7)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runAttestamVerifiedDryRun(t, ctx, binDir, repoRoot, stateDir, server.URL, command)
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"missing-step=none\n",
		"final-missing-step=teep.trust_anchor_unbound\n",
		"evidence-result-load=absent\n",
		"evidence-verifier-result=none\n",
		"evidence-decision-source=none\n",
		"evidence-nonce-match=false\n",
		"evidence-cnf-key-match=false\n",
		"evidence-platform-match=false\n",
		"evidence-tam-response-verified=false\n",
		"evidence-challenge-response-bound=false\n",
		"evidence-acceptance-generation-current=false\n",
		"evidence-binding=unbound\n",
		"evidence-affirming=false\n",
		"component-kind=twep-app-v1\n",
		"component-name=remotehello\n",
		"promotion=blocked-final-verified\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertVerifiedDiagnoseJSONObservations(t, ctx, binDir, repoRoot, stateDir,
		[]string{},
		[]string{},
		[]string{"teep.protected_credential_store_unbound", "teep.issuer_allowlist_unbound", "teep.store_freshness_unbound", "teep.revocation_state_unbound"},
	)
	assertPathMissing(t, filepath.Join(teepAgentDir, "verified-evidence-result.cbor"))
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, devFreshness, nil)
	assertVerifiedNoPromotion(t, stateDir, command, "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSEUsesProtectedSequenceFreshnessE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified protected freshness dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	token := []byte{0xca, 0xfe, 0x51, 0x09}
	payload := []byte("not executed with protected freshness")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        payload,
		SequenceNumber: 9,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), token, 0o600); err != nil {
		t.Fatal(err)
	}
	protectedFreshness := cborMap(nil, 1)
	protectedFreshness = append(protectedFreshness, cborBstr(artifact.ComponentID)...)
	protectedFreshness = cborUint(protectedFreshness, 8)
	sealedDir := filepath.Join(stateDir, "platform", "linux", "sealed")
	if err := os.MkdirAll(sealedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sealedDir, "protected-sequence-freshness.cbor"), protectedFreshness, 0o600); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-verified",
		"--attestam-url", server.URL,
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		command,
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.verified_required\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.verified_required") {
		t.Fatalf("twep-cli output = %q, want teep.verified_required\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "verified-state.txt"),
		[]byte("cose-outer-verified=true\nsession-token-bound=true\nsuit-auth-verified=true\nsequence-fresh=true\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n"),
	)
	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"== verified-state ==\n",
		"sequence-fresh=true\n",
		"missing-step=none\n",
		"final-missing-step=teep.trust_anchor_unbound\n",
		"== suit-auth-status ==\n",
		"suit-auth=ok\n",
		"== update-component-status ==\n",
		"component-kind=twep-app-v1\n",
		"component-name=remotehello\n",
		"promotion=blocked-final-verified\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-sequence-number.txt"), []byte("sequence-number=9\n"))
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-0.bin"), payload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-component-status.txt"), []byte("component-kind=twep-app-v1\ncomponent-name=remotehello\npromotion=blocked-final-verified\n"))
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, nil, protectedFreshness)
	assertVerifiedNoPromotion(t, stateDir, command, "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSERejectsProtectedSequenceReplayE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified protected freshness replay dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	token := []byte{0xca, 0xfe, 0x51, 0x0a}
	payload := []byte("replay is not executed")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        payload,
		SequenceNumber: 9,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), token, 0o600); err != nil {
		t.Fatal(err)
	}
	protectedFreshness := cborMap(nil, 1)
	protectedFreshness = append(protectedFreshness, cborBstr(artifact.ComponentID)...)
	protectedFreshness = cborUint(protectedFreshness, 9)
	sealedDir := filepath.Join(stateDir, "platform", "linux", "sealed")
	if err := os.MkdirAll(sealedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sealedDir, "protected-sequence-freshness.cbor"), protectedFreshness, 0o600); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-verified",
		"--attestam-url", server.URL,
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		command,
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.verified_required\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.verified_required") {
		t.Fatalf("twep-cli output = %q, want teep.verified_required\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "verified-state.txt"),
		[]byte("cose-outer-verified=true\nsession-token-bound=true\nsuit-auth-verified=true\nsequence-fresh=false\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=false\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=teep.sequence_unverified\nfinal-missing-step=teep.sequence_unverified\n"),
	)
	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"== verified-state ==\n",
		"sequence-fresh=false\n",
		"missing-step=teep.sequence_unverified\n",
		"final-missing-step=teep.sequence_unverified\n",
		"== suit-auth-status ==\n",
		"suit-auth=ok\n",
		"== update-component-status ==\n",
		"component-kind=twep-app-v1\n",
		"component-name=remotehello\n",
		"promotion=blocked-final-verified\n",
	}, []string{
		"teep.sequence_unverified",
	})
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-sequence-number.txt"), []byte("sequence-number=9\n"))
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-0.bin"), payload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-component-status.txt"), []byte("component-kind=twep-app-v1\ncomponent-name=remotehello\npromotion=blocked-final-verified\n"))
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, nil, protectedFreshness)
	assertVerifiedNoPromotion(t, stateDir, command, "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSERejectsIssuerAllowlistMismatchE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified issuer allowlist mismatch dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	token := []byte{0xca, 0xfe, 0x41, 0x01}
	payload := []byte("issuer mismatch is not executed")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        payload,
		SequenceNumber: 12,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	writeVerifiedInputUpdate(t, stateDir, artifact.COSEUpdate, token)
	devFreshness := writeDevSequenceFreshness(t, stateDir, artifact.ComponentID, 11)
	writeProtectedCredentialPolicy(t, stateDir, artifact.KID, []byte("other-issuer"), 1, []byte("revoked-entry"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runAttestamVerifiedDryRun(t, ctx, binDir, repoRoot, stateDir, server.URL, command)
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"missing-step=none\n",
		"final-missing-step=teep.trust_anchor_unbound\n",
		"protected-storage-binding=observation-only\n",
		"protected-credential-store-bound=false\n",
		"protected-credential-store-issuer-allowlist-match=false\n",
		"issuer-allowlist-bound=false\n",
		"store-freshness-bound=false\n",
		"revocation-state-bound=false\n",
		"trust-anchor-bound=false\n",
		"component-kind=twep-app-v1\n",
		"component-name=remotehello\n",
		"promotion=blocked-final-verified\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertVerifiedDiagnoseJSONObservations(t, ctx, binDir, repoRoot, stateDir,
		[]string{},
		[]string{"teep.credential_rotation_matched_unbound", "teep.revocation_state_matched_unbound", "teep.store_freshness_matched_unbound"},
		[]string{"teep.protected_credential_store_unbound", "teep.issuer_allowlist_unbound", "teep.store_freshness_unbound", "teep.revocation_state_unbound"},
	)
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, devFreshness, nil)
	assertVerifiedNoPromotion(t, stateDir, command, "remotehello.wasm")
}

func TestAttestamVerifiedInputCatalogUpdateCOSERejectsIssuerAllowlistMismatchE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified Catalog issuer allowlist mismatch dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	token := []byte{0xca, 0x7a, 0x41, 0x02}
	catalogPayload, err := suitfixture.CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedCatalogUpdate(suitfixture.CatalogOptions{
		CatalogName:    "default",
		Payload:        catalogPayload,
		SequenceNumber: 13,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	writeVerifiedInputUpdate(t, stateDir, artifact.COSEUpdate, token)
	devFreshness := writeDevSequenceFreshness(t, stateDir, artifact.ComponentID, 12)
	writeProtectedCredentialPolicy(t, stateDir, artifact.KID, []byte("other-issuer"), 1, []byte("revoked-entry"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runAttestamVerifiedDryRun(t, ctx, binDir, repoRoot, stateDir, server.URL, "remotehello")
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"missing-step=none\n",
		"final-missing-step=teep.trust_anchor_unbound\n",
		"protected-storage-binding=observation-only\n",
		"protected-credential-store-bound=false\n",
		"protected-credential-store-issuer-allowlist-match=false\n",
		"issuer-allowlist-bound=false\n",
		"store-freshness-bound=false\n",
		"revocation-state-bound=false\n",
		"trust-anchor-bound=false\n",
		"component-kind=twep-catalog-v1\n",
		"component-name=default\n",
		"promotion=blocked-final-verified\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertVerifiedDiagnoseJSONObservations(t, ctx, binDir, repoRoot, stateDir,
		[]string{},
		[]string{"teep.credential_rotation_matched_unbound", "teep.revocation_state_matched_unbound", "teep.store_freshness_matched_unbound"},
		[]string{"teep.protected_credential_store_unbound", "teep.issuer_allowlist_unbound", "teep.store_freshness_unbound", "teep.revocation_state_unbound"},
	)
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, devFreshness, nil)
	assertVerifiedNoPromotion(t, stateDir, "remotehello", "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSEObservesProtectedCredentialPolicyE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified protected credential dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	token := []byte{0xca, 0xfe, 0x41, 0x03}
	payload := []byte("protected credentials are not final")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        payload,
		SequenceNumber: 14,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	writeVerifiedInputUpdate(t, stateDir, artifact.COSEUpdate, token)
	devFreshness := writeDevSequenceFreshness(t, stateDir, artifact.ComponentID, 13)
	writeProtectedCredentialPolicy(t, stateDir, artifact.KID, []byte("issuer"), 1, []byte("revoked-entry"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runAttestamVerifiedDryRun(t, ctx, binDir, repoRoot, stateDir, server.URL, command)
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"missing-step=none\n",
		"final-missing-step=teep.trust_anchor_unbound\n",
		"protected-storage-binding=observation-only\n",
		"protected-credential-store-bound=false\n",
		"protected-credential-store-issuer-allowlist-match=true\n",
		"issuer-allowlist-bound=false\n",
		"protected-credential-store-freshness=matched-unbound\n",
		"protected-credential-store-revocation-status=matched-unbound\n",
		"store-freshness-bound=false\n",
		"revocation-state-bound=false\n",
		"trust-anchor-bound=false\n",
		"component-kind=twep-app-v1\n",
		"component-name=remotehello\n",
		"promotion=blocked-final-verified\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertVerifiedDiagnoseJSONObservations(t, ctx, binDir, repoRoot, stateDir,
		[]string{},
		[]string{"teep.credential_rotation_matched_unbound", "teep.revocation_state_matched_unbound", "teep.store_freshness_matched_unbound"},
		[]string{"teep.protected_credential_store_unbound", "teep.issuer_allowlist_unbound", "teep.store_freshness_unbound", "teep.revocation_state_unbound"},
	)
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, devFreshness, nil)
	assertVerifiedNoPromotion(t, stateDir, command, "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSERejectsStaleProtectedStoreFreshnessE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified stale protected store dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	token := []byte{0xca, 0xfe, 0x41, 0x04}
	payload := []byte("stale store policy is not final")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        payload,
		SequenceNumber: 15,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	writeVerifiedInputUpdate(t, stateDir, artifact.COSEUpdate, token)
	devFreshness := writeDevSequenceFreshness(t, stateDir, artifact.ComponentID, 14)
	writeProtectedCredentialPolicy(t, stateDir, artifact.KID, []byte("issuer"), 2, []byte("revoked-entry"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runAttestamVerifiedDryRun(t, ctx, binDir, repoRoot, stateDir, server.URL, command)
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"protected-credential-store-bound=false\n",
		"issuer-allowlist-bound=false\n",
		"protected-store-freshness-epoch-match=false\n",
		"protected-credential-store-freshness=unverified\n",
		"store-freshness-bound=false\n",
		"revocation-state-bound=false\n",
		"trust-anchor-bound=false\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertVerifiedDiagnoseJSONObservations(t, ctx, binDir, repoRoot, stateDir,
		[]string{},
		[]string{"teep.revocation_state_matched_unbound"},
		[]string{"teep.protected_credential_store_unbound", "teep.issuer_allowlist_unbound", "teep.store_freshness_unbound", "teep.revocation_state_unbound"},
	)
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, devFreshness, nil)
	assertVerifiedNoPromotion(t, stateDir, command, "remotehello.wasm")
}

func TestAttestamVerifiedInputUpdateCOSERejectsRevokedProtectedCredentialE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified revoked protected credential dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	command := "remotehello"
	token := []byte{0xca, 0xfe, 0x41, 0x05}
	payload := []byte("revoked credential is not final")
	artifact, err := suitfixture.GenerateDemoTAMVerifiedUpdate(suitfixture.Options{
		Command:        command,
		WasmFile:       "remotehello.wasm",
		Payload:        payload,
		SequenceNumber: 16,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	writeVerifiedInputUpdate(t, stateDir, artifact.COSEUpdate, token)
	devFreshness := writeDevSequenceFreshness(t, stateDir, artifact.ComponentID, 15)
	writeProtectedCredentialPolicy(t, stateDir, artifact.KID, []byte("issuer"), 1, []byte("tam-entry"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runAttestamVerifiedDryRun(t, ctx, binDir, repoRoot, stateDir, server.URL, command)
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"protected-credential-store-bound=false\n",
		"issuer-allowlist-bound=false\n",
		"protected-credential-store-freshness=matched-unbound\n",
		"protected-revocation-state-match=false\n",
		"protected-credential-store-revocation-status=unverified\n",
		"store-freshness-bound=false\n",
		"revocation-state-bound=false\n",
		"trust-anchor-bound=false\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertVerifiedDiagnoseJSONObservations(t, ctx, binDir, repoRoot, stateDir,
		[]string{},
		[]string{"teep.credential_rotation_matched_unbound", "teep.store_freshness_matched_unbound"},
		[]string{"teep.protected_credential_store_unbound", "teep.issuer_allowlist_unbound", "teep.store_freshness_unbound", "teep.revocation_state_unbound"},
	)
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, devFreshness, nil)
	assertVerifiedNoPromotion(t, stateDir, command, "remotehello.wasm")
}

func TestAttestamVerifiedInputCatalogUpdateCOSEDoesNotPromoteCatalogE2E(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		t.Errorf("attestam-verified Catalog TC dry-run must not POST to AttesTAM")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	token := []byte{0xca, 0x7a, 0x10}
	catalogPayload, err := suitfixture.CanonicalDefaultCatalogPayload()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := suitfixture.GenerateDemoTAMVerifiedCatalogUpdate(suitfixture.CatalogOptions{
		CatalogName:    "default",
		Payload:        catalogPayload,
		SequenceNumber: 6,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), artifact.COSEUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), token, 0o600); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = append(devFreshness, cborBstr(artifact.ComponentID)...)
	devFreshness = cborUint(devFreshness, 5)
	if err := os.WriteFile(filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-verified",
		"--attestam-url", server.URL,
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		"remotehello",
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.verified_required\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.verified_required") {
		t.Fatalf("twep-cli output = %q, want teep.verified_required\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
	if posts.Load() != 0 {
		t.Fatalf("AttesTAM fixture server received %d POSTs, want 0", posts.Load())
	}

	assertFileBytes(t, filepath.Join(teepAgentDir, "verified-input-payload.cbor"), artifact.UpdatePayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "suit-auth-status.txt"), []byte("suit-auth=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "verified-state.txt"),
		[]byte("cose-outer-verified=true\nsession-token-bound=true\nsuit-auth-verified=true\nsequence-fresh=true\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n"),
	)
	assertVerifiedDiagnoseOutput(t, ctx, binDir, repoRoot, stateDir, []string{
		"== verified-state ==\n",
		"missing-step=none\n",
		"final-missing-step=teep.trust_anchor_unbound\n",
		"== credential-status ==\n",
		"trust-anchor-bound=false\n",
		"== platform-status ==\n",
		"sealed-storage-security=observation-only\n",
		"== evidence-status ==\n",
		"evidence-result-load=absent\n",
		"evidence-affirming=false\n",
		"== agent-identity-status ==\n",
		"agent-identity-source=platform-status-linux\n",
		"agent-identity-bound=false\n",
		"== suit-auth-status ==\n",
		"suit-auth=ok\n",
		"== update-component-status ==\n",
		"component-kind=twep-catalog-v1\n",
		"component-name=default\n",
		"promotion=blocked-final-verified\n",
	}, []string{
		"teep.trust_anchor_unbound",
		"teep.evidence_unaffirmed",
		"teep.agent_identity_unbound",
	})
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-component-id.cbor"), artifact.ComponentID)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-manifest-sequence-number.txt"), []byte("sequence-number=6\n"))
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-uri.txt"), []byte("payload-uri=#catalog.cbor\n"))
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-0.bin"), catalogPayload)
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-sha256.bin"), artifact.PayloadSHA256[:])
	assertFileBytes(t, filepath.Join(teepAgentDir, "update-payload-hash-status.txt"), []byte("payload-hash=ok\n"))
	assertFileBytes(
		t,
		filepath.Join(teepAgentDir, "update-component-status.txt"),
		[]byte("component-kind=twep-catalog-v1\ncomponent-name=default\npromotion=blocked-final-verified\n"),
	)
	assertVerifiedDryRunSequenceFreshnessUnchanged(t, stateDir, devFreshness, nil)
	assertVerifiedNoPromotion(t, stateDir, "remotehello", "remotehello.wasm")
}

func e2eEnv(t *testing.T) (string, string) {
	t.Helper()
	binDir := os.Getenv("TWEP_E2E_BIN_DIR")
	repoRoot := os.Getenv("TWEP_E2E_REPO_ROOT")
	if binDir == "" || repoRoot == "" {
		t.Skip("set TWEP_E2E_BIN_DIR and TWEP_E2E_REPO_ROOT to run twepd CLI E2E")
	}
	return binDir, repoRoot
}

func unusedLocalHTTPURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr + "/tam"
}

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for socket %s", socketPath)
}

func runAttestamVerifiedDryRun(t *testing.T, ctx context.Context, binDir string, repoRoot string, stateDir string, attestamURL string, command string) {
	t.Helper()
	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-verified",
		"--attestam-url", attestamURL,
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"--socket", socketPath,
		command,
	)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err == nil {
		t.Fatalf("twep-cli succeeded, want teep.verified_required\n%s\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if !strings.Contains(string(cliOut), "teep.verified_required") {
		t.Fatalf("twep-cli output = %q, want teep.verified_required\ntwepd:\n%s", cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd failed: %v\n%s", err, twepdOut.Bytes())
	}
}

func runTwepdCLIOnce(t *testing.T, ctx context.Context, binDir string, repoRoot string, stateDir string, socketPath string, cliArgs []string) []byte {
	t.Helper()
	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--once",
	)
	twepd.Dir = repoRoot
	var twepdOut bytes.Buffer
	twepd.Stdout = &twepdOut
	twepd.Stderr = &twepdOut
	if err := twepd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if twepd.ProcessState == nil {
			_ = twepd.Process.Kill()
			_ = twepd.Wait()
		}
	}()
	waitForSocket(t, socketPath)

	args := append([]string{"--socket", socketPath}, cliArgs...)
	cli := exec.CommandContext(ctx, filepath.Join(binDir, "twep-cli"), args...)
	cli.Dir = repoRoot
	cliOut, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("twep-cli %v failed: %v\n%s\ntwepd:\n%s", cliArgs, err, cliOut, twepdOut.Bytes())
	}
	if err := twepd.Wait(); err != nil {
		t.Fatalf("twepd for %v failed: %v\n%s", cliArgs, err, twepdOut.Bytes())
	}
	return cliOut
}

func assertVerifiedDiagnoseOutput(t *testing.T, ctx context.Context, binDir string, repoRoot string, stateDir string, wantSubstrings []string, wantFinalBlockers []string) {
	t.Helper()
	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"diagnose", "verified",
		"--state-dir", stateDir,
	)
	cli.Dir = repoRoot
	out, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("twep-cli diagnose verified failed: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range wantSubstrings {
		if !strings.Contains(got, want) {
			t.Fatalf("diagnose output missing %q in:\n%s", want, got)
		}
	}

	cli = exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"diagnose", "verified",
		"--state-dir", stateDir,
		"--output-format", "json",
	)
	cli.Dir = repoRoot
	jsonOut, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("twep-cli diagnose verified --output-format json failed: %v\n%s", err, jsonOut)
	}
	assertVerifiedDiagnoseJSON(t, jsonOut, stateDir, wantSubstrings, wantFinalBlockers)
}

func assertVerifiedDiagnoseJSONObservations(t *testing.T, ctx context.Context, binDir string, repoRoot string, stateDir string, wantBound []string, wantMatchedUnbound []string, wantTrustAnchorBlockers []string) {
	t.Helper()
	cli := exec.CommandContext(ctx,
		filepath.Join(binDir, "twep-cli"),
		"diagnose", "verified",
		"--state-dir", stateDir,
		"--output-format", "json",
	)
	cli.Dir = repoRoot
	jsonOut, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("twep-cli diagnose verified --output-format json failed: %v\n%s", err, jsonOut)
	}
	var report verifiedDiagnoseJSON
	if err := json.Unmarshal(jsonOut, &report); err != nil {
		t.Fatalf("decode diagnose JSON: %v\n%s", err, jsonOut)
	}
	if wantBound != nil && !stringSlicesEqual(report.Summary.Bound, wantBound) {
		t.Fatalf("diagnose JSON summary bound = %v, want %v\n%s", report.Summary.Bound, wantBound, jsonOut)
	}
	if wantMatchedUnbound != nil && !stringSlicesEqual(report.Summary.MatchedUnbound, wantMatchedUnbound) {
		t.Fatalf("diagnose JSON summary matched_unbound = %v, want %v\n%s", report.Summary.MatchedUnbound, wantMatchedUnbound, jsonOut)
	}
	if wantTrustAnchorBlockers != nil && !stringSlicesEqual(report.Summary.TrustAnchorBlockers, wantTrustAnchorBlockers) {
		t.Fatalf("diagnose JSON summary trust_anchor_blockers = %v, want %v\n%s", report.Summary.TrustAnchorBlockers, wantTrustAnchorBlockers, jsonOut)
	}
}

type verifiedDiagnoseJSON struct {
	SchemaVersion int    `json:"schema_version"`
	Target        string `json:"target"`
	StateDir      string `json:"state_dir"`
	Summary       struct {
		FixtureVerified     bool     `json:"fixture_verified"`
		FinalVerified       bool     `json:"final_verified"`
		MissingStep         string   `json:"missing_step"`
		FinalMissingStep    string   `json:"final_missing_step"`
		FinalBlockers       []string `json:"final_blockers"`
		TrustAnchorBlockers []string `json:"trust_anchor_blockers"`
		Bound               []string `json:"bound"`
		MatchedUnbound      []string `json:"matched_unbound"`
		SuitAuth            string   `json:"suit_auth"`
		UpdateComponent     *struct {
			ComponentKind string `json:"component_kind"`
			ComponentName string `json:"component_name"`
			Promotion     string `json:"promotion"`
		} `json:"update_component"`
	} `json:"summary"`
	Artifacts []struct {
		Label   string `json:"label"`
		Path    string `json:"path"`
		Missing bool   `json:"missing"`
		Text    string `json:"text"`
	} `json:"artifacts"`
}

func assertVerifiedDiagnoseJSON(t *testing.T, jsonOut []byte, stateDir string, wantSubstrings []string, wantFinalBlockers []string) {
	t.Helper()
	var report verifiedDiagnoseJSON
	if err := json.Unmarshal(jsonOut, &report); err != nil {
		t.Fatalf("decode diagnose JSON: %v\n%s", err, jsonOut)
	}
	if report.SchemaVersion != 1 || report.Target != "verified" || report.StateDir != stateDir {
		t.Fatalf("diagnose JSON metadata = version %d target %q state %q, want version 1 target verified state %q",
			report.SchemaVersion, report.Target, report.StateDir, stateDir)
	}
	if report.Summary.FinalVerified {
		t.Fatalf("diagnose JSON summary final_verified=true, want false\n%s", jsonOut)
	}
	if report.Summary.FinalMissingStep == "" {
		t.Fatalf("diagnose JSON summary missing final_missing_step\n%s", jsonOut)
	}
	wantMissingStep := wantedDiagnosticLineValue(wantSubstrings, "missing-step=")
	if wantMissingStep == "" {
		wantMissingStep = "none"
	}
	if report.Summary.MissingStep != wantMissingStep {
		t.Fatalf("diagnose JSON summary missing_step = %q, want %q\n%s", report.Summary.MissingStep, wantMissingStep, jsonOut)
	}
	if wantFinalMissingStep := wantedDiagnosticLineValue(wantSubstrings, "final-missing-step="); wantFinalMissingStep != "" && report.Summary.FinalMissingStep != wantFinalMissingStep {
		t.Fatalf("diagnose JSON summary final_missing_step = %q, want %q\n%s", report.Summary.FinalMissingStep, wantFinalMissingStep, jsonOut)
	}
	if len(report.Summary.FinalBlockers) == 0 {
		t.Fatalf("diagnose JSON summary missing final_blockers\n%s", jsonOut)
	}
	if !stringSlicesEqual(report.Summary.FinalBlockers, wantFinalBlockers) {
		t.Fatalf("diagnose JSON summary final_blockers = %v, want %v\n%s", report.Summary.FinalBlockers, wantFinalBlockers, jsonOut)
	}
	if report.Summary.Bound == nil {
		t.Fatalf("diagnose JSON summary missing bound\n%s", jsonOut)
	}
	if report.Summary.MatchedUnbound == nil {
		t.Fatalf("diagnose JSON summary missing matched_unbound\n%s", jsonOut)
	}
	if want := wantedDiagnosticLineValue(wantSubstrings, "suit-auth="); want != "" && report.Summary.SuitAuth != want {
		t.Fatalf("diagnose JSON summary suit_auth = %q, want %q\n%s", report.Summary.SuitAuth, want, jsonOut)
	}
	wantComponentKind := wantedDiagnosticLineValue(wantSubstrings, "component-kind=")
	wantComponentName := wantedDiagnosticLineValue(wantSubstrings, "component-name=")
	wantPromotion := wantedDiagnosticLineValue(wantSubstrings, "promotion=")
	if wantComponentKind != "" || wantComponentName != "" || wantPromotion != "" {
		if report.Summary.UpdateComponent == nil {
			t.Fatalf("diagnose JSON summary missing update_component\n%s", jsonOut)
		}
		if report.Summary.UpdateComponent.ComponentKind != wantComponentKind ||
			report.Summary.UpdateComponent.ComponentName != wantComponentName ||
			report.Summary.UpdateComponent.Promotion != wantPromotion {
			t.Fatalf("diagnose JSON summary update_component = %+v, want kind %q name %q promotion %q\n%s",
				*report.Summary.UpdateComponent, wantComponentKind, wantComponentName, wantPromotion, jsonOut)
		}
	}
	wantLabels := []string{"verified-state", "credential-status", "platform-status", "evidence-status", "agent-identity-status", "suit-auth-status", "update-component-status"}
	if len(report.Artifacts) != len(wantLabels) {
		t.Fatalf("diagnose JSON artifacts = %d, want %d\n%s", len(report.Artifacts), len(wantLabels), jsonOut)
	}
	var joined strings.Builder
	hasMissing := false
	for i, wantLabel := range wantLabels {
		artifact := report.Artifacts[i]
		if artifact.Label != wantLabel {
			t.Fatalf("diagnose JSON artifact[%d].label = %q, want %q", i, artifact.Label, wantLabel)
		}
		if artifact.Path == "" {
			t.Fatalf("diagnose JSON artifact[%d].path is empty", i)
		}
		if artifact.Missing {
			hasMissing = true
		}
		joined.WriteString(artifact.Text)
	}
	for _, want := range wantSubstrings {
		if strings.HasPrefix(want, "== ") {
			continue
		}
		if want == "(missing)\n" {
			if !hasMissing {
				t.Fatalf("diagnose JSON has no missing artifact, want one\n%s", jsonOut)
			}
			continue
		}
		if !strings.Contains(joined.String(), want) {
			t.Fatalf("diagnose JSON artifact text missing %q in:\n%s", want, jsonOut)
		}
	}
}

func wantedDiagnosticLineValue(wantSubstrings []string, prefix string) string {
	for _, want := range wantSubstrings {
		if strings.HasPrefix(want, prefix) && strings.HasSuffix(want, "\n") {
			return strings.TrimSuffix(strings.TrimPrefix(want, prefix), "\n")
		}
	}
	return ""
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got := readFileBytes(t, path)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s does not match expected bytes", path)
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

func assertVerifiedNoPromotion(t *testing.T, stateDir string, command string, wasmFile string) {
	t.Helper()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	for _, path := range []string{
		filepath.Join(stateDir, "tmp", "teep-agent-probe"),
		filepath.Join(stateDir, "tmp", "update-payload-0.bin"),
		filepath.Join(stateDir, "tmp", "update-staging-metadata.cbor"),
		filepath.Join(stateDir, "tmp", "update-staging-status.txt"),
		filepath.Join(stateDir, "apps", wasmFile),
		filepath.Join(stateDir, "apps", wasmFile+".tmp"),
		filepath.Join(stateDir, "catalog", "catalog.cbor"),
		filepath.Join(stateDir, "catalog", "catalog.cbor.tmp"),
		filepath.Join(stateDir, "catalog", "catalog.dev.json"),
		filepath.Join(teepAgentDir, "last-teep-response.cose"),
		filepath.Join(teepAgentDir, "last-teep-payload.cbor"),
		filepath.Join(teepAgentDir, "last-teep-message-type.txt"),
		filepath.Join(teepAgentDir, "last-query-response.cose"),
		filepath.Join(teepAgentDir, "last-query-response-status.txt"),
		filepath.Join(teepAgentDir, "last-query-response-body.cose"),
		filepath.Join(teepAgentDir, "last-query-response-body-payload.cbor"),
		filepath.Join(teepAgentDir, "last-query-response-body-message-type.txt"),
		filepath.Join(teepAgentDir, "success-payload.cbor"),
		filepath.Join(teepAgentDir, "success.cose"),
		filepath.Join(teepAgentDir, "success-status.txt"),
		filepath.Join(teepAgentDir, "last-session-result.txt"),
	} {
		assertPathMissing(t, path)
	}
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.cbor"), command, wasmFile)
	assertCatalogDoesNotReference(t, filepath.Join(stateDir, "catalog", "catalog.dev.json"), command, wasmFile)
}

func assertVerifiedDryRunSequenceFreshnessUnchanged(t *testing.T, stateDir string, devFreshness []byte, protectedFreshness []byte) {
	t.Helper()
	devPath := filepath.Join(stateDir, "teep-agent", "dev-sequence-freshness.cbor")
	protectedPath := filepath.Join(stateDir, "platform", "linux", "sealed", "protected-sequence-freshness.cbor")
	if devFreshness == nil {
		assertPathMissing(t, devPath)
	} else {
		assertFileBytes(t, devPath, devFreshness)
	}
	if protectedFreshness == nil {
		assertPathMissing(t, protectedPath)
	} else {
		assertFileBytes(t, protectedPath, protectedFreshness)
	}
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

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s stat error = %v, want not exist", path, err)
	}
}

func assertInventoryCBOR(t *testing.T, input []byte) {
	t.Helper()
	var got map[string]any
	if err := cbor.Unmarshal(input, &got); err != nil {
		t.Fatalf("decode tc-inventory cbor: %v\n%x", err, input)
	}
	assertCBORUint(t, got, "schema_version", 1)
	assertCBORUint(t, got, "sequence_number", 0)
	assertCBORUint(t, got, "size", uint64(len(fixtureSUITPayload())))
	assertCBORText(t, got, "payload_uri", "#hello.txt")
	assertCBORText(t, got, "payload_file", "components/hello.txt")
	assertCBORText(t, got, "payload_hash_status", "ok")
	assertCBORText(t, got, "status", "install=ready")
	if !bytes.Equal(cborBytesValue(t, got, "component_id_cbor"), fixtureSUITComponentID()) {
		t.Fatalf("component_id_cbor mismatch")
	}
	if !bytes.Equal(cborBytesValue(t, got, "payload_sha256"), fixtureSUITPayloadDigestBytes()) {
		t.Fatalf("payload_sha256 mismatch")
	}
}

func assertCBORUint(t *testing.T, got map[string]any, key string, want uint64) {
	t.Helper()
	value, ok := got[key].(uint64)
	if !ok || value != want {
		t.Fatalf("%s = %#v, want %d", key, got[key], want)
	}
}

func assertCBORText(t *testing.T, got map[string]any, key string, want string) {
	t.Helper()
	value, ok := got[key].(string)
	if !ok || value != want {
		t.Fatalf("%s = %#v, want %q", key, got[key], want)
	}
}

func cborBytesValue(t *testing.T, got map[string]any, key string) []byte {
	t.Helper()
	value, ok := got[key].([]byte)
	if !ok {
		t.Fatalf("%s = %#v, want bytes", key, got[key])
	}
	return value
}

// assertLinuxAttestamInsecureEvidenceObservation validates the explicitly
// insecure install flow. Generation zero is never a verified-mode acceptance.
func assertLinuxAttestamInsecureEvidenceObservation(t *testing.T, path string) {
	t.Helper()
	bytes := readFileBytes(t, path)
	var got map[string]any
	if err := cbor.Unmarshal(bytes, &got); err != nil {
		t.Fatalf("decode %s: %v", path, err)
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
			t.Fatalf("%s = %#v, want %#v in %s", key, got[key], wantValue, path)
		}
	}
	for _, legacyKey := range []string{"verifier_result", "nonce_match", "cnf_key_match", "platform_match"} {
		if _, ok := got[legacyKey]; ok {
			t.Fatalf("%s present in Linux AttesTAM evidence observation", legacyKey)
		}
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

func cborText(value string) []byte {
	out := []byte{}
	if len(value) < 24 {
		out = append(out, 0x60|byte(len(value)))
	} else {
		out = append(out, 0x78, byte(len(value)))
	}
	return append(out, []byte(value)...)
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

func cborMap(out []byte, n int) []byte {
	if n < 24 {
		return append(out, 0xa0|byte(n))
	}
	return append(out, 0xb8, byte(n))
}

func cborArray(out []byte, n int) []byte {
	if n < 24 {
		return append(out, 0x80|byte(n))
	}
	return append(out, 0x98, byte(n))
}

func cborBool(out []byte, value bool) []byte {
	if value {
		return append(out, 0xf5)
	}
	return append(out, 0xf4)
}

func writeVerifiedInputUpdate(t *testing.T, stateDir string, coseUpdate []byte, token []byte) {
	t.Helper()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-input.cose"), coseUpdate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teepAgentDir, "verified-expected-token.bin"), token, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeDevSequenceFreshness(t *testing.T, stateDir string, componentID []byte, lastSequence uint64) []byte {
	t.Helper()
	teepAgentDir := filepath.Join(stateDir, "teep-agent")
	if err := os.MkdirAll(teepAgentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	devFreshness := cborMap(nil, 1)
	devFreshness = append(devFreshness, cborBstr(componentID)...)
	devFreshness = cborUint(devFreshness, lastSequence)
	if err := os.WriteFile(filepath.Join(teepAgentDir, "dev-sequence-freshness.cbor"), devFreshness, 0o600); err != nil {
		t.Fatal(err)
	}
	return devFreshness
}

func writeProtectedCredentialPolicy(t *testing.T, stateDir string, attestamKID []byte, issuerID []byte, maxStoreEpoch uint64, revokedEntryID []byte) {
	t.Helper()
	sealedDir := filepath.Join(stateDir, "platform", "linux", "sealed")
	if err := os.MkdirAll(sealedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile := func(name string, contents []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(sealedDir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("protected-credential-store.cbor", protectedCredentialStoreCBOR(attestamKID))
	writeFile("protected-issuer-allowlist.cbor", platformIssuerAllowlistCBORFor(issuerID))
	writeFile("protected-store-freshness.cbor", platformStoreFreshnessCBORFor(maxStoreEpoch))
	writeFile("protected-revocation-state.cbor", platformRevocationStateCBORFor(revokedEntryID))
}

func protectedCredentialStoreCBOR(attestamKID []byte) []byte {
	var out []byte
	out = cborMap(out, 4)
	out = append(out, cborText("schema_version")...)
	out = cborUint(out, 1)
	out = append(out, cborText("store_epoch")...)
	out = cborUint(out, 1)
	out = append(out, cborText("attestam_message_verification_keys")...)
	out = cborArray(out, 1)
	out = protectedPublicKeyCredential(out, "tam-entry", attestamKID, "attestam-message-verification")
	out = append(out, cborText("suit_content_verification_keys")...)
	out = cborArray(out, 1)
	out = protectedPublicKeyCredential(out, "suit-entry", []byte("suit-key"), "suit-content-verification")
	return out
}

func platformIssuerAllowlistCBORFor(issuerID []byte) []byte {
	var out []byte
	out = cborMap(out, 2)
	out = append(out, cborText("schema_version")...)
	out = cborUint(out, 1)
	out = append(out, cborText("issuer_ids")...)
	out = cborArray(out, 1)
	out = append(out, cborBstr(issuerID)...)
	return out
}

func platformStoreFreshnessCBORFor(maxEpoch uint64) []byte {
	var out []byte
	out = cborMap(out, 2)
	out = append(out, cborText("schema_version")...)
	out = cborUint(out, 1)
	out = append(out, cborText("max_store_epoch")...)
	out = cborUint(out, maxEpoch)
	return out
}

func platformRevocationStateCBORFor(entryID []byte) []byte {
	var out []byte
	out = cborMap(out, 2)
	out = append(out, cborText("schema_version")...)
	out = cborUint(out, 1)
	out = append(out, cborText("revoked_entry_ids")...)
	out = cborArray(out, 1)
	out = append(out, cborBstr(entryID)...)
	return out
}

func protectedPublicKeyCredential(out []byte, entryID string, kid []byte, purpose string) []byte {
	x := bytes.Repeat([]byte{0x08}, 32)
	y := bytes.Repeat([]byte{0x08}, 32)
	if purpose == "attestam-message-verification" {
		x, y = demoTAMPublicCoordinates()
	}
	out = cborMap(out, 11)
	out = append(out, cborText("entry_id")...)
	out = append(out, cborBstr([]byte(entryID))...)
	out = append(out, cborText("issuer_id")...)
	out = append(out, cborBstr([]byte("issuer"))...)
	out = append(out, cborText("kid")...)
	out = append(out, cborBstr(kid)...)
	out = append(out, cborText("purpose")...)
	out = append(out, cborText(purpose)...)
	out = append(out, cborText("alg")...)
	out = append(out, cborText("ESP256")...)
	out = append(out, cborText("crv")...)
	out = append(out, cborText("P-256")...)
	out = append(out, cborText("not_before")...)
	out = cborUint(out, 1)
	out = append(out, cborText("not_after")...)
	out = cborUint(out, 2)
	out = append(out, cborText("provisioning_epoch")...)
	out = cborUint(out, 1)
	out = append(out, cborText("x")...)
	out = append(out, cborBstr(x)...)
	out = append(out, cborText("y")...)
	out = append(out, cborBstr(y)...)
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
	return fixtureUpdateMetadataFor(fixtureSUITComponentID(), 0, "#hello.txt", payloadFile, fixtureSUITPayloadDigestBytes())
}

func fixtureUpdateMetadataFor(componentID []byte, sequenceNumber uint64, payloadURI string, payloadFile string, payloadSHA256 []byte) []byte {
	out := []byte{0xa6}
	out = append(out, cborText("schema_version")...)
	out = append(out, 0x01)
	out = append(out, cborText("component_id_cbor")...)
	out = append(out, cborBstr(componentID)...)
	out = append(out, cborText("sequence_number")...)
	out = cborUint(out, sequenceNumber)
	out = append(out, cborText("payload_uri")...)
	out = append(out, cborText(payloadURI)...)
	out = append(out, cborText("payload_file")...)
	out = append(out, cborText(payloadFile)...)
	out = append(out, cborText("payload_sha256")...)
	out = append(out, cborBstr(payloadSHA256)...)
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
	out = append(out, cborText("")...)
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
	return fixtureSUITManifestFor(fixtureSUITComponentID(), "#hello.txt", fixtureSUITPayload(), fixtureSUITPayloadDigestBytes(), nil)
}

func fixtureSUITManifestFor(componentID []byte, payloadURI string, payload []byte, payloadSHA256 []byte, appMetadata []byte) []byte {
	payloadDigest := append([]byte{0x82, 0x2f}, cborBstr(payloadSHA256)...)
	sharedSequence := append([]byte{0x82, 0x14, 0xa1, 0x03}, cborBstr(payloadDigest)...)
	common := append([]byte{0xa2, 0x02, 0x81}, componentID...)
	common = append(common, 0x04)
	common = append(common, cborBstr(sharedSequence)...)
	payloadFetch := []byte{0x82, 0x14, 0xa1, 0x15}
	payloadFetch = append(payloadFetch, cborText(payloadURI)...)
	manifest := []byte{0xa3, 0x02, 0x00, 0x03}
	manifest = append(manifest, cborBstr(common)...)
	manifest = append(manifest, 0x10)
	manifest = append(manifest, cborBstr(payloadFetch)...)
	authWrapper := []byte{0x82}
	authWrapper = append(authWrapper, cborBstr(fixtureSUITManifestDigest())...)
	authWrapper = append(authWrapper, cborBstr([]byte{0})...)
	pairs := byte(3)
	if appMetadata != nil {
		pairs = 4
	}
	envelope := []byte{0xd8, 0x6b, 0xa0 | pairs, 0x02}
	envelope = append(envelope, cborBstr(authWrapper)...)
	envelope = append(envelope, 0x03)
	envelope = append(envelope, cborBstr(manifest)...)
	envelope = append(envelope, cborText(payloadURI)...)
	envelope = append(envelope, cborBstr(payload)...)
	if appMetadata != nil {
		envelope = append(envelope, cborText("twep-app-v1-metadata")...)
		envelope = append(envelope, cborBstr(appMetadata)...)
	}
	return envelope
}

func fixtureAppInstallMetadata(command string, componentID string, wasmFile string) []byte {
	return fixtureAppInstallMetadataWithABI(command, componentID, wasmFile, "twep-app-v1")
}

func fixtureAppInstallMetadataWithABI(command string, componentID string, wasmFile string, abi string) []byte {
	out := []byte{0xa6}
	out = append(out, cborText("schema_version")...)
	out = append(out, 0x01)
	out = append(out, cborText("command")...)
	out = append(out, cborText(command)...)
	out = append(out, cborText("component_id")...)
	out = append(out, cborText(componentID)...)
	out = append(out, cborText("version")...)
	out = append(out, cborText("0.1.0")...)
	out = append(out, cborText("abi")...)
	out = append(out, cborText(abi)...)
	out = append(out, cborText("wasm_file")...)
	out = append(out, cborText(wasmFile)...)
	return out
}

func assertPromotedCatalogEntry(t *testing.T, path string, command string, wasmFile string, sha256Bytes []byte) {
	t.Helper()
	got := readFileBytes(t, path)
	var catalog map[any]any
	if err := cbor.Unmarshal(got, &catalog); err != nil {
		t.Fatalf("decode promoted catalog: %v\n%x", err, got)
	}
	apps, ok := catalog["apps"].(map[any]any)
	if !ok {
		t.Fatalf("catalog apps = %#v, want map", catalog["apps"])
	}
	app, ok := apps[command].(map[any]any)
	if !ok {
		t.Fatalf("catalog app %q = %#v, want map", command, apps[command])
	}
	assertAnyCBORText(t, app, "abi", "twep-app-v1")
	assertAnyCBORText(t, app, "wasm_file", wasmFile)
	if !bytes.Equal(anyCBORBytesValue(t, app, "sha256"), sha256Bytes) {
		t.Fatalf("catalog sha256 mismatch")
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
			t.Fatalf("%s references rejected app value %q", path, value)
		}
	}
}

func assertAnyCBORText(t *testing.T, got map[any]any, key string, want string) {
	t.Helper()
	value, ok := got[key].(string)
	if !ok || value != want {
		t.Fatalf("%s = %#v, want %q", key, got[key], want)
	}
}

func anyCBORBytesValue(t *testing.T, got map[any]any, key string) []byte {
	t.Helper()
	value, ok := got[key].([]byte)
	if !ok {
		t.Fatalf("%s = %#v, want bytes", key, got[key])
	}
	return value
}
