// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAttestamLiveChallengeResponseUpdate(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)
	attestamURL := getenvOrSkip(t, "ATTESTAM_URL")
	attestamRegisterURL := getenvOrSkip(t, "ATTESTAM_REGISTER_URL")
	veraisonProvisionURL := getenvOrSkip(t, "VERAISON_PROVISION_URL")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	runMakeForLiveAttestam(t, ctx, repoRoot, "provision-veraison-generic-eat-fixture", map[string]string{
		"VERAISON_PROVISION_URL": veraisonProvisionURL,
	})
	runMakeForLiveAttestam(t, ctx, repoRoot, "register-attestam-helloworld-fixture", map[string]string{
		"ATTESTAM_REGISTER_URL": attestamRegisterURL,
	})

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "run", "twepd.sock")
	twepd := exec.CommandContext(ctx,
		filepath.Join(binDir, "twepd"),
		"--socket", socketPath,
		"--state-dir", stateDir,
		"--resolver-mode", "attestam-insecure",
		"--attestam-url", attestamURL,
		"--insecure-demo-mode",
		"--insecure-demo-agent-key", "alternate",
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

	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-attestation-query-response-status.txt"), []byte("host-status=ok\n"))
	assertLinuxAttestamInsecureEvidenceObservation(t, filepath.Join(stateDir, "teep-agent", "verified-evidence-result.cbor"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "update-payload-hash-status.txt"), []byte("payload-hash=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "success-status.txt"), []byte("host-status=ok\n"))
	assertFileBytes(t, filepath.Join(stateDir, "teep-agent", "last-session-result.txt"), []byte("session-result=no-content\n"))
	if _, err := os.Stat(filepath.Join(stateDir, "apps", "helloworld.wasm")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "catalog", "catalog.cbor.tmp")); !os.IsNotExist(err) {
		t.Fatalf("catalog.cbor.tmp stat error = %v, want not exist", err)
	}
}

func getenvOrSkip(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Skipf("set %s to run live AttesTAM/Veraison E2E", key)
	}
	return value
}

func runMakeForLiveAttestam(t *testing.T, ctx context.Context, repoRoot string, target string, env map[string]string) {
	t.Helper()
	args := []string{target}
	for key, value := range env {
		args = append(args, key+"="+value)
	}
	cmd := exec.CommandContext(ctx, "make", args...)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make %s failed: %v\n%s", target, err, out)
	}
}
