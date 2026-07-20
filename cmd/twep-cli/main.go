// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/s-miyazawa/twep-system/internal/cborcodec"
	"github.com/s-miyazawa/twep-system/internal/cliargs"
	"github.com/s-miyazawa/twep-system/internal/ipc"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("twep-cli", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	socketPath := fs.String("socket", defaultSocketPath(), "twepd Unix domain socket path")
	cborHex := fs.String("cbor-hex", "", "CBOR app input as hex")
	cborFile := fs.String("cbor-file", "", "CBOR app input file")
	outputFormat := fs.String("output-format", "", "response output format, e.g. cbor for tc-inventory")
	help := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help || fs.NArg() == 0 {
		fs.Usage()
		return nil
	}
	if fs.Arg(0) == "diagnose" {
		return runDiagnose(fs.Args()[1:], os.Stdout, *outputFormat)
	}
	built, err := cliargs.BuildRequest(fs.Arg(0), fs.Args()[1:], *cborHex, *cborFile, *outputFormat)
	if err != nil {
		return fmt.Errorf("cli.usage: %w", err)
	}
	reqBytes, err := cborcodec.EncodeRequest(built.Request)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	conn, err := net.Dial("unix", *socketPath)
	if err != nil {
		return fmt.Errorf("ipc.connect: %w", err)
	}
	defer conn.Close()
	if err := ipc.WriteFrame(conn, reqBytes, ipc.DefaultMaxFrameBytes); err != nil {
		return fmt.Errorf("ipc.protocol: %w", err)
	}
	respBytes, err := ipc.ReadFrame(conn, ipc.DefaultMaxFrameBytes)
	if err != nil {
		return fmt.Errorf("ipc.protocol: %w", err)
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(resp.Stderr) != 0 {
		fmt.Fprint(os.Stderr, string(resp.Stderr))
	}
	if resp.Status == "error" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("daemon.request: unknown error")
	}
	if len(resp.Stdout) != 0 {
		fmt.Print(string(resp.Stdout))
	}
	if built.OutputPath != "" {
		if err := writeAppOutputFile(resp.AppOutput, built.OutputPath); err != nil {
			return err
		}
	}
	if resp.ExitCode != 0 {
		os.Exit(resp.ExitCode)
	}
	return nil
}

func runDiagnose(args []string, stdout io.Writer, outputFormat string) error {
	if len(args) == 0 {
		return fmt.Errorf("diagnose requires a target")
	}
	switch args[0] {
	case "verified":
		return runDiagnoseVerified(args[1:], stdout, outputFormat)
	default:
		return fmt.Errorf("unsupported diagnose target %q", args[0])
	}
}

func runDiagnoseVerified(args []string, stdout io.Writer, inheritedOutputFormat string) error {
	fs := flag.NewFlagSet("twep-cli diagnose verified", flag.ContinueOnError)
	fs.SetOutput(stdout)
	stateDir := fs.String("state-dir", defaultStateDir(), "twep state directory")
	outputFormat := fs.String("output-format", inheritedOutputFormat, "diagnostic output format: text or json")
	help := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.Usage()
		return nil
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("diagnose verified does not accept positional arguments")
	}
	report, err := buildVerifiedDiagnosticReport(*stateDir)
	if err != nil {
		return err
	}
	switch *outputFormat {
	case "", "text":
		return writeVerifiedDiagnosticText(stdout, report)
	case "json":
		return writeVerifiedDiagnosticJSON(stdout, report)
	default:
		return fmt.Errorf("unsupported diagnose output format %q", *outputFormat)
	}
}

type diagnosticArtifact struct {
	label string
	path  string
}

type diagnosticReport struct {
	SchemaVersion int                          `json:"schema_version"`
	Target        string                       `json:"target"`
	StateDir      string                       `json:"state_dir"`
	Summary       verifiedDiagnosticSummary    `json:"summary"`
	Artifacts     []diagnosticArtifactSnapshot `json:"artifacts"`
}

type verifiedDiagnosticSummary struct {
	FixtureVerified     bool                               `json:"fixture_verified"`
	FinalVerified       bool                               `json:"final_verified"`
	MissingStep         string                             `json:"missing_step,omitempty"`
	FinalMissingStep    string                             `json:"final_missing_step,omitempty"`
	FinalBlockers       []string                           `json:"final_blockers"`
	TrustAnchorBlockers []string                           `json:"trust_anchor_blockers"`
	Bound               []string                           `json:"bound"`
	MatchedUnbound      []string                           `json:"matched_unbound"`
	SuitAuth            string                             `json:"suit_auth,omitempty"`
	UpdateComponent     *verifiedUpdateComponentDiagnostic `json:"update_component,omitempty"`
}

type verifiedUpdateComponentDiagnostic struct {
	ComponentKind string `json:"component_kind,omitempty"`
	ComponentName string `json:"component_name,omitempty"`
	Promotion     string `json:"promotion,omitempty"`
}

type diagnosticArtifactSnapshot struct {
	Label   string `json:"label"`
	Path    string `json:"path"`
	Missing bool   `json:"missing"`
	Text    string `json:"text,omitempty"`
}

func verifiedDiagnosticArtifacts() []diagnosticArtifact {
	return []diagnosticArtifact{
		{label: "verified-state", path: filepath.Join("teep-agent", "verified-state.txt")},
		{label: "credential-status", path: filepath.Join("teep-agent", "credential-status.txt")},
		{label: "platform-status", path: filepath.Join("teep-agent", "platform-status.txt")},
		{label: "evidence-status", path: filepath.Join("teep-agent", "evidence-status.txt")},
		{label: "agent-identity-status", path: filepath.Join("teep-agent", "agent-identity-status.txt")},
		{label: "suit-auth-status", path: filepath.Join("teep-agent", "suit-auth-status.txt")},
		{label: "update-component-status", path: filepath.Join("teep-agent", "update-component-status.txt")},
	}
}

func buildVerifiedDiagnosticReport(stateDir string) (diagnosticReport, error) {
	report := diagnosticReport{
		SchemaVersion: 1,
		Target:        "verified",
		StateDir:      stateDir,
	}
	for _, artifact := range verifiedDiagnosticArtifacts() {
		snapshot := diagnosticArtifactSnapshot{
			Label: artifact.label,
			Path:  artifact.path,
		}
		bytes, err := os.ReadFile(filepath.Join(stateDir, artifact.path))
		if os.IsNotExist(err) {
			snapshot.Missing = true
			report.Artifacts = append(report.Artifacts, snapshot)
			continue
		}
		if err != nil {
			return diagnosticReport{}, fmt.Errorf("read %s: %w", artifact.path, err)
		}
		snapshot.Text = string(bytes)
		report.Artifacts = append(report.Artifacts, snapshot)
	}
	report.Summary = buildVerifiedDiagnosticSummary(report.Artifacts)
	return report, nil
}

func buildVerifiedDiagnosticSummary(artifacts []diagnosticArtifactSnapshot) verifiedDiagnosticSummary {
	values := map[string]string{}
	for _, artifact := range artifacts {
		if artifact.Missing {
			continue
		}
		for key, value := range parseDiagnosticStatusLines(artifact.Text) {
			values[key] = value
		}
	}
	summary := verifiedDiagnosticSummary{
		FixtureVerified:  values["fixture-verified"] == "true",
		FinalVerified:    values["final-verified"] == "true",
		MissingStep:      values["missing-step"],
		FinalMissingStep: values["final-missing-step"],
	}
	if summary.MissingStep != "" && summary.MissingStep != "none" {
		summary.FinalBlockers = append(summary.FinalBlockers, summary.MissingStep)
	} else {
		if values["trust-anchor-bound"] == "false" {
			summary.FinalBlockers = append(summary.FinalBlockers, "teep.trust_anchor_unbound")
		}
		if values["evidence-affirming"] == "false" {
			summary.FinalBlockers = append(summary.FinalBlockers, "teep.evidence_unaffirmed")
		}
		if values["agent-identity-bound"] == "false" {
			summary.FinalBlockers = append(summary.FinalBlockers, "teep.agent_identity_unbound")
		}
		if values["credential-model-ready"] == "false" {
			summary.FinalBlockers = append(summary.FinalBlockers, "teep.credential_model_unready")
		}
	}
	if summary.FinalBlockers == nil {
		summary.FinalBlockers = []string{}
	}
	summary.TrustAnchorBlockers = verifiedTrustAnchorBlockers(values)
	summary.Bound = verifiedBoundObservations(values)
	summary.MatchedUnbound = verifiedMatchedUnboundObservations(values)
	summary.SuitAuth = values["suit-auth"]
	summary.UpdateComponent = verifiedUpdateComponentObservation(values)
	return summary
}

func verifiedTrustAnchorBlockers(values map[string]string) []string {
	if values["trust-anchor-bound"] == "true" {
		return []string{}
	}
	var blockers []string
	if values["credential-model-ready"] == "false" {
		blockers = append(blockers, "teep.credential_model_unready")
	}
	if values["protected-credential-store-bound"] == "false" {
		blockers = append(blockers, "teep.protected_credential_store_unbound")
	}
	if values["issuer-allowlist-bound"] == "false" {
		blockers = append(blockers, "teep.issuer_allowlist_unbound")
	}
	if values["store-freshness-bound"] == "false" {
		blockers = append(blockers, "teep.store_freshness_unbound")
	}
	if values["revocation-state-bound"] == "false" {
		blockers = append(blockers, "teep.revocation_state_unbound")
	}
	if blockers == nil {
		return []string{}
	}
	return blockers
}

func verifiedUpdateComponentObservation(values map[string]string) *verifiedUpdateComponentDiagnostic {
	componentKind := values["component-kind"]
	componentName := values["component-name"]
	promotion := values["promotion"]
	if componentKind == "" && componentName == "" && promotion == "" {
		return nil
	}
	return &verifiedUpdateComponentDiagnostic{
		ComponentKind: componentKind,
		ComponentName: componentName,
		Promotion:     promotion,
	}
}

func verifiedBoundObservations(values map[string]string) []string {
	var bound []string
	if values["protected-credential-store-bound"] == "true" {
		bound = append(bound, "teep.protected_credential_store_bound")
	}
	if values["issuer-allowlist-bound"] == "true" {
		bound = append(bound, "teep.issuer_allowlist_bound")
	}
	if values["store-freshness-bound"] == "true" {
		bound = append(bound, "teep.store_freshness_bound")
	}
	if values["revocation-state-bound"] == "true" {
		bound = append(bound, "teep.revocation_state_bound")
	}
	if values["trust-anchor-bound"] == "true" {
		bound = append(bound, "teep.trust_anchor_bound")
	}
	if values["evidence-affirming"] == "true" {
		bound = append(bound, "teep.evidence_affirming")
	}
	if values["agent-identity-bound"] == "true" {
		bound = append(bound, "teep.agent_identity_bound")
	}
	if bound == nil {
		return []string{}
	}
	return bound
}

func verifiedMatchedUnboundObservations(values map[string]string) []string {
	var matched []string
	if values["protected-credential-store-rotation-policy"] == "matched-unbound" {
		matched = append(matched, "teep.credential_rotation_matched_unbound")
	}
	if values["protected-credential-store-revocation-status"] == "matched-unbound" {
		matched = append(matched, "teep.revocation_state_matched_unbound")
	}
	if values["protected-credential-store-freshness"] == "matched-unbound" {
		matched = append(matched, "teep.store_freshness_matched_unbound")
	}
	if values["evidence-binding"] == "matched-unbound" {
		matched = append(matched, "teep.evidence_matched_unbound")
	}
	if values["agent-identity-binding"] == "matched-unbound" {
		matched = append(matched, "teep.agent_identity_matched_unbound")
	}
	if matched == nil {
		return []string{}
	}
	return matched
}

func parseDiagnosticStatusLines(text string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		values[key] = value
	}
	return values
}

func writeVerifiedDiagnosticText(stdout io.Writer, report diagnosticReport) error {
	for _, artifact := range report.Artifacts {
		if _, err := fmt.Fprintf(stdout, "== %s ==\n", artifact.Label); err != nil {
			return err
		}
		if artifact.Missing {
			if _, err := fmt.Fprintln(stdout, "(missing)"); err != nil {
				return err
			}
			continue
		}
		if _, err := io.WriteString(stdout, artifact.Text); err != nil {
			return err
		}
		if artifact.Text == "" || artifact.Text[len(artifact.Text)-1] != '\n' {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeVerifiedDiagnosticJSON(stdout io.Writer, report diagnosticReport) error {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func writeAppOutputFile(appOutput []byte, outputPath string) error {
	out, err := cborcodec.DecodeAppOutput(appOutput)
	if err != nil {
		return fmt.Errorf("decode app output: %w", err)
	}
	if out.Status != "ok" {
		if out.Error != nil {
			return fmt.Errorf("%s: %s", out.Error.Code, out.Error.Message)
		}
		return fmt.Errorf("app output status %q", out.Status)
	}
	outputBytes := out.Files["output"]
	if len(outputBytes) == 0 {
		return fmt.Errorf("app output missing files.output")
	}
	if mime, _ := out.Metadata["output_mime"].(string); mime != "image/jpeg" {
		return fmt.Errorf("app output mime %q is not image/jpeg", mime)
	}
	if err := atomicWriteFile(outputPath, outputBytes, 0o600); err != nil {
		return fmt.Errorf("write output JPEG: %w", err)
	}
	return nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if strings.ContainsRune(base, 0) {
		return fmt.Errorf("output path is invalid")
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func defaultSocketPath() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "twep", "twepd.sock")
}

func defaultStateDir() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			base = filepath.Join(home, ".local", "state")
		} else {
			base = os.TempDir()
		}
	}
	return filepath.Join(base, "twep")
}
