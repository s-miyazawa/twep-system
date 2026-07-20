// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cliargs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildRequestNegaPosiFilesInput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.jpg")
	output := filepath.Join(dir, "output.jpg")
	if err := os.WriteFile(input, []byte{0xff, 0xd8, 0xff, 0xd9}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := BuildRequest("negaposi", []string{"-i", input, "-o", output}, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.OutputPath != output {
		t.Fatalf("OutputPath = %q, want %q", got.OutputPath, output)
	}
	if string(got.Request.Files["input"]) != string([]byte{0xff, 0xd8, 0xff, 0xd9}) {
		t.Fatalf("files.input not populated")
	}
	if got.Request.Metadata["input_mime"] != "image/jpeg" {
		t.Fatalf("metadata.input_mime = %v", got.Request.Metadata["input_mime"])
	}
}

func TestBuildRequestNegaPosiRejectsNonJPEGOutputPath(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.jpg")
	if err := os.WriteFile(input, []byte{0xff, 0xd8, 0xff, 0xd9}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRequest("negaposi", []string{"-i", input, "-o", filepath.Join(dir, "output.png")}, "", "", ""); err == nil {
		t.Fatal("BuildRequest succeeded, want error")
	}
}

func TestBuildRequestNegaPosiValidatesInputBeforeRead(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.png")
	if err := os.WriteFile(input, []byte{0xff, 0xd8, 0xff, 0xd9}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRequest("negaposi", []string{"-i", input, "-o", filepath.Join(dir, "output.jpg")}, "", "", ""); err == nil {
		t.Fatal("BuildRequest succeeded, want extension error")
	}
}

func TestBuildRequestNegaPosiRejectsLargeInput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.jpg")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxNegaPosiInputBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRequest("negaposi", []string{"-i", input, "-o", filepath.Join(dir, "output.jpg")}, "", "", ""); err == nil {
		t.Fatal("BuildRequest succeeded, want size error")
	}
}

func TestBuildRequestNegaPosiRejectsNonJPEGBytes(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.jpg")
	if err := os.WriteFile(input, []byte("not jpeg"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRequest("negaposi", []string{"-i", input, "-o", filepath.Join(dir, "output.jpg")}, "", "", ""); err == nil {
		t.Fatal("BuildRequest succeeded, want JPEG magic error")
	}
}

func TestBuildRequestOutputFormat(t *testing.T) {
	got, err := BuildRequest("tc-inventory", nil, "", "", "cbor")
	if err != nil {
		t.Fatal(err)
	}
	if got.Request.Options.OutputFormat != "cbor" {
		t.Fatalf("OutputFormat = %q, want cbor", got.Request.Options.OutputFormat)
	}
}
