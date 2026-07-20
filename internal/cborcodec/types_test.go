// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cborcodec

import "testing"

func TestRequestRoundTrip(t *testing.T) {
	req := Request{
		SchemaVersion: SchemaVersion,
		RequestID:     "r1",
		Command:       "calcadd",
		Argv:          []string{"3", "4", "5"},
		Inferred:      InferArgv([]string{"3", "4", "5"}),
		Files:         map[string][]byte{"input": []byte("jpeg")},
		Metadata:      map[string]any{"input_mime": "image/jpeg"},
		Cwd:           "/tmp",
		Options: RequestOptions{
			OutputFormat: "cbor",
			Verbose:      true,
		},
	}
	b, err := EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != "calcadd" || len(got.Inferred) != 3 {
		t.Fatalf("unexpected roundtrip: %+v", got)
	}
	if string(got.Files["input"]) != "jpeg" || got.Metadata["input_mime"] != "image/jpeg" {
		t.Fatalf("binary fields did not roundtrip: %+v", got)
	}
	if got.Options.OutputFormat != "cbor" || !got.Options.Verbose {
		t.Fatalf("options did not roundtrip: %+v", got.Options)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	resp := Response{
		SchemaVersion: SchemaVersion,
		RequestID:     "r1",
		Status:        "error",
		Stdout:        []byte("Hello, World!!\n"),
		Result:        map[string]any{"answer": uint64(42)},
		Error: &TwepError{
			Code:    "app.output_generation",
			Message: "output generation error",
			Details: map[string]any{
				"return_code": uint64(3),
				"command":     "calcadd",
				"wasm_file":   "calcadd.wasm",
			},
		},
	}
	b, err := EncodeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Stdout) != "Hello, World!!\n" {
		t.Fatalf("stdout = %q", got.Stdout)
	}
	result, ok := got.Result.(map[string]any)
	if !ok || result["answer"] != uint64(42) {
		t.Fatalf("result = %#v", got.Result)
	}
	if got.Error == nil {
		t.Fatalf("error details = %#v", got.Error)
	}
	details, ok := got.Error.Details.(map[string]any)
	if !ok || details["return_code"] != uint64(3) || details["wasm_file"] != "calcadd.wasm" {
		t.Fatalf("error details = %#v", got.Error)
	}
}

func TestBuildAppInputPassThrough(t *testing.T) {
	appInput := []byte{0xa1, 0x63, 'f', 'o', 'o', 0x01}
	got, err := BuildAppInput(Request{
		SchemaVersion: SchemaVersion,
		RequestID:     "r1",
		Command:       "helloworld",
		AppInput:      appInput,
		Cwd:           "/tmp",
		Options:       RequestOptions{TimeoutMS: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(appInput) {
		t.Fatalf("BuildAppInput changed app_input: %x", got)
	}
}

func TestBuildAppInputConstructedSchema(t *testing.T) {
	got, err := BuildAppInput(Request{
		SchemaVersion: SchemaVersion,
		RequestID:     "r1",
		Command:       "calcadd",
		Argv:          []string{"3", "4"},
		Inferred:      InferArgv([]string{"3", "4"}),
		Stdin:         []byte("stdin"),
		Files:         map[string][]byte{"input": []byte("jpeg")},
		Metadata:      map[string]any{"input_mime": "image/jpeg"},
		Cwd:           "/tmp",
		Options:       RequestOptions{TimeoutMS: 1, Verbose: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeValue(got)
	if err != nil {
		t.Fatal(err)
	}
	m := decoded.(map[string]any)
	for _, forbidden := range []string{"request_id", "cwd", "options", "app_input"} {
		if _, ok := m[forbidden]; ok {
			t.Fatalf("constructed app input contains %q: %#v", forbidden, m)
		}
	}
	if m["command"] != "calcadd" || string(m["stdin"].([]byte)) != "stdin" {
		t.Fatalf("constructed app input = %#v", m)
	}
}

func TestDecodeAppOutputFiles(t *testing.T) {
	b, err := encodeValue(map[string]any{
		"schema_version": uint64(SchemaVersion),
		"status":         "ok",
		"files":          map[string]any{"output": []byte("jpeg")},
		"metadata":       map[string]any{"output_mime": "image/jpeg"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAppOutput(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Files["output"]) != "jpeg" {
		t.Fatalf("files.output = %q", got.Files["output"])
	}
	if got.Metadata["output_mime"] != "image/jpeg" {
		t.Fatalf("metadata.output_mime = %v", got.Metadata["output_mime"])
	}
}
