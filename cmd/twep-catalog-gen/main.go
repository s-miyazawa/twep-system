// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
)

type appEntry struct {
	Command         string
	DisplayName     string
	ComponentID     string
	Version         string
	ABI             string
	WasmFile        string
	AcceptedFormats []string
	ResourceLimits  map[string]uint64
	SHA256          [32]byte
}

func main() {
	outJSON := flag.String("json", "", "output JSON catalog path")
	outCBOR := flag.String("cbor", "", "output CBOR catalog path")
	flag.Parse()
	if *outJSON == "" || *outCBOR == "" {
		fmt.Fprintln(os.Stderr, "usage: twep-catalog-gen --json PATH --cbor PATH")
		os.Exit(2)
	}
	apps, err := catalogApps()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outJSON, []byte(renderJSON(apps)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write json catalog: %v\n", err)
		os.Exit(1)
	}
	cborBytes, err := renderCBOR(apps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render cbor catalog: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outCBOR, cborBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write cbor catalog: %v\n", err)
		os.Exit(1)
	}
}

func catalogApps() ([]appEntry, error) {
	defs := []struct {
		command, displayName, componentID, version, abi, wasmFile string
		acceptedFormats                                           []string
		resourceLimits                                            map[string]uint64
	}{
		{"helloworld", "Hello World", "twep.example.helloworld", "0.1.0", "twep-app-v1", "helloworld.wasm", nil, nil},
		{"calcadd", "Calculator", "twep.example.calcadd", "0.1.0", "twep-app-v1", "calcadd.wasm", nil, nil},
		{
			command:         "negaposi",
			displayName:     "Negative/Positive Image",
			componentID:     "twep.example.negaposi",
			version:         "0.1.0",
			abi:             "twep-app-v1",
			wasmFile:        "negaposi.wasm",
			acceptedFormats: []string{"image/jpeg"},
			resourceLimits: map[string]uint64{
				"stack_bytes":      1048576,
				"heap_bytes":       16777216,
				"timeout_ms":       10000,
				"max_output_bytes": 16777216,
			},
		},
	}
	apps := make([]appEntry, 0, len(defs))
	for _, def := range defs {
		b, err := os.ReadFile("build/" + def.wasmFile)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", def.wasmFile, err)
		}
		apps = append(apps, appEntry{
			Command:         def.command,
			DisplayName:     def.displayName,
			ComponentID:     def.componentID,
			Version:         def.version,
			ABI:             def.abi,
			WasmFile:        def.wasmFile,
			AcceptedFormats: def.acceptedFormats,
			ResourceLimits:  def.resourceLimits,
			SHA256:          sha256.Sum256(b),
		})
	}
	return apps, nil
}

func renderJSON(apps []appEntry) string {
	var b bytes.Buffer
	b.WriteString("{\n  \"schema_version\": 1,\n  \"generated_at\": \"2026-07-11T00:00:00Z\",\n  \"source\": \"local-dev\",\n  \"apps\": {\n")
	for i, app := range apps {
		comma := ","
		if i == len(apps)-1 {
			comma = ""
		}
		fmt.Fprintf(&b, "    %q: { \"display_name\": %q, \"component_id\": %q, \"version\": %q, \"abi\": %q, \"wasm_file\": %q, \"sha256\": %q",
			app.Command, app.DisplayName, app.ComponentID, app.Version, app.ABI, app.WasmFile, hex.EncodeToString(app.SHA256[:]))
		if len(app.AcceptedFormats) != 0 {
			fmt.Fprintf(&b, ", \"accepted_formats\": [")
			for j, format := range app.AcceptedFormats {
				if j != 0 {
					fmt.Fprintf(&b, ", ")
				}
				fmt.Fprintf(&b, "%q", format)
			}
			fmt.Fprintf(&b, "]")
		}
		if len(app.ResourceLimits) != 0 {
			fmt.Fprintf(&b, ", \"resource_limits\": {")
			keys := sortedUintMapKeys(app.ResourceLimits)
			for j, key := range keys {
				if j != 0 {
					fmt.Fprintf(&b, ", ")
				}
				fmt.Fprintf(&b, "%q: %d", key, app.ResourceLimits[key])
			}
			fmt.Fprintf(&b, "}")
		}
		fmt.Fprintf(&b, " }%s\n", comma)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func renderCBOR(apps []appEntry) ([]byte, error) {
	root := map[string]any{
		"schema_version": uint64(1),
		"generated_at":   "2026-07-11T00:00:00Z",
		"source":         "local-dev",
		"apps":           appsMap(apps),
	}
	var b bytes.Buffer
	if err := writeValue(&b, root); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func appsMap(apps []appEntry) map[string]any {
	out := make(map[string]any, len(apps))
	for _, app := range apps {
		sha := make([]byte, len(app.SHA256))
		copy(sha, app.SHA256[:])
		entry := map[string]any{
			"display_name": app.DisplayName,
			"component_id": app.ComponentID,
			"version":      app.Version,
			"abi":          app.ABI,
			"wasm_file":    app.WasmFile,
			"sha256":       sha,
		}
		if len(app.AcceptedFormats) != 0 {
			formats := make([]any, len(app.AcceptedFormats))
			for i, format := range app.AcceptedFormats {
				formats[i] = format
			}
			entry["accepted_formats"] = formats
		}
		if len(app.ResourceLimits) != 0 {
			limits := make(map[string]any, len(app.ResourceLimits))
			for k, v := range app.ResourceLimits {
				limits[k] = v
			}
			entry["resource_limits"] = limits
		}
		out[app.Command] = entry
	}
	return out
}

func sortedUintMapKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func writeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case uint64:
		writeTypeLen(buf, 0, x)
	case string:
		writeTypeLen(buf, 3, uint64(len(x)))
		buf.WriteString(x)
	case []byte:
		writeTypeLen(buf, 2, uint64(len(x)))
		buf.Write(x)
	case []any:
		writeTypeLen(buf, 4, uint64(len(x)))
		for _, e := range x {
			if err := writeValue(buf, e); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) != len(keys[j]) {
				return len(keys[i]) < len(keys[j])
			}
			return keys[i] < keys[j]
		})
		writeTypeLen(buf, 5, uint64(len(keys)))
		for _, k := range keys {
			if err := writeValue(buf, k); err != nil {
				return err
			}
			if err := writeValue(buf, x[k]); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func writeTypeLen(buf *bytes.Buffer, major byte, n uint64) {
	head := major << 5
	switch {
	case n < 24:
		buf.WriteByte(head | byte(n))
	case n <= 0xff:
		buf.WriteByte(head | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(head | 25)
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n))
	case n <= 0xffffffff:
		buf.WriteByte(head | 26)
		buf.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		buf.WriteByte(head | 27)
		buf.Write([]byte{byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
}
