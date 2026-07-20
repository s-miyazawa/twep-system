// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package tcinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

type Metadata struct {
	SchemaVersion   uint64 `cbor:"schema_version"`
	ComponentIDCBOR []byte `cbor:"component_id_cbor"`
	SequenceNumber  uint64 `cbor:"sequence_number"`
	PayloadURI      string `cbor:"payload_uri"`
	PayloadFile     string `cbor:"payload_file"`
	PayloadSHA256   []byte `cbor:"payload_sha256"`
}

type Inventory struct {
	Metadata          Metadata
	Status            string
	PayloadHashStatus string
	Size              int64
}

func Load(stateDir string) (Inventory, error) {
	metadataPath := filepath.Join(stateDir, "components", "install-metadata.cbor")
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Inventory{}, fmt.Errorf("tc.inventory_empty: no installed TC artifact")
		}
		return Inventory{}, fmt.Errorf("read install metadata: %w", err)
	}
	var metadata Metadata
	if err := cbor.Unmarshal(metadataBytes, &metadata); err != nil {
		return Inventory{}, fmt.Errorf("decode install metadata: %w", err)
	}
	if err := validateMetadata(metadata); err != nil {
		return Inventory{}, err
	}
	statusBytes, err := os.ReadFile(filepath.Join(stateDir, "components", "install-status.txt"))
	if err != nil {
		return Inventory{}, fmt.Errorf("read install status: %w", err)
	}
	payloadPath := filepath.Join(stateDir, filepath.FromSlash(metadata.PayloadFile))
	info, err := os.Stat(payloadPath)
	if err != nil {
		return Inventory{}, fmt.Errorf("stat payload: %w", err)
	}
	if info.IsDir() {
		return Inventory{}, fmt.Errorf("payload path is a directory")
	}
	payloadBytes, err := os.ReadFile(payloadPath)
	if err != nil {
		return Inventory{}, fmt.Errorf("read payload: %w", err)
	}
	payloadSHA256 := sha256.Sum256(payloadBytes)
	if !bytes.Equal(payloadSHA256[:], metadata.PayloadSHA256) {
		return Inventory{}, fmt.Errorf("payload sha256 mismatch")
	}
	return Inventory{
		Metadata:          metadata,
		Status:            strings.TrimSpace(string(statusBytes)),
		PayloadHashStatus: "ok",
		Size:              int64(len(payloadBytes)),
	}, nil
}

func Format(inv Inventory) string {
	m := inv.Metadata
	var b strings.Builder
	b.WriteString("TC artifacts:\n")
	fmt.Fprintf(&b, "- component_id_cbor: %s\n", hex.EncodeToString(m.ComponentIDCBOR))
	fmt.Fprintf(&b, "  sequence_number: %d\n", m.SequenceNumber)
	fmt.Fprintf(&b, "  payload_uri: %s\n", m.PayloadURI)
	fmt.Fprintf(&b, "  payload_file: %s\n", m.PayloadFile)
	fmt.Fprintf(&b, "  payload_sha256: %s\n", hex.EncodeToString(m.PayloadSHA256))
	fmt.Fprintf(&b, "  payload_hash_status: %s\n", inv.PayloadHashStatus)
	fmt.Fprintf(&b, "  status: %s\n", inv.Status)
	fmt.Fprintf(&b, "  size: %d\n", inv.Size)
	return b.String()
}

func MarshalCBOR(inv Inventory) ([]byte, error) {
	m := inv.Metadata
	return cbor.Marshal(map[string]any{
		"schema_version":      uint64(1),
		"component_id_cbor":   m.ComponentIDCBOR,
		"sequence_number":     m.SequenceNumber,
		"payload_uri":         m.PayloadURI,
		"payload_file":        m.PayloadFile,
		"payload_sha256":      m.PayloadSHA256,
		"payload_hash_status": inv.PayloadHashStatus,
		"status":              inv.Status,
		"size":                uint64(inv.Size),
	})
}

func validateMetadata(m Metadata) error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("unsupported install metadata schema_version %d", m.SchemaVersion)
	}
	if len(m.ComponentIDCBOR) == 0 {
		return fmt.Errorf("install metadata missing component_id_cbor")
	}
	if m.PayloadURI == "" {
		return fmt.Errorf("install metadata missing payload_uri")
	}
	if m.PayloadFile == "" || filepath.IsAbs(m.PayloadFile) || strings.Contains(m.PayloadFile, "\\") {
		return fmt.Errorf("install metadata payload_file is invalid")
	}
	clean := filepath.Clean(filepath.FromSlash(m.PayloadFile))
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return fmt.Errorf("install metadata payload_file escapes state directory")
	}
	if len(m.PayloadSHA256) != 32 {
		return fmt.Errorf("install metadata payload_sha256 length = %d, want 32", len(m.PayloadSHA256))
	}
	return nil
}
