// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package ipc

import (
	"encoding/binary"
	"fmt"
	"io"
)

const DefaultMaxFrameBytes = 16 * 1024 * 1024

func WriteFrame(w io.Writer, payload []byte, max uint32) error {
	if max == 0 {
		max = DefaultMaxFrameBytes
	}
	if len(payload) > int(max) {
		return fmt.Errorf("frame too large: %d > %d", len(payload), max)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

func ReadFrame(r io.Reader, max uint32) ([]byte, error) {
	if max == 0 {
		max = DefaultMaxFrameBytes
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > max {
		return nil, fmt.Errorf("frame too large: %d > %d", n, max)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read frame payload: %w", err)
	}
	return payload, nil
}
