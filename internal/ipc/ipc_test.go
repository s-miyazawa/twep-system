// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package ipc

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("abc"), 10); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, 10)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Fatalf("payload = %q", got)
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("abc"), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(&buf, 2); err == nil {
		t.Fatal("expected size error")
	}
}
