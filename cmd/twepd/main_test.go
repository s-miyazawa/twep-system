// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareSocketPathRejectsNonSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "twepd.sock")
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketPath(socketPath, socketPath); err == nil {
		t.Fatal("prepareSocketPath succeeded, want non-socket rejection")
	}
}

func TestPrepareSocketPathRemovesStaleSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "twepd.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketPath(socketPath, socketPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket stat error = %v, want not exist", err)
	}
}

func TestListenUnixSocketSetsMode0600(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "twepd.sock")
	ln, err := listenUnixSocket(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 0600", got)
	}
}

func TestValidateSocketParentRejectsWorldWritable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateSocketParent(dir); err == nil {
		t.Fatal("validateSocketParent succeeded, want mode rejection")
	}
}
