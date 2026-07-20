// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/s-miyazawa/twep-system/internal/cborcodec"
	"github.com/s-miyazawa/twep-system/internal/ipc"
	"github.com/s-miyazawa/twep-system/internal/tcinventory"
	"github.com/s-miyazawa/twep-system/internal/twepwr"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("twepd", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	socketPath := fs.String("socket", defaultSocketPath(), "Unix domain socket path")
	stateDir := fs.String("state-dir", defaultStateDir(), "twep state directory")
	resolverMode := fs.String("resolver-mode", "mock", "resolver mode: mock, attestam-insecure, or attestam-verified")
	attestamURL := fs.String("attestam-url", "", "AttesTAM URL for TEEP-over-HTTP")
	insecureDemo := fs.Bool("insecure-demo-mode", false, "allow development-only insecure AttesTAM mode")
	insecureDemoAgentKey := fs.String("insecure-demo-agent-key", "default", "development-only AttesTAM agent key: default or alternate")
	once := fs.Bool("once", false, "handle one request and exit")
	help := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.Usage()
		return nil
	}
	if err := prepareSocketPath(*socketPath, defaultSocketPath()); err != nil {
		return err
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	ctx, err := twepwr.InitWithConfig(twepwr.Config{
		StateDir:             *stateDir,
		ResolverMode:         *resolverMode,
		AttestamURL:          *attestamURL,
		InsecureDemo:         *insecureDemo,
		InsecureDemoAgentKey: *insecureDemoAgentKey,
	})
	if err != nil {
		return err
	}
	defer ctx.Shutdown()
	ln, err := listenUnixSocket(*socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(*socketPath)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		if err := handleConn(conn, ctx, *stateDir); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		if *once {
			return nil
		}
	}
}

func handleConn(conn net.Conn, ctx *twepwr.Context, stateDir string) error {
	defer conn.Close()
	reqBytes, err := ipc.ReadFrame(conn, ipc.DefaultMaxFrameBytes)
	if err != nil {
		return fmt.Errorf("ipc.protocol: %w", err)
	}
	req, err := cborcodec.DecodeRequest(reqBytes)
	if err != nil {
		return writeError(conn, "", "daemon.request", err.Error())
	}
	if req.Command == "tc-inventory" {
		return writeTCInventory(conn, req, stateDir)
	}
	respBytes, err := ctx.Execute(reqBytes)
	if err != nil {
		var statusErr *twepwr.StatusError
		if errors.As(err, &statusErr) {
			return writeError(conn, req.RequestID, statusErr.Status, statusErr.Message)
		}
		return writeError(conn, req.RequestID, "app.runtime", err.Error())
	}
	resp, err := cborcodec.DecodeResponse(respBytes)
	if err != nil {
		return writeError(conn, req.RequestID, "app.runtime", fmt.Sprintf("decode twep-wr response: %v", err))
	}
	resp.RequestID = req.RequestID
	normalized, err := cborcodec.EncodeResponse(resp)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	return ipc.WriteFrame(conn, normalized, ipc.DefaultMaxFrameBytes)
}

func writeTCInventory(conn net.Conn, req cborcodec.Request, stateDir string) error {
	inv, err := tcinventory.Load(stateDir)
	if err != nil {
		return writeError(conn, req.RequestID, "tc.inventory", err.Error())
	}
	var stdout []byte
	switch req.Options.OutputFormat {
	case "", "text":
		stdout = []byte(tcinventory.Format(inv))
	case "cbor":
		stdout, err = tcinventory.MarshalCBOR(inv)
		if err != nil {
			return writeError(conn, req.RequestID, "tc.inventory", err.Error())
		}
	default:
		return writeError(conn, req.RequestID, "cli.usage", fmt.Sprintf("unsupported output_format %q", req.Options.OutputFormat))
	}
	resp, err := cborcodec.EncodeResponse(cborcodec.Response{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     req.RequestID,
		Status:        "ok",
		ExitCode:      0,
		Stdout:        stdout,
	})
	if err != nil {
		return err
	}
	return ipc.WriteFrame(conn, resp, ipc.DefaultMaxFrameBytes)
}

func writeError(conn net.Conn, requestID, code, message string) error {
	resp, err := cborcodec.EncodeResponse(cborcodec.Response{
		SchemaVersion: cborcodec.SchemaVersion,
		RequestID:     requestID,
		Status:        "error",
		ExitCode:      1,
		Error:         &cborcodec.TwepError{Code: code, Message: message},
	})
	if err != nil {
		return err
	}
	return ipc.WriteFrame(conn, resp, ipc.DefaultMaxFrameBytes)
}

func prepareSocketPath(socketPath string, defaultPath string) error {
	if socketPath == "" {
		return fmt.Errorf("socket path is empty")
	}
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if socketPath != defaultPath {
		if err := validateSocketParent(socketDir); err != nil {
			return err
		}
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("socket path exists and is not a socket: %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat socket path: %w", err)
	}
	return nil
}

func listenUnixSocket(socketPath string) (net.Listener, error) {
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln, nil
}

func validateSocketParent(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat socket dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("socket parent is not a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("socket parent must not be group/world writable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("socket parent owner unavailable")
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("socket parent must be owned by current user")
	}
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
