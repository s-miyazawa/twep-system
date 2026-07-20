// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package e2e

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCalcAddAcceptsVariableArgumentCounts(t *testing.T) {
	binDir, repoRoot := e2eEnv(t)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "three", args: []string{"calcadd", "3", "4", "5"}, want: "12\n"},
		{name: "five", args: []string{"calcadd", "3", "4", "5", "6", "7"}, want: "25\n"},
		{name: "one", args: []string{"calcadd", "3"}, want: "3\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDir := t.TempDir()
			socketPath := filepath.Join(stateDir, "run", "twepd.sock")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			got := runTwepdCLIOnce(t, ctx, binDir, repoRoot, stateDir, socketPath, tt.args)
			if string(got) != tt.want {
				t.Fatalf("twep-cli %v output = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}
