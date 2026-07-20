// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/s-miyazawa/twep-system/internal/demokeys"
	"github.com/s-miyazawa/twep-system/internal/wasmsign"
)

func main() {
	role := flag.String("role", "", "signature role: teep-agent or app")
	in := flag.String("in", "", "input wasm file")
	out := flag.String("out", "", "output wasm file")
	verify := flag.Bool("verify", false, "verify instead of signing")
	flag.Parse()

	if *role != wasmsign.RoleTEEPAgent && *role != wasmsign.RoleApp {
		fatalf("-role must be %q or %q", wasmsign.RoleTEEPAgent, wasmsign.RoleApp)
	}
	if *in == "" {
		fatalf("-in is required")
	}
	if !*verify && *out == "" {
		fatalf("-out is required when signing")
	}

	input, err := os.ReadFile(*in)
	if err != nil {
		fatalf("read input: %v", err)
	}
	key, kid := keyForRole(*role)
	if *verify {
		if err := wasmsign.Verify(input, key, *role); err != nil {
			fatalf("verify wasm signature: %v", err)
		}
		return
	}
	signed, err := wasmsign.Sign(input, key, *role, []byte(kid))
	if err != nil {
		fatalf("sign wasm: %v", err)
	}
	if err := os.WriteFile(*out, signed, 0o644); err != nil {
		fatalf("write output: %v", err)
	}
}

func keyForRole(role string) ([]byte, string) {
	if role == wasmsign.RoleTEEPAgent {
		return demokeys.DemoTEEPAgentCodeSigningESP256PrivateCOSEKey(), wasmsign.TEEPAgentKID
	}
	return demokeys.DemoAppCodeSigningESP256PrivateCOSEKey(), wasmsign.AppKID
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
