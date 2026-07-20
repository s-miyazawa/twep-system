// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package teepbroker

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPPostDevelopmentAttesTAMPolicy(t *testing.T) {
	requestBody := []byte{0x81, 0x01}
	responseBody := []byte{0x81, 0x02}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Content-Type"); got != "application/teep+cbor" {
			t.Errorf("Content-Type = %q, want application/teep+cbor", got)
		}
		if got := r.Header.Get("Accept"); got != "application/teep+cbor" {
			t.Errorf("Accept = %q, want application/teep+cbor", got)
		}
		gotBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(gotBody) != string(requestBody) {
			t.Errorf("body = %x, want %x", gotBody, requestBody)
		}
		_, _ = w.Write(responseBody)
	}))
	defer server.Close()

	tests := []struct {
		name         string
		config       HTTPPostConfig
		url          string
		wantStatus   int32
		wantRequests int
	}{
		{
			name: "verified development path",
			config: HTTPPostConfig{
				ResolverMode: "attestam-verified",
				AttestamURL:  server.URL,
				InsecureDemo: false,
			},
			url:          server.URL,
			wantStatus:   HostStatusOK,
			wantRequests: 1,
		},
		{
			name: "insecure demo path",
			config: HTTPPostConfig{
				ResolverMode: "attestam-insecure",
				AttestamURL:  server.URL,
				InsecureDemo: true,
			},
			url:          server.URL,
			wantStatus:   HostStatusOK,
			wantRequests: 1,
		},
		{
			name: "verified cannot enable insecure demo flag",
			config: HTTPPostConfig{
				ResolverMode: "attestam-verified",
				AttestamURL:  server.URL,
				InsecureDemo: true,
			},
			url:        server.URL,
			wantStatus: HostStatusDenied,
		},
		{
			name: "insecure requires demo flag",
			config: HTTPPostConfig{
				ResolverMode: "attestam-insecure",
				AttestamURL:  server.URL,
				InsecureDemo: false,
			},
			url:        server.URL,
			wantStatus: HostStatusDenied,
		},
		{
			name: "verified requires exact URL",
			config: HTTPPostConfig{
				ResolverMode: "attestam-verified",
				AttestamURL:  server.URL + "/tam",
				InsecureDemo: false,
			},
			url:        server.URL,
			wantStatus: HostStatusDenied,
		},
		{
			name: "generic resolver denied",
			config: HTTPPostConfig{
				ResolverMode: "mock",
				AttestamURL:  server.URL,
			},
			url:        server.URL,
			wantStatus: HostStatusDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := requests
			result := HTTPPost(server.Client(), tt.config, tt.url, requestBody)
			if result.Status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", result.Status, tt.wantStatus)
			}
			if got := requests - before; got != tt.wantRequests {
				t.Fatalf("request count = %d, want %d", got, tt.wantRequests)
			}
			if tt.wantStatus == HostStatusOK && string(result.Response) != string(responseBody) {
				t.Fatalf("response = %x, want %x", result.Response, responseBody)
			}
		})
	}
}
