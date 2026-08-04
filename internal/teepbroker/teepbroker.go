// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package teepbroker

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/s-miyazawa/twep-system/internal/demokeys"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	HostStatusOK               int32 = 0
	HostStatusInvalidArgument  int32 = 1
	HostStatusResponseTooLarge int32 = 2
	HostStatusDenied           int32 = 4
	HostStatusNetwork          int32 = 5
	HostStatusProtocol         int32 = 7
)

type HTTPPostConfig struct {
	ResolverMode     string
	AttestamURL      string
	InsecureDemo     bool
	MaxResponseBytes uint32
}

type HTTPPostResult struct {
	Status   int32
	Response []byte
}

func HTTPPost(client *http.Client, config HTTPPostConfig, url string, body []byte) HTTPPostResult {
	if client == nil || url == "" {
		return HTTPPostResult{Status: HostStatusInvalidArgument}
	}
	developmentModeAllowed := (config.ResolverMode == "attestam-insecure" && config.InsecureDemo) ||
		(config.ResolverMode == "attestam-verified" && !config.InsecureDemo)
	if !developmentModeAllowed || url != config.AttestamURL {
		return HTTPPostResult{Status: HostStatusDenied}
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return HTTPPostResult{Status: HostStatusInvalidArgument}
	}
	req.Header.Set("Content-Type", "application/teep+cbor")
	req.Header.Set("Accept", "application/teep+cbor")
	resp, err := client.Do(req)
	if err != nil {
		return HTTPPostResult{Status: HostStatusNetwork}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return HTTPPostResult{Status: HostStatusProtocol}
	}
	maxResponse := config.MaxResponseBytes
	if maxResponse == 0 {
		maxResponse = 16 * 1024 * 1024
	}
	response, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponse)+1))
	if err != nil {
		return HTTPPostResult{Status: HostStatusNetwork}
	}
	if len(response) > int(maxResponse) {
		return HTTPPostResult{Status: HostStatusResponseTooLarge, Response: response}
	}
	return HTTPPostResult{Status: HostStatusOK, Response: response}
}

func DemoTrustedAgentKeyCBOR() []byte {
	return demokeys.DemoTrustedAgentESP256PrivateCOSEKey()
}

func AlternateDemoAgentKeyCBOR() []byte {
	return clone(alternateDemoAgentKeyCBOR)
}

func DemoAgentEATUEID() []byte {
	return clone(demoAgentEATUEID)
}

func DemoAgentEATMeasurementDigest() []byte {
	return clone(demoAgentEATMeasurementDigest)
}

func PublicCOSEKeyCBOR(privateKeyCBOR []byte) ([]byte, error) {
	var key cose.Key
	if err := cbor.Unmarshal(privateKeyCBOR, &key); err != nil {
		return nil, fmt.Errorf("decode demo agent key: %w", err)
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	publicCOSEKey, err := cose.NewKeyFromPublic(publicKey)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	alg, err := key.AlgorithmOrDefault()
	if err != nil {
		return nil, fmt.Errorf("detect public key algorithm: %w", err)
	}
	publicCOSEKey.Algorithm = alg
	return publicCOSEKey.MarshalCBOR()
}

func clone(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

var demoAgentEATUEID = []byte{
	0x01, 0x98, 0xf5, 0x0a, 0x4f, 0xf6, 0xc0, 0x58,
	0x61, 0xc8, 0x86, 0x0d, 0x13, 0xa6, 0x38, 0xea,
}

var demoAgentEATMeasurementDigest = []byte{
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
}

// alternateDemoAgentKeyCBOR is a published, intentionally insecure private key
// for disposable demos and automated tests only. Never use it in production,
// shared validation environments, long-lived deployments, or with external
// services. AttesTAM insecure-demo does not pre-register it, which lets local
// smoke tests force the token-then-challenge path without editing the database.
var alternateDemoAgentKeyCBOR = []byte{
	0xa6, 0x01, 0x02, 0x03, 0x28, 0x20, 0x01, 0x21, 0x58, 0x20, 0x0e, 0x90,
	0x8a, 0xa8, 0xf0, 0x66, 0xdb, 0x1f, 0x08, 0x4e, 0x0c, 0x36, 0x52, 0xc6,
	0x39, 0x52, 0xbd, 0x99, 0xf2, 0xa5, 0xbd, 0xb2, 0x2f, 0x9e, 0x01, 0x36,
	0x7a, 0xad, 0x03, 0xab, 0xa6, 0x8b, 0x22, 0x58, 0x20, 0x77, 0xda, 0x1b,
	0xd8, 0xac, 0x4f, 0x0c, 0xb4, 0x90, 0xba, 0x21, 0x06, 0x48, 0xbf, 0x79,
	0xab, 0x16, 0x4d, 0x49, 0xad, 0x35, 0x51, 0xd7, 0x1d, 0x31, 0x4b, 0x27,
	0x49, 0xee, 0x42, 0xd2, 0x9a, 0x23, 0x58, 0x20, 0x84, 0x1a, 0xeb, 0xb7,
	0xb9, 0xea, 0x6f, 0x02, 0x60, 0xbe, 0x73, 0x55, 0xa2, 0x45, 0x88, 0xb9,
	0x77, 0xd2, 0x3d, 0x2a, 0xc5, 0xbf, 0x2b, 0x6b, 0x2d, 0x83, 0x79, 0x43,
	0x2a, 0x1f, 0xea, 0x98,
}
