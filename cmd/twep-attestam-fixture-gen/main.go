// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/s-miyazawa/twep-system/internal/demokeys"
	"github.com/s-miyazawa/twep-system/internal/suitfixture"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func main() {
	command := flag.String("command", "remotehello", "twep command name")
	wasmPath := flag.String("wasm", "", "input Wasm payload path")
	wasmFile := flag.String("wasm-file", "", "Wasm filename to install in twep apps cache")
	catalog := flag.Bool("catalog", false, "generate a twep-catalog-v1 Trusted Component instead of an app")
	catalogName := flag.String("catalog-name", "default", "Catalog component name for --catalog")
	catalogPayloadPath := flag.String("catalog-payload", "", "optional Catalog CBOR payload path for --catalog")
	catalogFixture := flag.String("catalog-fixture", "default", "built-in Catalog payload for --catalog: default, malformed, or oversized")
	outPath := flag.String("out", "", "output SUIT envelope CBOR path")
	verifiedUpdateOutPath := flag.String("verified-update-out", "", "optional output COSE_Sign1 TEEP Update path signed by the demo TAM")
	verifiedUpdateSize := flag.Int("verified-update-size", 0, "optional exact COSE Update size for transport-boundary fixtures")
	verifiedTokenOutPath := flag.String("verified-token-out", "", "optional output token path for --verified-update-out")
	protectedStoreOutPath := flag.String("protected-store-out", "", "optional output protected credential store fixture path using the generated TAM kid")
	issuerAllowlistOutPath := flag.String("issuer-allowlist-out", "", "optional output protected issuer allowlist fixture path")
	issuerAllowlistID := flag.String("issuer-allowlist-id", "issuer", "issuer id string for --issuer-allowlist-out")
	registerURL := flag.String("register-url", "", "optional AttesTAM RegisterManifest URL")
	sequence := flag.Uint64("sequence", 1, "SUIT manifest sequence number")
	insecureMetadata := flag.Bool("insecure-app-metadata", false, "include legacy twep-app-v1-metadata fixture data")
	flag.Parse()

	if *outPath == "" || (!*catalog && *wasmPath == "") {
		fmt.Fprintln(os.Stderr, "usage: twep-attestam-fixture-gen (-wasm app.wasm | -catalog) -out envelope.cbor")
		os.Exit(2)
	}
	if *catalog && (*wasmPath != "" || *wasmFile != "" || *insecureMetadata) {
		fmt.Fprintln(os.Stderr, "--catalog cannot be combined with app Wasm or insecure app metadata options")
		os.Exit(2)
	}
	if *catalogPayloadPath != "" && *catalogFixture != "default" {
		fmt.Fprintln(os.Stderr, "--catalog-payload cannot be combined with a non-default --catalog-fixture")
		os.Exit(2)
	}
	if *verifiedUpdateSize != 0 && (!*catalog || *verifiedUpdateOutPath == "") {
		fmt.Fprintln(os.Stderr, "--verified-update-size requires --catalog and --verified-update-out")
		os.Exit(2)
	}
	if *verifiedUpdateSize != 0 && (*catalogPayloadPath != "" || *catalogFixture != "default") {
		fmt.Fprintln(os.Stderr, "--verified-update-size uses a synthetic payload and cannot be combined with Catalog payload options")
		os.Exit(2)
	}
	var payload []byte
	var err error
	if *catalog {
		if *catalogPayloadPath != "" {
			payload, err = os.ReadFile(*catalogPayloadPath)
		} else {
			payload, err = catalogFixturePayload(*catalogFixture)
		}
	} else {
		payload, err = os.ReadFile(*wasmPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "read payload: %v\n", err)
		os.Exit(1)
	}
	token := []byte{0xca, 0xfe, 0xba, 0xbe}
	componentName := *command
	if *catalog {
		componentName = *catalogName
	}
	artifact, verifiedUpdate, err := generateFixture(fixtureOptions{
		catalog:             *catalog,
		componentName:       componentName,
		wasmFile:            *wasmFile,
		payload:             payload,
		sequence:            *sequence,
		insecureAppMetadata: *insecureMetadata,
		verified:            *verifiedUpdateOutPath != "" || *verifiedTokenOutPath != "",
		token:               token,
	})
	if err == nil && *verifiedUpdateSize != 0 {
		artifact, verifiedUpdate, err = generateCatalogFixtureWithUpdateSize(fixtureOptions{
			catalog:       true,
			componentName: *catalogName,
			sequence:      *sequence,
			verified:      true,
			token:         token,
		}, *verifiedUpdateSize)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate fixture: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, artifact.Envelope, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write envelope: %v\n", err)
		os.Exit(1)
	}
	if *verifiedUpdateOutPath != "" {
		if err := writeFileWithParents(*verifiedUpdateOutPath, verifiedUpdate); err != nil {
			fmt.Fprintf(os.Stderr, "write verified update: %v\n", err)
			os.Exit(1)
		}
	}
	if *verifiedTokenOutPath != "" {
		if err := writeFileWithParents(*verifiedTokenOutPath, token); err != nil {
			fmt.Fprintf(os.Stderr, "write verified token: %v\n", err)
			os.Exit(1)
		}
	}
	if *protectedStoreOutPath != "" {
		store, err := protectedCredentialStoreFixture()
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode protected credential store: %v\n", err)
			os.Exit(1)
		}
		if err := writeFileWithParents(*protectedStoreOutPath, store); err != nil {
			fmt.Fprintf(os.Stderr, "write protected credential store: %v\n", err)
			os.Exit(1)
		}
	}
	if *issuerAllowlistOutPath != "" {
		allowlist, err := issuerAllowlistFixture([]byte(*issuerAllowlistID))
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode issuer allowlist: %v\n", err)
			os.Exit(1)
		}
		if err := writeFileWithParents(*issuerAllowlistOutPath, allowlist); err != nil {
			fmt.Fprintf(os.Stderr, "write issuer allowlist: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("wrote %s\ncomponent_id=%x\nkid=%x\npayload_sha256=%x\n", *outPath, artifact.ComponentID, artifact.KID, artifact.PayloadSHA256)
	if *registerURL != "" {
		if err := register(*registerURL, artifact.Envelope); err != nil {
			fmt.Fprintf(os.Stderr, "register manifest: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("registered %s\n", *registerURL)
	}
}

func generateCatalogFixtureWithUpdateSize(opts fixtureOptions, target int) (*suitfixture.Artifact, []byte, error) {
	if target <= 0 {
		return nil, nil, fmt.Errorf("verified Update size must be positive")
	}
	if !opts.catalog || !opts.verified {
		return nil, nil, fmt.Errorf("exact Update sizing requires a verified Catalog fixture")
	}
	// The payload is intentionally synthetic and usually exceeds the Catalog
	// limit. These fixtures isolate the outer TEEP/COSE transport boundary.
	low, high := 0, target
	for low <= high {
		payloadSize := low + (high-low)/2
		opts.payload = make([]byte, payloadSize)
		artifact, update, err := generateFixture(opts)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case len(update) == target:
			return artifact, update, nil
		case len(update) < target:
			low = payloadSize + 1
		default:
			high = payloadSize - 1
		}
	}
	return nil, nil, fmt.Errorf("cannot generate a COSE Update of exactly %d bytes", target)
}

type fixtureOptions struct {
	catalog             bool
	componentName       string
	wasmFile            string
	payload             []byte
	sequence            uint64
	insecureAppMetadata bool
	verified            bool
	token               []byte
}

func generateFixture(opts fixtureOptions) (*suitfixture.Artifact, []byte, error) {
	if opts.catalog {
		catalogOpts := suitfixture.CatalogOptions{
			CatalogName:    opts.componentName,
			Payload:        opts.payload,
			SequenceNumber: opts.sequence,
		}
		if opts.verified {
			verified, err := suitfixture.GenerateDemoTAMVerifiedCatalogUpdate(catalogOpts, opts.token)
			if err != nil {
				return nil, nil, err
			}
			return &verified.Artifact, verified.COSEUpdate, nil
		}
		artifact, err := suitfixture.GenerateCatalog(catalogOpts)
		return artifact, nil, err
	}

	appOpts := suitfixture.Options{
		Command:             opts.componentName,
		WasmFile:            opts.wasmFile,
		Payload:             opts.payload,
		SequenceNumber:      opts.sequence,
		InsecureAppMetadata: opts.insecureAppMetadata,
	}
	if opts.verified {
		verified, err := suitfixture.GenerateDemoTAMVerifiedUpdate(appOpts, opts.token)
		if err != nil {
			return nil, nil, err
		}
		return &verified.Artifact, verified.COSEUpdate, nil
	}
	artifact, err := suitfixture.Generate(appOpts)
	return artifact, nil, err
}

func catalogFixturePayload(kind string) ([]byte, error) {
	switch kind {
	case "default":
		return suitfixture.CanonicalDefaultCatalogPayload()
	case "malformed":
		return []byte{0xa1}, nil
	case "oversized":
		return make([]byte, suitfixture.MaxCatalogPayloadSize+1), nil
	default:
		return nil, fmt.Errorf("unknown Catalog fixture %q", kind)
	}
}

func writeFileWithParents(path string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, contents, 0o600)
}

func protectedCredentialStoreFixture() ([]byte, error) {
	var tamKey cose.Key
	if err := cbor.Unmarshal(demokeys.DemoTAMESP256PrivateCOSEKey(), &tamKey); err != nil {
		return nil, fmt.Errorf("decode demo TAM key: %w", err)
	}
	tamX, tamXOK := tamKey.ParamBytes(cose.KeyLabelEC2X)
	tamY, tamYOK := tamKey.ParamBytes(cose.KeyLabelEC2Y)
	if !tamXOK || !tamYOK || len(tamX) != 32 || len(tamY) != 32 {
		return nil, fmt.Errorf("demo TAM key does not contain P-256 public coordinates")
	}
	tamKID, err := tamKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("derive demo TAM kid: %w", err)
	}

	developerBlock, _ := pem.Decode(demokeys.DemoTCSignerESP256PrivateKeyPEM())
	if developerBlock == nil {
		return nil, fmt.Errorf("decode demo developer private key pem")
	}
	parsedDeveloperKey, err := x509.ParsePKCS8PrivateKey(developerBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse demo developer private key: %w", err)
	}
	developerKey, ok := parsedDeveloperKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("demo developer private key is %T, want *ecdsa.PrivateKey", parsedDeveloperKey)
	}
	developerPublicKey, err := cose.NewKeyEC2(
		cose.AlgorithmESP256,
		developerKey.X.Bytes(),
		developerKey.Y.Bytes(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create demo developer public COSE key: %w", err)
	}
	developerKID, err := developerPublicKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("derive demo developer kid: %w", err)
	}
	store := map[string]any{
		"schema_version": 1,
		"store_epoch":    1,
		"attestam_message_verification_keys": []any{
			protectedPublicKeyCredential("tam-entry", tamKID, "attestam-message-verification", tamX, tamY),
		},
		"suit_content_verification_keys": []any{
			protectedPublicKeyCredential(
				"suit-entry",
				developerKID,
				"suit-content-verification",
				developerKey.X.Bytes(),
				developerKey.Y.Bytes(),
			),
		},
	}
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return enc.Marshal(store)
}

func protectedPublicKeyCredential(entryID string, kid []byte, purpose string, x, y []byte) map[string]any {
	return map[string]any{
		"entry_id":           []byte(entryID),
		"issuer_id":          []byte("issuer"),
		"kid":                kid,
		"purpose":            purpose,
		"alg":                "ESP256",
		"crv":                "P-256",
		"not_before":         1,
		"not_after":          2,
		"provisioning_epoch": 1,
		"x":                  x,
		"y":                  y,
	}
}

func issuerAllowlistFixture(issuerID []byte) ([]byte, error) {
	allowlist := map[string]any{
		"schema_version": 1,
		"issuer_ids":     []any{issuerID},
	}
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return enc.Marshal(allowlist)
}

func register(url string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/suit-envelope+cose")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s: %s", resp.Status, bytes.TrimSpace(respBody))
	}
	return nil
}
