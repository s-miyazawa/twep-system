// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package suitfixture

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"

	"github.com/s-miyazawa/twep-system/internal/demokeys"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var commandRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

const (
	// MaxCatalogPayloadSize is the D047 authoritative Catalog payload limit.
	MaxCatalogPayloadSize = 65536
	// MaxVerifiedTEEPResponseSize is the D047 inbound verified-session limit.
	MaxVerifiedTEEPResponseSize = 131072
)

type Options struct {
	Command             string
	WasmFile            string
	Payload             []byte
	PayloadURI          string
	SequenceNumber      uint64
	InsecureAppMetadata bool
}

type CatalogOptions struct {
	CatalogName    string
	Payload        []byte
	PayloadURI     string
	SequenceNumber uint64
}

// CanonicalDefaultCatalogPayload returns the smallest D047 Catalog payload.
// It contains Catalog metadata only; application Wasm bytes are always carried
// by separate twep-app-v1 Trusted Components.
func CanonicalDefaultCatalogPayload() ([]byte, error) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create catalog CBOR encoder: %w", err)
	}
	payload, err := enc.Marshal(map[string]any{
		"schema_version": uint64(1),
		"generated_at":   "2026-07-11T00:00:00Z",
		"source":         "local-dev",
		"apps":           map[string]any{},
	})
	if err != nil {
		return nil, fmt.Errorf("encode default catalog: %w", err)
	}
	return payload, nil
}

type Artifact struct {
	Envelope      []byte
	ComponentID   []byte
	PayloadSHA256 [32]byte
	KID           []byte
}

type VerifiedUpdateArtifact struct {
	Artifact
	UpdatePayload []byte
	COSEUpdate    []byte
	Token         []byte
}

type suitDigest struct {
	_     struct{} `cbor:",toarray"`
	Alg   int64
	Bytes []byte
}

func Generate(opts Options) (*Artifact, error) {
	return generateAppWithSigner(opts, signDemoDeveloper)
}

func GenerateCatalog(opts CatalogOptions) (*Artifact, error) {
	return generateCatalogWithSigner(opts, signDemoDeveloper)
}

func GenerateDemoTAMVerifiedUpdate(opts Options, token []byte) (*VerifiedUpdateArtifact, error) {
	artifact, err := generateAppWithSigner(opts, signDemoTAM)
	if err != nil {
		return nil, err
	}
	return signedUpdateArtifact(artifact, token)
}

func GenerateDemoTAMVerifiedCatalogUpdate(opts CatalogOptions, token []byte) (*VerifiedUpdateArtifact, error) {
	artifact, err := generateCatalogWithSigner(opts, signDemoTAM)
	if err != nil {
		return nil, err
	}
	return signedUpdateArtifact(artifact, token)
}

func signedUpdateArtifact(artifact *Artifact, token []byte) (*VerifiedUpdateArtifact, error) {
	return signedUpdateArtifactWithSigner(artifact, token, DemoTAMSign1)
}

func signedUpdateArtifactWithSigner(artifact *Artifact, token []byte, signUpdate func([]byte) ([]byte, error)) (*VerifiedUpdateArtifact, error) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create cbor enc mode: %w", err)
	}
	updatePayload, err := enc.Marshal([]any{
		uint64(3),
		map[uint64]any{
			9:  [][]byte{artifact.Envelope},
			19: token,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode teep update payload: %w", err)
	}
	coseUpdate, err := signUpdate(updatePayload)
	if err != nil {
		return nil, fmt.Errorf("sign teep update: %w", err)
	}
	return &VerifiedUpdateArtifact{
		Artifact:      *artifact,
		UpdatePayload: updatePayload,
		COSEUpdate:    coseUpdate,
		Token:         append([]byte(nil), token...),
	}, nil
}

func generateAppWithSigner(opts Options, sign signerFunc) (*Artifact, error) {
	if !commandRE.MatchString(opts.Command) {
		return nil, fmt.Errorf("invalid command %q", opts.Command)
	}
	if opts.WasmFile == "" {
		opts.WasmFile = opts.Command + ".wasm"
	}
	if opts.PayloadURI == "" {
		opts.PayloadURI = "#" + opts.WasmFile
	}
	if len(opts.Payload) == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	return generateWithSigner(componentOptions{
		ComponentPrefix:     "twep-app-v1",
		ComponentName:       opts.Command,
		Payload:             opts.Payload,
		PayloadURI:          opts.PayloadURI,
		SequenceNumber:      opts.SequenceNumber,
		InsecureAppMetadata: opts.InsecureAppMetadata,
		AppCommand:          opts.Command,
		WasmFile:            opts.WasmFile,
	}, sign)
}

func generateCatalogWithSigner(opts CatalogOptions, sign signerFunc) (*Artifact, error) {
	if opts.CatalogName == "" {
		opts.CatalogName = "default"
	}
	if !commandRE.MatchString(opts.CatalogName) {
		return nil, fmt.Errorf("invalid catalog name %q", opts.CatalogName)
	}
	if opts.PayloadURI == "" {
		opts.PayloadURI = "#catalog.cbor"
	}
	if len(opts.Payload) == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	return generateWithSigner(componentOptions{
		ComponentPrefix: "twep-catalog-v1",
		ComponentName:   opts.CatalogName,
		Payload:         opts.Payload,
		PayloadURI:      opts.PayloadURI,
		SequenceNumber:  opts.SequenceNumber,
	}, sign)
}

type componentOptions struct {
	ComponentPrefix     string
	ComponentName       string
	Payload             []byte
	PayloadURI          string
	SequenceNumber      uint64
	InsecureAppMetadata bool
	AppCommand          string
	WasmFile            string
}

func generateWithSigner(opts componentOptions, sign signerFunc) (*Artifact, error) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create cbor enc mode: %w", err)
	}

	componentID, err := enc.Marshal([][]byte{[]byte(opts.ComponentPrefix), []byte(opts.ComponentName)})
	if err != nil {
		return nil, fmt.Errorf("encode component id: %w", err)
	}
	payloadDigest := sha256.Sum256(opts.Payload)
	payloadDigestBytes, err := enc.Marshal(suitDigest{Alg: int64(cose.AlgorithmSHA256), Bytes: payloadDigest[:]})
	if err != nil {
		return nil, fmt.Errorf("encode payload digest: %w", err)
	}

	sharedSequence, err := enc.Marshal([]any{
		uint64(20),
		map[uint64]any{3: payloadDigestBytes},
	})
	if err != nil {
		return nil, fmt.Errorf("encode shared sequence: %w", err)
	}
	common, err := enc.Marshal(map[uint64]any{
		2: []any{[][]byte{[]byte(opts.ComponentPrefix), []byte(opts.ComponentName)}},
		4: sharedSequence,
	})
	if err != nil {
		return nil, fmt.Errorf("encode common: %w", err)
	}
	payloadFetch, err := enc.Marshal([]any{
		uint64(20),
		map[uint64]any{21: opts.PayloadURI},
	})
	if err != nil {
		return nil, fmt.Errorf("encode payload fetch: %w", err)
	}
	manifest, err := enc.Marshal(map[uint64]any{
		1:  uint64(1),
		2:  opts.SequenceNumber,
		3:  common,
		16: payloadFetch,
	})
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	manifestBstr, err := enc.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode manifest bstr: %w", err)
	}
	manifestDigest := sha256.Sum256(manifestBstr)
	manifestDigestBytes, err := enc.Marshal(suitDigest{Alg: int64(cose.AlgorithmSHA256), Bytes: manifestDigest[:]})
	if err != nil {
		return nil, fmt.Errorf("encode manifest digest: %w", err)
	}

	authBlock, kid, err := sign(manifestDigestBytes, true)
	if err != nil {
		return nil, err
	}
	authWrapper, err := enc.Marshal([]any{manifestDigestBytes, authBlock})
	if err != nil {
		return nil, fmt.Errorf("encode auth wrapper: %w", err)
	}

	envelope := map[any]any{
		uint64(2):       authWrapper,
		uint64(3):       manifest,
		opts.PayloadURI: opts.Payload,
	}
	if opts.InsecureAppMetadata {
		metadata, err := appMetadata(enc, opts.AppCommand, opts.WasmFile)
		if err != nil {
			return nil, err
		}
		envelope["twep-app-v1-metadata"] = metadata
	}
	envelopeBytes, err := enc.Marshal(cbor.Tag{Number: 107, Content: envelope})
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	return &Artifact{
		Envelope:      envelopeBytes,
		ComponentID:   componentID,
		PayloadSHA256: payloadDigest,
		KID:           kid,
	}, nil
}

func appMetadata(enc cbor.EncMode, command, wasmFile string) ([]byte, error) {
	metadata, err := enc.Marshal(map[string]any{
		"schema_version": uint64(1),
		"command":        command,
		"component_id":   "twep.example." + command,
		"version":        "sequence",
		"abi":            "twep-app-v1",
		"wasm_file":      wasmFile,
	})
	if err != nil {
		return nil, fmt.Errorf("encode app metadata: %w", err)
	}
	return metadata, nil
}

func DemoDeveloperVerifier() (cose.Verifier, error) {
	privateKey, _, err := demoDeveloperKey()
	if err != nil {
		return nil, err
	}
	return cose.NewVerifier(cose.AlgorithmESP256, privateKey.Public())
}

func DemoDeveloperSign1(payload []byte) ([]byte, error) {
	out, _, err := signDemoDeveloper(payload, false)
	return out, err
}

func DemoTAMVerifier() (cose.Verifier, error) {
	var key cose.Key
	if err := cbor.Unmarshal(demokeys.DemoTAMESP256PrivateCOSEKey(), &key); err != nil {
		return nil, fmt.Errorf("decode demo TAM key: %w", err)
	}
	verifier, err := key.Verifier()
	if err != nil {
		return nil, fmt.Errorf("create demo TAM verifier: %w", err)
	}
	return verifier, nil
}

func DemoTAMSign1(payload []byte) ([]byte, error) {
	out, _, err := signDemoTAM(payload, false)
	return out, err
}

type signerFunc func(payload []byte, detached bool) ([]byte, []byte, error)

func signDemoDeveloper(payload []byte, detached bool) ([]byte, []byte, error) {
	privateKey, kid, err := demoDeveloperKey()
	if err != nil {
		return nil, nil, err
	}
	out, err := signDetachedOrAttached(payload, privateKey, kid, detached)
	return out, kid, err
}

func signDetachedOrAttached(payload []byte, key *ecdsa.PrivateKey, kid []byte, detached bool) ([]byte, error) {
	signer, err := cose.NewSigner(cose.AlgorithmESP256, key)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmESP256
	msg.Headers.Unprotected[cose.HeaderLabelKeyID] = kid
	msg.Payload = payload
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign manifest digest: %w", err)
	}
	if detached {
		msg.Payload = nil
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encode auth block: %w", err)
	}
	return out, nil
}

func signDemoTAM(payload []byte, detached bool) ([]byte, []byte, error) {
	return signDemoTAMWithProtectedHeaders(payload, detached, nil)
}

func signDemoTAMWithProtectedHeaders(payload []byte, detached bool, protected cose.ProtectedHeader) ([]byte, []byte, error) {
	var key cose.Key
	if err := cbor.Unmarshal(demokeys.DemoTAMESP256PrivateCOSEKey(), &key); err != nil {
		return nil, nil, fmt.Errorf("decode demo TAM key: %w", err)
	}
	signer, err := key.Signer()
	if err != nil {
		return nil, nil, fmt.Errorf("create demo TAM signer: %w", err)
	}
	alg, err := key.AlgorithmOrDefault()
	if err != nil {
		return nil, nil, fmt.Errorf("detect demo TAM alg: %w", err)
	}
	kid, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("derive demo TAM kid: %w", err)
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = alg
	for label, value := range protected {
		msg.Headers.Protected[label] = value
	}
	msg.Headers.Unprotected[cose.HeaderLabelKeyID] = kid
	msg.Payload = payload
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, nil, fmt.Errorf("sign demo TAM payload: %w", err)
	}
	if detached {
		msg.Payload = nil
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, nil, fmt.Errorf("encode demo TAM sign1: %w", err)
	}
	return out, kid, nil
}

func demoDeveloperKey() (*ecdsa.PrivateKey, []byte, error) {
	block, _ := pem.Decode(demokeys.DemoTCSignerESP256PrivateKeyPEM())
	if block == nil {
		return nil, nil, fmt.Errorf("decode demo developer private key pem")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse demo developer private key: %w", err)
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("demo developer private key is %T, want *ecdsa.PrivateKey", key)
	}
	publicKey, err := cose.NewKeyEC2(cose.AlgorithmESP256, privateKey.X.Bytes(), privateKey.Y.Bytes(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create public cose key: %w", err)
	}
	kid, err := publicKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("derive developer key kid: %w", err)
	}
	return privateKey, kid, nil
}
