// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package verifiedteep

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	coseSign1Tag           = 18
	suitEnvelopeTag        = 107
	teepTypeUpdate  uint64 = 3

	verificationCOSESign1                 = "COSE_Sign1 signature"
	verificationTEEPTokenSessionBinding   = "TEEP token/session binding"
	verificationSUITAuthenticationWrapper = "SUIT manifest authentication wrapper"
	verificationSUITSequenceFreshness     = "SUIT sequence freshness"
)

var componentNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

type ComponentKind string

const (
	ComponentKindUnknown ComponentKind = "unknown"
	ComponentKindApp     ComponentKind = "twep-app-v1"
	ComponentKindCatalog ComponentKind = "twep-catalog-v1"
)

type Update struct {
	TEEPType             uint64
	ManifestCount        uint64
	UpdateToken          []byte
	COSEPayload          []byte
	SUITEnvelope         []byte
	SUITManifest         []byte
	SUITAuthDigestRaw    []byte
	SUITAuthBlock        []byte
	ComponentIDCBOR      []byte
	ComponentKind        ComponentKind
	AppCommand           string
	CatalogName          string
	SequenceNumber       uint64
	PayloadURI           string
	Payload              []byte
	PayloadSHA256        [32]byte
	SUITPayloadDigest    []byte
	SUITPayloadDigestRaw []byte
	FixtureVerified      bool
	Verified             bool
	VerificationRequired []string
}

type FixtureVerifyOptions struct {
	TEEPMessageVerifier     cose.Verifier
	SUITAuthVerifier        cose.Verifier
	ExpectedSessionToken    []byte
	LastSequenceByComponent map[string]uint64
}

func (u *Update) IsAppInstallCandidate() bool {
	return u != nil &&
		u.ComponentKind == ComponentKindApp &&
		u.AppCommand != "" &&
		u.CatalogName == ""
}

func (u *Update) IsCatalogUpdateCandidate() bool {
	return u != nil &&
		u.ComponentKind == ComponentKindCatalog &&
		u.CatalogName != "" &&
		u.AppCommand == ""
}

type coseSign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

type teepMessage struct {
	_       struct{} `cbor:",toarray"`
	MsgType uint64
	Options map[uint64]any
}

type suitDigest struct {
	_     struct{} `cbor:",toarray"`
	Alg   int64
	Bytes []byte
}

func ParseUpdateCOSE(input []byte) (*Update, error) {
	payload, err := coseSign1Payload(input)
	if err != nil {
		return nil, err
	}
	update, err := ParseUpdatePayload(payload)
	if err != nil {
		return nil, err
	}
	update.COSEPayload = append([]byte(nil), payload...)
	update.Verified = false
	update.VerificationRequired = []string{
		verificationCOSESign1,
		verificationTEEPTokenSessionBinding,
		verificationSUITAuthenticationWrapper,
		verificationSUITSequenceFreshness,
	}
	return update, nil
}

func ParseUpdateCOSEVerified(input []byte, verifier cose.Verifier) (*Update, error) {
	payload, err := verifyCOSESign1Payload(input, verifier)
	if err != nil {
		return nil, err
	}
	update, err := ParseUpdatePayload(payload)
	if err != nil {
		return nil, err
	}
	update.COSEPayload = append([]byte(nil), payload...)
	update.Verified = false
	update.VerificationRequired = []string{
		verificationTEEPTokenSessionBinding,
		verificationSUITAuthenticationWrapper,
		verificationSUITSequenceFreshness,
	}
	return update, nil
}

func VerifyFixtureUpdateCOSE(input []byte, opts FixtureVerifyOptions) (*Update, error) {
	update, err := ParseUpdateCOSEVerified(input, opts.TEEPMessageVerifier)
	if err != nil {
		return nil, err
	}
	if err := update.VerifySessionToken(opts.ExpectedSessionToken); err != nil {
		return nil, err
	}
	if err := update.VerifySUITAuthenticationWrapper(opts.SUITAuthVerifier); err != nil {
		return nil, err
	}
	if err := update.VerifySequenceFreshness(opts.LastSequenceByComponent); err != nil {
		return nil, err
	}
	update.FixtureVerified = len(update.VerificationRequired) == 0
	update.Verified = false
	return update, nil
}

func (u *Update) VerifySUITAuthenticationWrapper(verifier cose.Verifier) error {
	if u == nil {
		return fmt.Errorf("update is nil")
	}
	if verifier == nil {
		return fmt.Errorf("suit auth verifier is nil")
	}
	if len(u.SUITAuthDigestRaw) == 0 {
		return fmt.Errorf("suit auth digest is empty")
	}
	if len(u.SUITAuthBlock) == 0 {
		return fmt.Errorf("suit auth block is empty")
	}

	wantDigest, err := manifestDigestRaw(u.SUITManifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(u.SUITAuthDigestRaw, wantDigest) {
		return fmt.Errorf("suit auth digest does not match manifest")
	}

	var sign1 cose.Sign1Message
	if err := cbor.Unmarshal(u.SUITAuthBlock, &sign1); err != nil {
		return fmt.Errorf("decode suit auth cose sign1: %w", err)
	}
	if sign1.Payload != nil {
		return fmt.Errorf("suit auth cose sign1 payload is attached, want detached")
	}
	sign1.Payload = u.SUITAuthDigestRaw
	if err := sign1.Verify(nil, verifier); err != nil {
		return fmt.Errorf("verify suit auth cose sign1: %w", err)
	}
	u.VerificationRequired = removeVerificationRequirement(u.VerificationRequired, verificationSUITAuthenticationWrapper)
	u.Verified = false
	return nil
}

func (u *Update) VerifySessionToken(expected []byte) error {
	if u == nil {
		return fmt.Errorf("update is nil")
	}
	if len(expected) == 0 {
		return fmt.Errorf("expected teep session token is empty")
	}
	if len(u.UpdateToken) == 0 {
		return fmt.Errorf("teep update token is empty")
	}
	if !bytes.Equal(u.UpdateToken, expected) {
		return fmt.Errorf("teep update token mismatch")
	}
	u.VerificationRequired = removeVerificationRequirement(u.VerificationRequired, verificationTEEPTokenSessionBinding)
	u.Verified = false
	return nil
}

func (u *Update) VerifySequenceFreshness(lastByComponent map[string]uint64) error {
	if u == nil {
		return fmt.Errorf("update is nil")
	}
	if lastByComponent == nil {
		return fmt.Errorf("sequence freshness store is nil")
	}
	if len(u.ComponentIDCBOR) == 0 {
		return fmt.Errorf("suit component id is empty")
	}
	key := string(u.ComponentIDCBOR)
	if last, ok := lastByComponent[key]; ok && u.SequenceNumber <= last {
		return fmt.Errorf("suit sequence rollback: got %d, last %d", u.SequenceNumber, last)
	}
	lastByComponent[key] = u.SequenceNumber
	u.VerificationRequired = removeVerificationRequirement(u.VerificationRequired, verificationSUITSequenceFreshness)
	u.Verified = false
	return nil
}

func ParseUpdatePayload(payload []byte) (*Update, error) {
	var msg teepMessage
	if err := cbor.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("decode teep message: %w", err)
	}
	if msg.MsgType != teepTypeUpdate {
		return nil, fmt.Errorf("teep message type %d, want Update", msg.MsgType)
	}
	manifestList, ok := msg.Options[uint64(9)].([]any)
	if !ok || len(manifestList) == 0 {
		return nil, fmt.Errorf("teep update missing manifest-list")
	}
	envelope, ok := manifestList[0].([]byte)
	if !ok || len(envelope) == 0 {
		return nil, fmt.Errorf("teep update manifest-list[0] is not bytes")
	}
	update, err := ParseSUITEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	update.TEEPType = msg.MsgType
	update.ManifestCount = uint64(len(manifestList))
	if token, ok := msg.Options[uint64(19)].([]byte); ok {
		update.UpdateToken = append([]byte(nil), token...)
	}
	return update, nil
}

func ParseSUITEnvelope(envelope []byte) (*Update, error) {
	var tag cbor.Tag
	if err := cbor.Unmarshal(envelope, &tag); err != nil {
		return nil, fmt.Errorf("decode suit envelope tag: %w", err)
	}
	if tag.Number != suitEnvelopeTag {
		return nil, fmt.Errorf("suit envelope tag = %d, want %d", tag.Number, suitEnvelopeTag)
	}
	content, ok := tag.Content.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("suit envelope content = %T, want map", tag.Content)
	}
	manifest, ok := content[uint64(3)].([]byte)
	if !ok || len(manifest) == 0 {
		return nil, fmt.Errorf("suit envelope missing manifest")
	}
	authDigestRaw, authBlock, err := parseSUITAuthWrapper(content[uint64(2)])
	if err != nil {
		return nil, err
	}
	manifestDigest, err := manifestDigestRaw(manifest)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(authDigestRaw, manifestDigest) {
		return nil, fmt.Errorf("suit auth digest does not match manifest")
	}
	info, err := parseSUITManifest(manifest)
	if err != nil {
		return nil, err
	}
	payload, ok := content[info.PayloadURI].([]byte)
	if !ok {
		return nil, fmt.Errorf("suit envelope missing payload %q", info.PayloadURI)
	}
	payloadSHA256 := sha256.Sum256(payload)
	if !bytes.Equal(payloadSHA256[:], info.PayloadDigestSHA256) {
		return nil, fmt.Errorf("suit payload digest mismatch")
	}
	componentKind, appCommand, catalogName, err := ParseComponentID(info.ComponentIDCBOR)
	if err != nil {
		return nil, err
	}
	return &Update{
		SUITEnvelope:         append([]byte(nil), envelope...),
		SUITManifest:         append([]byte(nil), manifest...),
		SUITAuthDigestRaw:    append([]byte(nil), authDigestRaw...),
		SUITAuthBlock:        append([]byte(nil), authBlock...),
		ComponentIDCBOR:      append([]byte(nil), info.ComponentIDCBOR...),
		ComponentKind:        componentKind,
		AppCommand:           appCommand,
		CatalogName:          catalogName,
		SequenceNumber:       info.SequenceNumber,
		PayloadURI:           info.PayloadURI,
		Payload:              append([]byte(nil), payload...),
		PayloadSHA256:        payloadSHA256,
		SUITPayloadDigest:    append([]byte(nil), info.PayloadDigestSHA256...),
		SUITPayloadDigestRaw: append([]byte(nil), info.PayloadDigestRaw...),
	}, nil
}

func ParseComponentID(componentIDCBOR []byte) (ComponentKind, string, string, error) {
	var parts [][]byte
	if err := cbor.Unmarshal(componentIDCBOR, &parts); err != nil {
		return ComponentKindUnknown, "", "", fmt.Errorf("decode suit component id: %w", err)
	}
	if len(parts) != 2 {
		return ComponentKindUnknown, "", "", fmt.Errorf("suit component id len = %d, want 2", len(parts))
	}
	name := string(parts[1])
	if !componentNameRE.MatchString(name) {
		return ComponentKindUnknown, "", "", fmt.Errorf("suit component id name %q is not allowed", name)
	}
	switch string(parts[0]) {
	case string(ComponentKindApp):
		return ComponentKindApp, name, "", nil
	case string(ComponentKindCatalog):
		return ComponentKindCatalog, "", name, nil
	default:
		return ComponentKindUnknown, "", "", fmt.Errorf("unsupported suit component kind %q", string(parts[0]))
	}
}

func parseSUITAuthWrapper(value any) ([]byte, []byte, error) {
	authWrapperBytes, ok := value.([]byte)
	if !ok || len(authWrapperBytes) == 0 {
		return nil, nil, fmt.Errorf("suit envelope missing auth wrapper")
	}
	var authWrapper [][]byte
	if err := cbor.Unmarshal(authWrapperBytes, &authWrapper); err != nil {
		return nil, nil, fmt.Errorf("decode suit auth wrapper: %w", err)
	}
	if len(authWrapper) != 2 {
		return nil, nil, fmt.Errorf("suit auth wrapper len = %d, want 2", len(authWrapper))
	}
	if _, err := decodeSHA256Digest(authWrapper[0], "suit auth manifest digest"); err != nil {
		return nil, nil, err
	}
	if len(authWrapper[1]) == 0 {
		return nil, nil, fmt.Errorf("suit auth block is empty")
	}
	return append([]byte(nil), authWrapper[0]...), append([]byte(nil), authWrapper[1]...), nil
}

func manifestDigestRaw(manifest []byte) ([]byte, error) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create canonical cbor enc mode: %w", err)
	}
	manifestBstr, err := enc.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode suit manifest bstr: %w", err)
	}
	digest := sha256.Sum256(manifestBstr)
	digestRaw, err := enc.Marshal(suitDigest{Alg: -16, Bytes: digest[:]})
	if err != nil {
		return nil, fmt.Errorf("encode suit manifest digest: %w", err)
	}
	return digestRaw, nil
}

type suitManifestInfo struct {
	ComponentIDCBOR     []byte
	SequenceNumber      uint64
	PayloadURI          string
	PayloadDigestRaw    []byte
	PayloadDigestSHA256 []byte
}

func parseSUITManifest(manifest []byte) (*suitManifestInfo, error) {
	var m map[uint64]any
	if err := cbor.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("decode suit manifest: %w", err)
	}
	sequence, ok := m[uint64(2)].(uint64)
	if !ok {
		return nil, fmt.Errorf("suit manifest missing sequence number")
	}
	common, ok := m[uint64(3)].([]byte)
	if !ok || len(common) == 0 {
		return nil, fmt.Errorf("suit manifest missing common")
	}
	payloadFetch, ok := m[uint64(16)].([]byte)
	if !ok || len(payloadFetch) == 0 {
		return nil, fmt.Errorf("suit manifest missing payload-fetch")
	}
	componentID, digestRaw, digestSHA256, err := parseSUITCommon(common)
	if err != nil {
		return nil, err
	}
	payloadURI, err := parsePayloadURI(payloadFetch)
	if err != nil {
		return nil, err
	}
	return &suitManifestInfo{
		ComponentIDCBOR:     componentID,
		SequenceNumber:      sequence,
		PayloadURI:          payloadURI,
		PayloadDigestRaw:    digestRaw,
		PayloadDigestSHA256: digestSHA256,
	}, nil
}

func parseSUITCommon(common []byte) ([]byte, []byte, []byte, error) {
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(common, &raw); err != nil {
		return nil, nil, nil, fmt.Errorf("decode suit common: %w", err)
	}
	componentsRaw, ok := raw[uint64(2)]
	if !ok {
		return nil, nil, nil, fmt.Errorf("suit common missing components")
	}
	var components []cbor.RawMessage
	if err := cbor.Unmarshal(componentsRaw, &components); err != nil || len(components) == 0 {
		return nil, nil, nil, fmt.Errorf("decode suit components: %w", err)
	}
	sharedSequenceBstr, ok := raw[uint64(4)]
	if !ok {
		return nil, nil, nil, fmt.Errorf("suit common missing shared sequence")
	}
	var sharedSequence []byte
	if err := cbor.Unmarshal(sharedSequenceBstr, &sharedSequence); err != nil {
		return nil, nil, nil, fmt.Errorf("decode suit shared sequence bstr: %w", err)
	}
	digestRaw, digestSHA256, err := parsePayloadDigest(sharedSequence)
	if err != nil {
		return nil, nil, nil, err
	}
	return append([]byte(nil), components[0]...), digestRaw, digestSHA256, nil
}

func parsePayloadDigest(sequence []byte) ([]byte, []byte, error) {
	var items []cbor.RawMessage
	if err := cbor.Unmarshal(sequence, &items); err != nil {
		return nil, nil, fmt.Errorf("decode suit shared sequence: %w", err)
	}
	for i := 0; i+1 < len(items); i++ {
		var command uint64
		if err := cbor.Unmarshal(items[i], &command); err != nil || command != 20 {
			continue
		}
		var params map[uint64]cbor.RawMessage
		if err := cbor.Unmarshal(items[i+1], &params); err != nil {
			return nil, nil, fmt.Errorf("decode suit digest params: %w", err)
		}
		raw, ok := params[uint64(3)]
		if !ok {
			continue
		}
		var digestBytes []byte
		if err := cbor.Unmarshal(raw, &digestBytes); err != nil {
			return nil, nil, fmt.Errorf("decode suit digest bytes wrapper: %w", err)
		}
		digest, err := decodeSHA256Digest(digestBytes, "suit payload digest")
		if err != nil {
			return nil, nil, err
		}
		return digestBytes, append([]byte(nil), digest.Bytes...), nil
	}
	return nil, nil, fmt.Errorf("suit shared sequence missing payload digest")
}

func decodeSHA256Digest(input []byte, context string) (*suitDigest, error) {
	var digest suitDigest
	if err := cbor.Unmarshal(input, &digest); err != nil {
		return nil, fmt.Errorf("decode %s: %w", context, err)
	}
	if digest.Alg != -16 {
		return nil, fmt.Errorf("%s alg = %d, want SHA-256", context, digest.Alg)
	}
	if len(digest.Bytes) != sha256.Size {
		return nil, fmt.Errorf("%s len = %d, want %d", context, len(digest.Bytes), sha256.Size)
	}
	return &digest, nil
}

func parsePayloadURI(sequence []byte) (string, error) {
	var items []cbor.RawMessage
	if err := cbor.Unmarshal(sequence, &items); err != nil {
		return "", fmt.Errorf("decode suit payload-fetch sequence: %w", err)
	}
	for i := 0; i+1 < len(items); i++ {
		var command uint64
		if err := cbor.Unmarshal(items[i], &command); err != nil || command != 20 {
			continue
		}
		var params map[uint64]string
		if err := cbor.Unmarshal(items[i+1], &params); err != nil {
			return "", fmt.Errorf("decode suit payload-fetch params: %w", err)
		}
		if uri := params[uint64(21)]; uri != "" {
			return uri, nil
		}
	}
	return "", fmt.Errorf("suit payload-fetch missing uri")
}

func coseSign1Payload(input []byte) ([]byte, error) {
	var tag cbor.Tag
	if err := cbor.Unmarshal(input, &tag); err != nil {
		return nil, fmt.Errorf("decode cose sign1 tag: %w", err)
	}
	if tag.Number != coseSign1Tag {
		return nil, fmt.Errorf("cose tag = %d, want %d", tag.Number, coseSign1Tag)
	}
	content, err := cbor.Marshal(tag.Content)
	if err != nil {
		return nil, fmt.Errorf("re-encode cose sign1 content: %w", err)
	}
	var msg coseSign1Message
	if err := cbor.Unmarshal(content, &msg); err != nil {
		return nil, fmt.Errorf("decode cose sign1 content: %w", err)
	}
	if len(msg.Payload) == 0 {
		return nil, fmt.Errorf("cose sign1 payload is empty or detached")
	}
	return append([]byte(nil), msg.Payload...), nil
}

func verifyCOSESign1Payload(input []byte, verifier cose.Verifier) ([]byte, error) {
	if verifier == nil {
		return nil, fmt.Errorf("cose sign1 verifier is nil")
	}
	var msg cose.Sign1Message
	if err := cbor.Unmarshal(input, &msg); err != nil {
		return nil, fmt.Errorf("decode cose sign1: %w", err)
	}
	if len(msg.Payload) == 0 {
		return nil, fmt.Errorf("cose sign1 payload is empty or detached")
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("verify cose sign1: %w", err)
	}
	return append([]byte(nil), msg.Payload...), nil
}

func removeVerificationRequirement(values []string, remove string) []string {
	out := values[:0]
	for _, value := range values {
		if value != remove {
			out = append(out, value)
		}
	}
	return out
}
