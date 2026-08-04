// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package twepwr

/*
#cgo CFLAGS: -I${SRCDIR}/../../lib/twep-wr/include
#cgo LDFLAGS: -L${SRCDIR}/../../build -ltwep_wr -Wl,-rpath,${SRCDIR}/../../build
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "twep_wr.h"

extern int32_t twepwrHTTPPostCallback(
	void *user_data,
	uint8_t *url,
	size_t url_len,
	uint8_t *body,
	size_t body_len,
	uint8_t *buf,
	size_t buf_cap,
	size_t *out_len);

static inline twep_wr_http_post_fn twepwr_http_post_callback(void) {
	return (twep_wr_http_post_fn)twepwrHTTPPostCallback;
}

static inline void *twepwr_hostio_user_data(uintptr_t v) {
	return (void *)v;
}
*/
import "C"

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime/cgo"
	"time"
	"unsafe"

	"github.com/s-miyazawa/twep-system/internal/cborcodec"
	"github.com/s-miyazawa/twep-system/internal/teepbroker"
)

const ABIVersion = 3

type Context struct {
	ptr        *C.twep_wr_context_t
	config     Config
	hostHandle cgo.Handle
	httpClient *http.Client
}

type Config struct {
	StateDir             string
	ResolverMode         string
	AttestamURL          string
	InsecureDemo         bool
	InsecureDemoAgentKey string
	DefaultTimeoutMS     uint32
	MaxRequestBytes      uint32
	MaxResponseBytes     uint32
}

// allowsDevelopmentAttesTAMCallbacks identifies the two explicitly
// development-only AttesTAM paths. attestam-verified keeps InsecureDemo false
// so it cannot silently select the attestam-insecure protocol behavior.
func (c Config) allowsDevelopmentAttesTAMCallbacks() bool {
	return (c.ResolverMode == "attestam-insecure" && c.InsecureDemo) ||
		(c.ResolverMode == "attestam-verified" && !c.InsecureDemo)
}

type StatusError struct {
	Status  string
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("twep_wr_execute: %s", e.Message)
}

func LinkedABIVersion() uint32 {
	return uint32(C.twep_wr_get_abi_version())
}

func Init(stateDir string) (*Context, error) {
	return InitWithConfig(Config{StateDir: stateDir})
}

func InitWithConfig(config Config) (*Context, error) {
	if LinkedABIVersion() != ABIVersion {
		return nil, fmt.Errorf("twep-wr ABI mismatch: got %d want %d", LinkedABIVersion(), ABIVersion)
	}
	if config.ResolverMode == "" {
		config.ResolverMode = "mock"
	}
	if config.InsecureDemoAgentKey == "" {
		config.InsecureDemoAgentKey = "default"
	}
	if config.InsecureDemoAgentKey != "default" && config.InsecureDemoAgentKey != "alternate" {
		return nil, fmt.Errorf("invalid insecure demo agent key mode %q", config.InsecureDemoAgentKey)
	}
	if config.InsecureDemoAgentKey != "default" && !config.allowsDevelopmentAttesTAMCallbacks() {
		return nil, fmt.Errorf("alternate insecure demo agent key requires an explicitly configured development AttesTAM mode")
	}
	if config.DefaultTimeoutMS == 0 {
		config.DefaultTimeoutMS = 5000
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = 16 * 1024 * 1024
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 16 * 1024 * 1024
	}
	cState := C.CString(config.StateDir)
	cResolver := C.CString(config.ResolverMode)
	cURL := C.CString(config.AttestamURL)
	defer C.free(unsafe.Pointer(cState))
	defer C.free(unsafe.Pointer(cResolver))
	defer C.free(unsafe.Pointer(cURL))

	cfg := C.twep_wr_config_t{
		state_dir:          cState,
		resolver_mode:      cResolver,
		attestam_url:       cURL,
		insecure_demo_mode: C.bool(config.InsecureDemo),
		default_timeout_ms: C.uint32_t(config.DefaultTimeoutMS),
		max_request_bytes:  C.uint32_t(config.MaxRequestBytes),
		max_response_bytes: C.uint32_t(config.MaxResponseBytes),
	}
	var raw *C.twep_wr_context_t
	st := C.twep_wr_init(&cfg, &raw)
	if st != C.TWEP_WR_OK {
		return nil, fmt.Errorf("twep_wr_init: %s", statusString(st))
	}
	ctx := &Context{
		ptr:    raw,
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	ctx.hostHandle = cgo.NewHandle(ctx)
	hostIO := C.twep_wr_host_io_t{
		http_post: C.twepwr_http_post_callback(),
		user_data: C.twepwr_hostio_user_data(C.uintptr_t(ctx.hostHandle)),
	}
	st = C.twep_wr_set_host_io(ctx.ptr, &hostIO)
	if st != C.TWEP_WR_OK {
		ctx.hostHandle.Delete()
		C.twep_wr_shutdown(raw)
		return nil, fmt.Errorf("twep_wr_set_host_io: %s", statusString(st))
	}
	if err := ctx.writeDevAgentPublicKey(); err != nil {
		ctx.Shutdown()
		return nil, err
	}
	return ctx, nil
}

func (c *Context) Execute(request []byte) ([]byte, error) {
	if c == nil || c.ptr == nil {
		return nil, fmt.Errorf("twep_wr context is nil")
	}
	normalized, err := NormalizeRequest(request)
	if err != nil {
		return nil, err
	}
	return c.ExecuteNormalized(normalized)
}

type NormalizedRequest struct {
	RequestID        string
	Command          string
	AppInputCBOR     []byte
	RequestTimeoutMS uint32
}

func NormalizeRequest(request []byte) (NormalizedRequest, error) {
	req, err := cborcodec.DecodeRequest(request)
	if err != nil {
		return NormalizedRequest{}, err
	}
	appInput, err := cborcodec.BuildAppInput(req)
	if err != nil {
		return NormalizedRequest{}, fmt.Errorf("build app input: %w", err)
	}
	var timeout uint32
	if req.Options.TimeoutMS > uint64(^uint32(0)) {
		return NormalizedRequest{}, fmt.Errorf("request timeout_ms too large")
	}
	timeout = uint32(req.Options.TimeoutMS)
	return NormalizedRequest{
		RequestID:        req.RequestID,
		Command:          req.Command,
		AppInputCBOR:     appInput,
		RequestTimeoutMS: timeout,
	}, nil
}

func (c *Context) ExecuteNormalized(request NormalizedRequest) ([]byte, error) {
	if c == nil || c.ptr == nil {
		return nil, fmt.Errorf("twep_wr context is nil")
	}
	cRequestID := C.CString(request.RequestID)
	cCommand := C.CString(request.Command)
	defer C.free(unsafe.Pointer(cRequestID))
	defer C.free(unsafe.Pointer(cCommand))

	var inPtr *C.uint8_t
	if len(request.AppInputCBOR) > 0 {
		raw := C.CBytes(request.AppInputCBOR)
		defer C.free(raw)
		inPtr = (*C.uint8_t)(raw)
	}
	in := C.twep_wr_bytes_t{ptr: inPtr, len: C.size_t(len(request.AppInputCBOR))}
	normalized := C.twep_wr_normalized_request_t{
		request_id:         cRequestID,
		command:            cCommand,
		app_input_cbor:     in,
		request_timeout_ms: C.uint32_t(request.RequestTimeoutMS),
	}
	var out C.twep_wr_owned_bytes_t
	st := C.twep_wr_execute(c.ptr, &normalized, &out)
	if st != C.TWEP_WR_OK {
		return nil, &StatusError{Status: c.statusCode(st), Message: statusString(st)}
	}
	defer C.twep_wr_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len)), nil
}

func (c *Context) Shutdown() {
	if c == nil || c.ptr == nil {
		return
	}
	_, _ = C.twep_wr_set_host_io(c.ptr, (*C.twep_wr_host_io_t)(nil))
	C.twep_wr_shutdown(c.ptr)
	c.ptr = nil
	if c.hostHandle != 0 {
		c.hostHandle.Delete()
		c.hostHandle = 0
	}
}

//export twepwrHTTPPostCallback
func twepwrHTTPPostCallback(userData unsafe.Pointer, urlPtr *C.uint8_t, urlLen C.size_t, bodyPtr *C.uint8_t, bodyLen C.size_t, buf *C.uint8_t, bufCap C.size_t, outLen *C.size_t) C.int32_t {
	if userData == nil || urlPtr == nil || outLen == nil {
		return 1
	}
	*outLen = 0
	handle := cgo.Handle(uintptr(userData))
	ctx, ok := handle.Value().(*Context)
	if !ok || ctx == nil {
		return 1
	}
	url := string(C.GoBytes(unsafe.Pointer(urlPtr), C.int(urlLen)))
	var body []byte
	if bodyLen != 0 {
		if bodyPtr == nil {
			return 1
		}
		body = C.GoBytes(unsafe.Pointer(bodyPtr), C.int(bodyLen))
	}
	result := teepbroker.HTTPPost(ctx.httpClient, teepbroker.HTTPPostConfig{
		ResolverMode:     ctx.config.ResolverMode,
		AttestamURL:      ctx.config.AttestamURL,
		InsecureDemo:     ctx.config.InsecureDemo,
		MaxResponseBytes: ctx.config.MaxResponseBytes,
	}, url, body)
	response := result.Response
	*outLen = C.size_t(len(response))
	if result.Status != teepbroker.HostStatusOK {
		return C.int32_t(result.Status)
	}
	if C.size_t(len(response)) > bufCap {
		return 2
	}
	if len(response) != 0 && buf != nil {
		C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&response[0]), C.size_t(len(response)))
	}
	return 0
}

func (c *Context) demoAgentKeyCBOR() []byte {
	if c != nil && c.config.InsecureDemoAgentKey == "alternate" {
		return teepbroker.AlternateDemoAgentKeyCBOR()
	}
	return teepbroker.DemoTrustedAgentKeyCBOR()
}

func (c *Context) writeDevAgentPublicKey() error {
	if c == nil || c.config.InsecureDemoAgentKey != "alternate" {
		return nil
	}
	publicKey, err := teepbroker.PublicCOSEKeyCBOR(c.demoAgentKeyCBOR())
	if err != nil {
		return fmt.Errorf("derive alternate demo agent public key: %w", err)
	}
	dir := filepath.Join(c.config.StateDir, "teep-agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create teep-agent state dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dev-agent-public-key.cbor"), publicKey, 0o600); err != nil {
		return fmt.Errorf("write alternate demo agent public key: %w", err)
	}
	return nil
}

func statusString(st C.twep_wr_status_t) string {
	return C.GoString(C.twep_wr_status_string(st))
}

func (c *Context) statusCode(st C.twep_wr_status_t) string {
	switch st {
	case C.TWEP_WR_ERR_INVALID_ARGUMENT:
		return "daemon.request"
	case C.TWEP_WR_ERR_CATALOG:
		return "catalog.not_found"
	case C.TWEP_WR_ERR_TEEP:
		if c != nil && c.config.ResolverMode == "attestam-verified" {
			return "teep.verified_required"
		}
		return "teep.protocol"
	case C.TWEP_WR_ERR_TEEP_NETWORK:
		return "teep.network"
	case C.TWEP_WR_ERR_TEEP_ATTESTATION_UNSUPPORTED:
		return "teep.attestation_unsupported"
	case C.TWEP_WR_ERR_WASM_LOAD:
		return "app.runtime"
	case C.TWEP_WR_ERR_WASM_ABI:
		return "app.abi"
	case C.TWEP_WR_ERR_WASM_RUNTIME:
		return "app.runtime"
	case C.TWEP_WR_ERR_SECURITY:
		return "app.hash_mismatch"
	case C.TWEP_WR_ERR_WASM_SIGNATURE:
		return "app.signature_unverified"
	case C.TWEP_WR_ERR_NO_MEMORY:
		return "app.runtime"
	default:
		return "app.runtime"
	}
}
