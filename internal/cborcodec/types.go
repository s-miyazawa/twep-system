// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cborcodec

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
)

const SchemaVersion = 1

type TypedValue struct {
	Type  string
	Value any
}

type RequestOptions struct {
	TimeoutMS    uint64
	OutputFormat string
	Verbose      bool
}

type Request struct {
	SchemaVersion int
	RequestID     string
	Command       string
	Argv          []string
	Inferred      []TypedValue
	AppInput      []byte
	Stdin         []byte
	Files         map[string][]byte
	Metadata      map[string]any
	Cwd           string
	Options       RequestOptions
}

type TwepError struct {
	Code    string
	Message string
	Details any
}

type Response struct {
	SchemaVersion int
	RequestID     string
	Status        string
	ExitCode      int
	Stdout        []byte
	Stderr        []byte
	AppOutput     []byte
	Result        any
	Error         *TwepError
}

type AppOutput struct {
	SchemaVersion int
	Status        string
	Stdout        []byte
	Stderr        []byte
	Files         map[string][]byte
	Metadata      map[string]any
	Result        any
	Error         *TwepError
}

func NewRequestID() string {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "req-fallback"
	}
	return hex.EncodeToString(b[:])
}

func EncodeRequest(r Request) ([]byte, error) {
	if r.SchemaVersion == 0 {
		r.SchemaVersion = SchemaVersion
	}
	m := map[string]any{
		"schema_version":  uint64(r.SchemaVersion),
		"request_id":      r.RequestID,
		"command":         r.Command,
		"argv":            stringSliceToAny(r.Argv),
		"inferred_params": typedValuesToAny(r.Inferred),
		"cwd":             r.Cwd,
	}
	if r.AppInput != nil {
		m["app_input"] = r.AppInput
	}
	if r.Stdin != nil {
		m["stdin"] = r.Stdin
	}
	if len(r.Files) != 0 {
		files := make(map[string]any, len(r.Files))
		for k, v := range r.Files {
			files[k] = v
		}
		m["files"] = files
	}
	if len(r.Metadata) != 0 {
		m["metadata"] = r.Metadata
	}
	opts := map[string]any{}
	if r.Options.TimeoutMS != 0 {
		opts["timeout_ms"] = r.Options.TimeoutMS
	}
	if r.Options.OutputFormat != "" {
		opts["output_format"] = r.Options.OutputFormat
	}
	if r.Options.Verbose {
		opts["verbose"] = true
	}
	if len(opts) != 0 {
		m["options"] = opts
	}
	return encodeValue(m)
}

func DecodeRequest(b []byte) (Request, error) {
	v, err := decodeValue(b)
	if err != nil {
		return Request{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Request{}, errors.New("request is not map")
	}
	var r Request
	r.SchemaVersion = int(asUint(m["schema_version"]))
	r.RequestID = asString(m["request_id"])
	r.Command = asString(m["command"])
	r.Argv = asStringSlice(m["argv"])
	r.Inferred = asTypedValues(m["inferred_params"])
	r.AppInput, _ = m["app_input"].([]byte)
	r.Stdin, _ = m["stdin"].([]byte)
	r.Files = asByteMap(m["files"])
	if metadata, ok := m["metadata"].(map[string]any); ok {
		r.Metadata = metadata
	}
	r.Cwd = asString(m["cwd"])
	if opts, ok := m["options"].(map[string]any); ok {
		r.Options.TimeoutMS = asUint(opts["timeout_ms"])
		r.Options.OutputFormat = asString(opts["output_format"])
		if verbose, ok := opts["verbose"].(bool); ok {
			r.Options.Verbose = verbose
		}
	}
	if r.SchemaVersion != SchemaVersion {
		return Request{}, fmt.Errorf("unsupported schema_version %d", r.SchemaVersion)
	}
	if r.RequestID == "" || r.Command == "" {
		return Request{}, errors.New("missing request_id or command")
	}
	return r, nil
}

func BuildAppInput(r Request) ([]byte, error) {
	if r.AppInput != nil {
		return r.AppInput, nil
	}
	m := map[string]any{
		"schema_version":  uint64(SchemaVersion),
		"command":         r.Command,
		"argv":            stringSliceToAny(r.Argv),
		"inferred_params": typedValuesToAny(r.Inferred),
	}
	if r.Stdin != nil {
		m["stdin"] = r.Stdin
	}
	if len(r.Files) != 0 {
		files := make(map[string]any, len(r.Files))
		for k, v := range r.Files {
			files[k] = v
		}
		m["files"] = files
	}
	if len(r.Metadata) != 0 {
		m["metadata"] = r.Metadata
	}
	return encodeValue(m)
}

func DecodeAppOutput(b []byte) (AppOutput, error) {
	v, err := decodeValue(b)
	if err != nil {
		return AppOutput{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return AppOutput{}, errors.New("app output is not map")
	}
	out := AppOutput{
		SchemaVersion: int(asUint(m["schema_version"])),
		Status:        asString(m["status"]),
	}
	out.Stdout, _ = m["stdout"].([]byte)
	out.Stderr, _ = m["stderr"].([]byte)
	out.Files = asByteMap(m["files"])
	if metadata, ok := m["metadata"].(map[string]any); ok {
		out.Metadata = metadata
	}
	out.Result = m["result"]
	if em, ok := m["error"].(map[string]any); ok {
		out.Error = &TwepError{Code: asString(em["code"]), Message: asString(em["message"]), Details: em["details"]}
	}
	if out.SchemaVersion != SchemaVersion {
		return AppOutput{}, fmt.Errorf("unsupported schema_version %d", out.SchemaVersion)
	}
	if out.Status == "" {
		return AppOutput{}, errors.New("missing status")
	}
	return out, nil
}

func EncodeResponse(r Response) ([]byte, error) {
	if r.SchemaVersion == 0 {
		r.SchemaVersion = SchemaVersion
	}
	m := map[string]any{
		"schema_version": uint64(r.SchemaVersion),
		"request_id":     r.RequestID,
		"status":         r.Status,
		"exit_code":      int64(r.ExitCode),
	}
	if r.Stdout != nil {
		m["stdout"] = r.Stdout
	}
	if r.Stderr != nil {
		m["stderr"] = r.Stderr
	}
	if r.AppOutput != nil {
		m["app_output"] = r.AppOutput
	}
	if r.Result != nil {
		m["result"] = r.Result
	}
	if r.Error != nil {
		em := map[string]any{"code": r.Error.Code, "message": r.Error.Message}
		if r.Error.Details != nil {
			em["details"] = r.Error.Details
		}
		m["error"] = em
	}
	return encodeValue(m)
}

func DecodeResponse(b []byte) (Response, error) {
	v, err := decodeValue(b)
	if err != nil {
		return Response{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Response{}, errors.New("response is not map")
	}
	r := Response{
		SchemaVersion: int(asUint(m["schema_version"])),
		RequestID:     asString(m["request_id"]),
		Status:        asString(m["status"]),
		ExitCode:      int(asInt(m["exit_code"])),
	}
	r.Stdout, _ = m["stdout"].([]byte)
	r.Stderr, _ = m["stderr"].([]byte)
	r.AppOutput, _ = m["app_output"].([]byte)
	r.Result = m["result"]
	if em, ok := m["error"].(map[string]any); ok {
		r.Error = &TwepError{Code: asString(em["code"]), Message: asString(em["message"]), Details: em["details"]}
	}
	if r.SchemaVersion != SchemaVersion {
		return Response{}, fmt.Errorf("unsupported schema_version %d", r.SchemaVersion)
	}
	if r.Status == "" {
		return Response{}, errors.New("missing status")
	}
	return r, nil
}

func stringSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func typedValuesToAny(in []TypedValue) []any {
	out := make([]any, len(in))
	for i, tv := range in {
		out[i] = map[string]any{"type": tv.Type, "value": tv.Value}
	}
	return out
}

func InferArgv(argv []string) []TypedValue {
	out := make([]TypedValue, 0, len(argv))
	for _, arg := range argv {
		if i, err := strconv.ParseInt(arg, 10, 64); err == nil {
			out = append(out, TypedValue{Type: "int", Value: i})
			continue
		}
		if u, err := strconv.ParseUint(arg, 10, 64); err == nil {
			out = append(out, TypedValue{Type: "uint", Value: u})
			continue
		}
		out = append(out, TypedValue{Type: "text", Value: arg})
	}
	return out
}

func encodeValue(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteByte(0xf6)
	case bool:
		if x {
			buf.WriteByte(0xf5)
		} else {
			buf.WriteByte(0xf4)
		}
	case int:
		writeInt(buf, int64(x))
	case int64:
		writeInt(buf, x)
	case uint64:
		writeTypeLen(buf, 0, x)
	case string:
		writeTypeLen(buf, 3, uint64(len(x)))
		buf.WriteString(x)
	case []byte:
		writeTypeLen(buf, 2, uint64(len(x)))
		buf.Write(x)
	case []any:
		writeTypeLen(buf, 4, uint64(len(x)))
		for _, e := range x {
			if err := writeValue(buf, e); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) != len(keys[j]) {
				return len(keys[i]) < len(keys[j])
			}
			return keys[i] < keys[j]
		})
		writeTypeLen(buf, 5, uint64(len(keys)))
		for _, k := range keys {
			if err := writeValue(buf, k); err != nil {
				return err
			}
			if err := writeValue(buf, x[k]); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported CBOR type %T", v)
	}
	return nil
}

func writeInt(buf *bytes.Buffer, v int64) {
	if v >= 0 {
		writeTypeLen(buf, 0, uint64(v))
		return
	}
	writeTypeLen(buf, 1, uint64(-1-v))
}

func writeTypeLen(buf *bytes.Buffer, major byte, n uint64) {
	head := major << 5
	switch {
	case n < 24:
		buf.WriteByte(head | byte(n))
	case n <= 0xff:
		buf.WriteByte(head | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(head | 25)
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(n))
		buf.Write(b[:])
	case n <= 0xffffffff:
		buf.WriteByte(head | 26)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		buf.Write(b[:])
	default:
		buf.WriteByte(head | 27)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		buf.Write(b[:])
	}
}

func decodeValue(b []byte) (any, error) {
	d := decoder{b: b}
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	if d.off != len(b) {
		return nil, errors.New("trailing CBOR data")
	}
	return v, nil
}

type decoder struct {
	b   []byte
	off int
}

func (d *decoder) value() (any, error) {
	if d.off >= len(d.b) {
		return nil, io.ErrUnexpectedEOF
	}
	head := d.b[d.off]
	d.off++
	major := head >> 5
	add := head & 0x1f
	n, err := d.readLen(add)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return n, nil
	case 1:
		return int64(-1 - int64(n)), nil
	case 2:
		return d.readBytes(n)
	case 3:
		b, err := d.readBytes(n)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case 4:
		out := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		out := make(map[string]any, n)
		for i := uint64(0); i < n; i++ {
			k, err := d.value()
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errors.New("non-string map key")
			}
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			out[ks] = v
		}
		return out, nil
	case 7:
		switch add {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		default:
			return nil, fmt.Errorf("unsupported simple value %d", add)
		}
	default:
		return nil, fmt.Errorf("unsupported major type %d", major)
	}
}

func (d *decoder) readLen(add byte) (uint64, error) {
	switch {
	case add < 24:
		return uint64(add), nil
	case add == 24:
		if d.off+1 > len(d.b) {
			return 0, io.ErrUnexpectedEOF
		}
		n := d.b[d.off]
		d.off++
		return uint64(n), nil
	case add == 25:
		if d.off+2 > len(d.b) {
			return 0, io.ErrUnexpectedEOF
		}
		n := binary.BigEndian.Uint16(d.b[d.off:])
		d.off += 2
		return uint64(n), nil
	case add == 26:
		if d.off+4 > len(d.b) {
			return 0, io.ErrUnexpectedEOF
		}
		n := binary.BigEndian.Uint32(d.b[d.off:])
		d.off += 4
		return uint64(n), nil
	case add == 27:
		if d.off+8 > len(d.b) {
			return 0, io.ErrUnexpectedEOF
		}
		n := binary.BigEndian.Uint64(d.b[d.off:])
		d.off += 8
		return n, nil
	default:
		return 0, fmt.Errorf("unsupported additional info %d", add)
	}
}

func (d *decoder) readBytes(n uint64) ([]byte, error) {
	if n > uint64(len(d.b)-d.off) {
		return nil, io.ErrUnexpectedEOF
	}
	out := d.b[d.off : d.off+int(n)]
	d.off += int(n)
	return out, nil
}

func asUint(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case int64:
		return uint64(x)
	default:
		return 0
	}
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case uint64:
		return int64(x)
	case int64:
		return x
	default:
		return 0
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asStringSlice(v any) []string {
	in, _ := v.([]any)
	out := make([]string, 0, len(in))
	for _, e := range in {
		out = append(out, asString(e))
	}
	return out
}

func asTypedValues(v any) []TypedValue {
	in, _ := v.([]any)
	out := make([]TypedValue, 0, len(in))
	for _, e := range in {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, TypedValue{Type: asString(m["type"]), Value: m["value"]})
	}
	return out
}

func asByteMap(v any) map[string][]byte {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		b, ok := v.([]byte)
		if !ok {
			continue
		}
		out[k] = b
	}
	return out
}
