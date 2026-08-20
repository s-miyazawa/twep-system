/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TWEP_WR_TA_RUNTIME_INTERNAL_H
#define TWEP_WR_TA_RUNTIME_INTERNAL_H

#include "acceptance_state.h"
#include "protected_app.h"
#include "ta_internal.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <twep_wr_ta.h>
#ifdef TWEP_TA_WAMR_LINK
#include <wasm_export.h>
#endif

#define PRODUCTION_STACK_SIZE (64 * 1024)
/* Bounded for a 128 KiB D047 response plus verified Catalog/COSE worksets. */
#define PRODUCTION_HEAP_SIZE (512 * 1024)
#define PRODUCTION_MAX_OUTPUT_SIZE (16 * 1024)
#define TEEP_AGENT_TRANSIENT_OBJECTS_MAX 64
#define TEEP_AGENT_TRANSIENT_OBJECT_NAME_MAX 96
#define TEEP_AGENT_TRANSIENT_OBJECT_SIZE_MAX (16 * 1024)
#define TEEP_AGENT_HOST_IO_HISTORY_MAX 8
#define TEEP_AGENT_TRANSCRIPT_SIZE_MAX (32 * 1024)
#define TEEP_AGENT_TRANSCRIPT_COUNT_MAX 2
#define TEEP_AGENT_TRANSCRIPT_AGGREGATE_SIZE_MAX (64 * 1024)
#define TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX                                   \
	(TEEP_AGENT_TRANSCRIPT_SIZE_MAX + 1024)

struct cbor_cursor {
	const uint8_t *buf;
	size_t len;
	size_t off;
};

struct bytes_view {
	const uint8_t *ptr;
	size_t len;
};

struct production_resource_limits {
	uint32_t stack_bytes;
	uint32_t heap_bytes;
	uint32_t max_output_bytes;
};

enum teep_agent_pending_hostcall {
	TEEP_AGENT_PENDING_NONE = 0,
	TEEP_AGENT_PENDING_HTTP_POST,
	TEEP_AGENT_PENDING_CREATE_EVIDENCE,
};

struct production_envelope_seen {
	bool resolver_mode;
	bool attestam_url;
	bool insecure;
	bool default_timeout_ms;
	bool max_request_size;
	bool max_response_size;
	bool request_id;
	bool command;
	bool app_input_cbor;
	bool request_timeout_ms;
	bool host_io_result_cbor;
	struct bytes_view request_id_view;
	struct bytes_view command_view;
	struct bytes_view resolver_mode_view;
	struct bytes_view attestam_url_view;
	struct bytes_view app_input_view;
	struct bytes_view host_io_result_view;
	struct bytes_view wasm_view;
	struct bytes_view catalog_view;
	struct bytes_view app_wasm_view;
	struct bytes_view dev_agent_public_key_view;
};

struct pending_host_io_state {
	bool active;
	bool http_transcript;
	uint64_t sequence;
	struct bytes_view request_id;
	struct bytes_view io_id;
	struct bytes_view kind;
	uint8_t normalized_input_sha256[32];
	uint8_t request_body_sha256[32];
	uint8_t *request_body;
	size_t request_body_len;
	char request_id_storage[64];
	char command_storage[64];
	char io_id_storage[64];
	char kind_storage[32];
};

#ifdef TWEP_TA_WAMR_LINK
struct pending_teep_live_state {
	bool active;
	bool component_commit_recorded;
	uint8_t component_commit_kind;
	uint8_t component_commit_query_digest[32];
	uint8_t component_commit_payload_digest[32];
	uint64_t component_commit_sequence;
	uint64_t component_commit_expected_generation;
	uint64_t component_commit_new_generation;
	uint32_t component_commit_payload_len;
	uint8_t *wasm;
	size_t wasm_len;
	uint8_t *input;
	size_t input_len;
	uint8_t *app_input;
	size_t app_input_len;
	uint8_t *catalog;
	size_t catalog_len;
	uint8_t *app_wasm;
	size_t app_wasm_len;
	uint8_t *dev_agent_public_key;
	size_t dev_agent_public_key_len;
	char request_id_storage[64];
	size_t request_id_len;
	char command_storage[64];
	size_t command_len;
	struct {
		enum teep_agent_pending_hostcall kind;
		uint8_t *payload;
		size_t payload_len;
	} history[TEEP_AGENT_HOST_IO_HISTORY_MAX];
	size_t history_count;
};

struct teep_agent_live_session {
	bool active;
	wasm_module_t module;
	uint8_t *module_wasm;
	size_t module_wasm_len;
};
#endif

struct twep_wr_session {
	struct pending_host_io_state pending_host_io;
#ifdef TWEP_TA_WAMR_LINK
	struct pending_teep_live_state pending_teep_live;
	struct teep_agent_live_session teep_agent_live_session;
#endif
};

struct teep_resolve_input {
	struct bytes_view command;
	struct bytes_view target_command;
	struct bytes_view resolver_mode;
};
struct teep_agent_hostcall_context {
	struct bytes_view teep_agent_wasm;
	struct bytes_view catalog;
	struct bytes_view app_wasm;
	struct bytes_view resolver_mode;
	const struct bytes_view *request_id;
	struct bytes_view command;
	struct bytes_view input;
	enum teep_agent_pending_hostcall pending;
	enum teep_agent_pending_hostcall replay;
	const uint8_t *replay_payload;
	size_t replay_payload_len;
	bool replay_used;
	size_t replay_history_index;
	char url[128];
	size_t url_len;
	uint8_t body[TEEP_AGENT_TRANSCRIPT_SIZE_MAX];
	size_t body_len;
	uint8_t challenge[64];
	size_t challenge_len;
	uint8_t agent_public_key_cose[128];
	size_t agent_public_key_cose_len;
	struct {
		bool used;
		char name[TEEP_AGENT_TRANSIENT_OBJECT_NAME_MAX];
		size_t name_len;
		uint8_t *data;
		size_t data_len;
	} objects[TEEP_AGENT_TRANSIENT_OBJECTS_MAX];
};

TWEP_TA_HIDDEN extern struct twep_wr_session *g_session;
TWEP_TA_HIDDEN extern size_t g_pending_http_transcript_count;
TWEP_TA_HIDDEN extern size_t g_pending_http_transcript_bytes;
#define g_pending_host_io (g_session->pending_host_io)
#ifdef TWEP_TA_WAMR_LINK
#define g_pending_teep_live (g_session->pending_teep_live)
#define g_teep_agent_live_session (g_session->teep_agent_live_session)
TWEP_TA_HIDDEN extern bool g_wamr_runtime_initialized;
TWEP_TA_HIDDEN extern bool g_teep_agent_natives_registered;
TWEP_TA_HIDDEN extern size_t g_teep_agent_live_session_count;
TWEP_TA_HIDDEN extern NativeSymbol teep_agent_native_symbols[14];
#endif

TWEP_TA_HIDDEN TEE_Result build_app_runtime_error_execute_response(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const char *code, const char *message, const char *reason, uint8_t *out,
	size_t out_size, size_t *out_len);
TWEP_TA_HIDDEN TEE_Result
build_execute_response(const struct bytes_view *request_id,
		       const struct bytes_view *stdout_view,
		       const struct bytes_view *app_output, uint8_t *out,
		       size_t out_size, size_t *out_len);
TWEP_TA_HIDDEN TEE_Result
build_final_response_wrapper(const struct bytes_view *request_id,
			     const struct bytes_view *final_response,
			     uint8_t *out, size_t out_size, size_t *out_len);
TWEP_TA_HIDDEN TEE_Result build_need_evidence_response(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const struct bytes_view *input, uint8_t *out, size_t out_size,
	size_t *out_len);
TWEP_TA_HIDDEN TEE_Result build_need_evidence_response_with_payload(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const struct bytes_view *input, const uint8_t *challenge,
	size_t challenge_len, const uint8_t *agent_public_key_cose,
	size_t agent_public_key_cose_len, uint8_t *out, size_t out_size,
	size_t *out_len);
TWEP_TA_HIDDEN TEE_Result build_need_host_io_response(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const struct bytes_view *input, const char *io_id, const char *url,
	const uint8_t *body, size_t body_len, uint8_t *out, size_t out_size,
	size_t *out_len);
TWEP_TA_HIDDEN TEE_Result build_resume_final_response(
	const struct bytes_view *request_id, const struct bytes_view *result,
	uint8_t *out, size_t out_size, size_t *out_len);
TWEP_TA_HIDDEN TEE_Result build_teep_error_execute_response(
	const struct bytes_view *request_id, const struct bytes_view *teep_code,
	const struct bytes_view *teep_message, const struct bytes_view *command,
	uint8_t *out, size_t out_size, size_t *out_len);
TWEP_TA_HIDDEN TEE_Result build_teep_resolve_input_for_command(
	const struct bytes_view *target_command,
	const struct bytes_view *resolver_mode,
	const struct bytes_view *attestam_url, uint8_t *out, size_t out_size,
	struct bytes_view *out_view);
TWEP_TA_HIDDEN bool bytes_view_eq(const struct bytes_view *view,
				  const char *want);
TWEP_TA_HIDDEN bool bytes_view_is_safe_command(const struct bytes_view *view);
TWEP_TA_HIDDEN bool cbor_read_len(struct cbor_cursor *cur, uint8_t want_major,
				  uint64_t *value);
TWEP_TA_HIDDEN bool cbor_read_text_key(struct cbor_cursor *cur,
				       const uint8_t **key, size_t *key_len);
TWEP_TA_HIDDEN bool cbor_skip_item(struct cbor_cursor *cur, unsigned depth);
TWEP_TA_HIDDEN size_t cbor_type_len_size(uint64_t n);
TWEP_TA_HIDDEN void cbor_write_bstr(uint8_t **p, const uint8_t *bytes,
				    size_t len);
TWEP_TA_HIDDEN void cbor_write_text(uint8_t **p, const char *text);
TWEP_TA_HIDDEN void cbor_write_type_len(uint8_t **p, uint8_t major, uint64_t n);
TWEP_TA_HIDDEN void cbor_write_uint64(uint8_t **p, uint64_t n);
TWEP_TA_HIDDEN void cbor_write_view_text(uint8_t **p,
					 const struct bytes_view *view);
TWEP_TA_HIDDEN TEE_Result execute_production_app_wasm(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const struct bytes_view *app_input, const struct bytes_view *app_wasm,
	const struct production_resource_limits *limits, uint8_t *out,
	size_t out_size, size_t *out_len);
TWEP_TA_HIDDEN TEE_Result execute_teep_agent_resolve(
	const struct bytes_view *request_id, const struct bytes_view *wasm,
	const struct bytes_view *input, const struct bytes_view *catalog,
	const struct bytes_view *app_wasm,
	const struct bytes_view *dev_agent_public_key,
	enum teep_agent_pending_hostcall replay, const uint8_t *replay_payload,
	size_t replay_payload_len, uint8_t *out, size_t out_size,
	size_t *out_len);
TWEP_TA_HIDDEN TEE_Result twep_ta_verify_teep_agent_wasm_signature(
	const struct bytes_view *wasm);
TWEP_TA_HIDDEN TEE_Result twep_load_protected_app(struct bytes_view *app,
						  uint8_t **owned,
						  uint8_t digest[32]);
TWEP_TA_HIDDEN TEE_Result extract_stdout_view(const uint8_t *app_output,
					      size_t app_output_len,
					      struct bytes_view *stdout_view);
TWEP_TA_HIDDEN bool host_io_result_ok(const struct bytes_view *result);
TWEP_TA_HIDDEN bool key_eq(const uint8_t *key, size_t key_len,
			   const char *want);
TWEP_TA_HIDDEN bool object_name_eq(const char *ptr, uint32_t len,
				   const char *want);
TWEP_TA_HIDDEN TEE_Result parse_bstr_value_view(struct cbor_cursor *cur,
						struct bytes_view *view);
TWEP_TA_HIDDEN TEE_Result
parse_host_io_result_payload(const struct bytes_view *result,
			     enum teep_agent_pending_hostcall *out_kind,
			     struct bytes_view *out_payload);
TWEP_TA_HIDDEN TEE_Result parse_production_envelope(
	const void *buf, size_t len, enum twep_ta_production_envelope_kind kind,
	struct production_envelope_seen *out_seen);
TWEP_TA_HIDDEN TEE_Result
parse_teep_error_output(const struct bytes_view *output,
			struct bytes_view *code, struct bytes_view *message);
TWEP_TA_HIDDEN TEE_Result parse_teep_resolve_input(
	const struct bytes_view *input, struct teep_resolve_input *out);
TWEP_TA_HIDDEN TEE_Result
parse_teep_resource_limits_output(const struct bytes_view *output,
				  struct production_resource_limits *limits,
				  uint8_t app_digest[32]);
TWEP_TA_HIDDEN TEE_Result parse_text_value_view(struct cbor_cursor *cur,
						struct bytes_view *view);
TWEP_TA_HIDDEN TEE_Result parse_uint32_value(struct cbor_cursor *cur,
					     uint32_t *out);
TWEP_TA_HIDDEN void
pending_host_io_clear(struct pending_host_io_state *pending);
TWEP_TA_HIDDEN bool
pending_request_matches(const struct bytes_view *request_id);
TWEP_TA_HIDDEN TEE_Result
pending_teep_live_append_history(enum teep_agent_pending_hostcall kind,
				 const struct bytes_view *payload);
TWEP_TA_HIDDEN void pending_teep_live_clear(void);
TWEP_TA_HIDDEN TEE_Result pending_teep_live_save(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const struct bytes_view *wasm, const struct bytes_view *input,
	const struct bytes_view *app_input, const struct bytes_view *catalog,
	const struct bytes_view *app_wasm,
	const struct bytes_view *dev_agent_public_key);
TWEP_TA_HIDDEN void
production_resource_limits_default(struct production_resource_limits *limits);
TWEP_TA_HIDDEN TEE_Result
resume_pending_teep_live(const struct bytes_view *request_id,
			 const struct bytes_view *host_io_result, uint8_t *out,
			 size_t out_size, size_t *out_len);
TWEP_TA_HIDDEN void teep_agent_live_abort(void);
TWEP_TA_HIDDEN void teep_agent_live_session_release(void);
TWEP_TA_HIDDEN TEE_Result teep_agent_pending_to_need_host_io(
	const struct teep_agent_hostcall_context *ctx, uint8_t *out,
	size_t out_size, size_t *out_len);
TWEP_TA_HIDDEN void
teep_hostcall_context_free(struct teep_agent_hostcall_context *ctx);
TWEP_TA_HIDDEN bool
teep_output_is_need_host_io(const struct bytes_view *output);
TWEP_TA_HIDDEN int32_t teep_transient_object_write(
	struct teep_agent_hostcall_context *ctx, const char *path,
	uint32_t path_len, const uint8_t *data, uint32_t data_len);
TWEP_TA_HIDDEN bool wasm_magic_valid(const struct bytes_view *wasm);

#endif /* TWEP_WR_TA_RUNTIME_INTERNAL_H */
