/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "ta_runtime_internal.h"

#ifdef TWEP_TA_WAMR_LINK
static TEE_Result teep_encode_attestam_acceptance_result(uint64_t generation,
							 uint8_t *buf,
							 uint32_t buf_cap,
							 uint32_t *out_len);

static struct teep_agent_hostcall_context *
teep_hostcall_context(wasm_exec_env_t exec_env)
{
	return (struct teep_agent_hostcall_context *)wasm_runtime_get_user_data(
		exec_env);
}

void teep_hostcall_context_free(struct teep_agent_hostcall_context *ctx)
{
	size_t i = 0;

	if (!ctx)
		return;
	for (i = 0; i < TEEP_AGENT_TRANSIENT_OBJECTS_MAX; i++) {
		if (ctx->objects[i].data) {
			TEE_Free(ctx->objects[i].data);
			ctx->objects[i].data = NULL;
		}
		ctx->objects[i].used = false;
		ctx->objects[i].data_len = 0;
		ctx->objects[i].name_len = 0;
	}
}

void teep_agent_live_session_release(void)
{
	struct teep_agent_live_session *session = &g_teep_agent_live_session;

	if (session->active && g_teep_agent_live_session_count)
		g_teep_agent_live_session_count--;
	if (session->module)
		wasm_runtime_unload(session->module);
	if (session->module_wasm)
		TEE_Free(session->module_wasm);
	TEE_MemFill(session, 0, sizeof(*session));
}

void teep_agent_live_abort(void)
{
	pending_host_io_clear(&g_pending_host_io);
	teep_agent_live_session_release();
	pending_teep_live_clear();
}

static struct bytes_view *
teep_transient_object_view(struct teep_agent_hostcall_context *ctx,
			   const char *path, uint32_t path_len,
			   struct bytes_view *out)
{
	size_t i = 0;

	if (!ctx || !path || !out)
		return NULL;
	for (i = 0; i < TEEP_AGENT_TRANSIENT_OBJECTS_MAX; i++) {
		if (!ctx->objects[i].used ||
		    ctx->objects[i].name_len != path_len)
			continue;
		if (TEE_MemCompare(ctx->objects[i].name, path, path_len) == 0) {
			out->ptr = ctx->objects[i].data;
			out->len = ctx->objects[i].data_len;
			return out;
		}
	}
	return NULL;
}

int32_t teep_transient_object_write(struct teep_agent_hostcall_context *ctx,
				    const char *path, uint32_t path_len,
				    const uint8_t *data, uint32_t data_len)
{
	size_t slot = TEEP_AGENT_TRANSIENT_OBJECTS_MAX;
	size_t i = 0;
	uint8_t *copy = NULL;

	if (!ctx || !path || (!data && data_len))
		return 1;
	if (path_len >= TEEP_AGENT_TRANSIENT_OBJECT_NAME_MAX ||
	    data_len > TEEP_AGENT_TRANSIENT_OBJECT_SIZE_MAX)
		return 2;
	for (i = 0; i < TEEP_AGENT_TRANSIENT_OBJECTS_MAX; i++) {
		if (ctx->objects[i].used &&
		    ctx->objects[i].name_len == path_len &&
		    TEE_MemCompare(ctx->objects[i].name, path, path_len) == 0) {
			slot = i;
			break;
		}
		if (!ctx->objects[i].used &&
		    slot == TEEP_AGENT_TRANSIENT_OBJECTS_MAX)
			slot = i;
	}
	if (slot == TEEP_AGENT_TRANSIENT_OBJECTS_MAX)
		return 2;
	copy = TEE_Malloc(data_len ? data_len : 1, 0);
	if (!copy)
		return 1;
	if (data_len)
		TEE_MemMove(copy, data, data_len);
	if (ctx->objects[slot].data)
		TEE_Free(ctx->objects[slot].data);
	ctx->objects[slot].data = copy;
	ctx->objects[slot].data_len = data_len;
	ctx->objects[slot].name_len = path_len;
	TEE_MemMove(ctx->objects[slot].name, path, path_len);
	ctx->objects[slot].used = true;
	return 0;
}

static void teep_host_log(wasm_exec_env_t exec_env, uint32_t level,
			  const char *msg, uint32_t msg_len)
{
	(void)exec_env;
	(void)level;
	(void)msg;
	(void)msg_len;
}

static int32_t teep_host_read_file(wasm_exec_env_t exec_env, const char *path,
				   uint32_t path_len, uint8_t *buf,
				   uint32_t buf_cap, uint32_t *out_len)
{
	struct teep_agent_hostcall_context *ctx =
		teep_hostcall_context(exec_env);
	const struct bytes_view *source = NULL;
	struct bytes_view transient = {};
	size_t protected_len = 0;
	TEE_Result res;

	if (!ctx || !path || !out_len)
		return 1;
	if (object_name_eq(path, path_len, "catalog/catalog.cbor") &&
	    bytes_view_eq(&ctx->resolver_mode, "attestam-verified")) {
#ifdef TWEP_TA_WAMR_LINK
		/*
		 * A host-I/O resume replays the Agent from its entry point.  Keep
		 * the protected-state view from the start of this request stable:
		 * the Catalog committed by this request becomes visible to the next
		 * top-level request, not to its own deterministic replay.
		 */
		if (g_pending_teep_live.active &&
		    g_pending_teep_live.component_commit_recorded &&
		    g_pending_teep_live.component_commit_kind == 1) {
			*out_len = 0;
			return 3;
		}
#endif
		res = twep_catalog_read_active(buf, buf_cap, &protected_len);
		*out_len = protected_len > UINT32_MAX ? UINT32_MAX
						      : (uint32_t)protected_len;
		if (res == TEE_SUCCESS)
			return 0;
		if (res == TEE_ERROR_SHORT_BUFFER)
			return 2;
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return 3;
		if (res == TEE_ERROR_BAD_PARAMETERS)
			return 1;
		if (res == TEE_ERROR_CORRUPT_OBJECT ||
		    res == TEE_ERROR_BAD_FORMAT ||
		    res == TEE_ERROR_NOT_SUPPORTED || res == TEE_ERROR_SECURITY)
			return 4;
		return 7;
	}
	if (path_len > sizeof("apps/") - 1 &&
	    TEE_MemCompare(path, "apps/", sizeof("apps/") - 1) == 0 &&
	    bytes_view_eq(&ctx->resolver_mode, "attestam-verified")) {
#ifdef TWEP_TA_WAMR_LINK
		/* Apply the same start-of-request snapshot rule to an app commit. */
		if (g_pending_teep_live.active &&
		    g_pending_teep_live.component_commit_recorded &&
		    g_pending_teep_live.component_commit_kind == 2) {
			*out_len = 0;
			return 3;
		}
#endif
		res = twep_app_read_active(buf, buf_cap, &protected_len, NULL);
		*out_len = protected_len > UINT32_MAX ? UINT32_MAX
						      : (uint32_t)protected_len;
		if (res == TEE_SUCCESS)
			return 0;
		if (res == TEE_ERROR_SHORT_BUFFER)
			return 2;
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return 3;
		if (res == TEE_ERROR_BAD_PARAMETERS)
			return 1;
		if (res == TEE_ERROR_CORRUPT_OBJECT ||
		    res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_SECURITY)
			return 4;
		return 7;
	}
	if (teep_transient_object_view(ctx, path, path_len, &transient))
		source = &transient;
	else if (object_name_eq(path, path_len, "catalog/catalog.cbor"))
		source = &ctx->catalog;
	else if (object_name_eq(path, path_len, "apps/helloworld.wasm"))
		source = &ctx->app_wasm;
	else {
		return 3;
	}
	*out_len =
		source->len > UINT32_MAX ? UINT32_MAX : (uint32_t)source->len;
	if (source->len > buf_cap)
		return 2;
	if (source->len && buf)
		TEE_MemMove(buf, source->ptr, source->len);
	return 0;
}

static bool teep_agent_state_object_allowed(const char *path, uint32_t path_len)
{
	static const char teep_agent_prefix[] = "teep-agent/";
	static const char tmp_prefix[] = "tmp/";
	static const char components_prefix[] = "components/";
	static const char apps_prefix[] = "apps/";

	if (!path || path_len == 0)
		return false;
	for (uint32_t i = 0; i < path_len; i++) {
		if (path[i] == '\0')
			return false;
		if (path[i] == '.' && i + 1 < path_len && path[i + 1] == '.')
			return false;
	}
	if (object_name_eq(path, path_len, "catalog/catalog.cbor"))
		return true;
	if (path_len >= sizeof(teep_agent_prefix) - 1 &&
	    TEE_MemCompare(path, teep_agent_prefix,
			   sizeof(teep_agent_prefix) - 1) == 0)
		return true;
	if (path_len >= sizeof(tmp_prefix) - 1 &&
	    TEE_MemCompare(path, tmp_prefix, sizeof(tmp_prefix) - 1) == 0)
		return true;
	if (path_len >= sizeof(components_prefix) - 1 &&
	    TEE_MemCompare(path, components_prefix,
			   sizeof(components_prefix) - 1) == 0)
		return true;
	if (path_len >= sizeof(apps_prefix) - 1 &&
	    TEE_MemCompare(path, apps_prefix, sizeof(apps_prefix) - 1) == 0)
		return object_name_eq(path, path_len, "apps/helloworld.wasm");
	return false;
}

static bool teep_agent_protected_object_allowed(const char *object_name,
						uint32_t object_name_len)
{
	return object_name_eq(object_name, object_name_len,
			      "protected-credential-store.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-issuer-allowlist.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-sequence-freshness.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-store-freshness.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-revocation-state.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-agent-identity.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "verified-evidence-result.cbor");
}

TEE_Result twep_ta_write_persistent_object(const char *object_name,
					   uint32_t object_name_len,
					   const uint8_t *data,
					   uint32_t data_len)
{
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint32_t flags =
		TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
		TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res;

	if (!object_name || object_name_len == 0 || (!data && data_len != 0))
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, object_name,
					 object_name_len, flags,
					 TEE_HANDLE_NULL, NULL, 0, &object);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_WriteObjectData(object, data, data_len);
	if (res != TEE_SUCCESS) {
		TEE_CloseAndDeletePersistentObject1(object);
		return res;
	}
	TEE_CloseObject(object);
	return TEE_SUCCESS;
}

static TEE_Result teep_encode_attestam_acceptance_result(uint64_t generation,
							 uint8_t *buf,
							 uint32_t buf_cap,
							 uint32_t *out_len)
{
	uint8_t *p = buf;
	uint32_t need = 1 + 1 + sizeof("schema_version") - 1 + 1 + 1 +
			sizeof("decision_source") - 1 + 1 +
			sizeof("attestam-signed-update") - 1 + 1 +
			sizeof("tam_response_verified") - 1 + 1 + 2 +
			sizeof("challenge_response_bound") - 1 + 1 + 1 +
			sizeof("acceptance_generation") - 1 +
			(uint32_t)cbor_type_len_size(generation);

	if (!buf || !out_len)
		return TEE_ERROR_BAD_PARAMETERS;
	if (buf_cap < need)
		return TEE_ERROR_SHORT_BUFFER;

	*p++ = 0xa5;
	cbor_write_text(&p, "schema_version");
	cbor_write_uint64(&p, 2);
	cbor_write_text(&p, "decision_source");
	cbor_write_text(&p, "attestam-signed-update");
	cbor_write_text(&p, "tam_response_verified");
	*p++ = 0xf5;
	cbor_write_text(&p, "challenge_response_bound");
	*p++ = 0xf5;
	cbor_write_text(&p, "acceptance_generation");
	cbor_write_uint64(&p, generation);
	*out_len = (uint32_t)(p - buf);
	return TEE_SUCCESS;
}

static TEE_Result teep_read_persistent_object(const char *object_name,
					      uint32_t object_name_len,
					      uint8_t *buf, uint32_t buf_cap,
					      uint32_t *out_len)
{
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_ObjectInfo object_info = {};
	uint32_t read_bytes = 0;
	TEE_Result res;

	if (!object_name || object_name_len == 0 || !out_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_OpenPersistentObject(
		TEE_STORAGE_PRIVATE, object_name, object_name_len,
		TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &object);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS)
		goto out;

	*out_len = object_info.dataSize;
	if (object_info.dataSize > buf_cap) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	if (object_info.dataSize != 0 && !buf) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = TEE_ReadObjectData(object, buf, object_info.dataSize,
				 &read_bytes);
	if (res != TEE_SUCCESS)
		goto out;
	if (read_bytes != object_info.dataSize)
		res = TEE_ERROR_CORRUPT_OBJECT;

out:
	TEE_CloseObject(object);
	return res;
}

static int32_t teep_host_write_file(wasm_exec_env_t exec_env, const char *path,
				    uint32_t path_len, const uint8_t *data,
				    uint32_t data_len)
{
	struct teep_agent_hostcall_context *ctx =
		teep_hostcall_context(exec_env);
	int32_t status;

	if (!ctx || !path)
		return 1;
	if (twep_ta_d047_object_name_reserved(path, path_len)) {
		IMSG("twep-wr-ta teep-agent generic catalog-state write "
		     "rejected");
		return 4;
	}
	if (object_name_eq(path, path_len,
			   "teep-agent/verified-evidence-result.cbor")) {
		IMSG("twep-wr-ta teep-agent generic acceptance-result write "
		     "rejected");
		return 4;
	}
	if (!teep_agent_state_object_allowed(path, path_len)) {
		IMSG("twep-wr-ta teep-agent write rejected object len=%u",
		     path_len);
		return 4;
	}
	status = teep_transient_object_write(ctx, path, path_len, data,
					     data_len);
	return status;
}

static int32_t teep_host_read_protected(wasm_exec_env_t exec_env,
					const char *object_name,
					uint32_t object_name_len, uint8_t *buf,
					uint32_t buf_cap, uint32_t *out_len)
{
	uint8_t snapshot[160] = {};
	uint32_t snapshot_len = 0;
	TEE_Result res;

	if (!teep_hostcall_context(exec_env) || !out_len)
		return 1;
	if (!teep_agent_protected_object_allowed(object_name, object_name_len))
		return 8;
	/*
	 * A commit causes the Agent to replay from its entry point.  Present the
	 * acceptance result from the start of that request, just as
	 * teep_host_acceptance_generation() presents the starting generation.
	 * The replayed commit below still has to match every recorded argument.
	 */
	if (g_pending_teep_live.active &&
	    g_pending_teep_live.component_commit_recorded &&
	    g_pending_teep_live.component_commit_expected_generation &&
	    object_name_eq(object_name, object_name_len,
			   "verified-evidence-result.cbor")) {
		res = teep_encode_attestam_acceptance_result(
			g_pending_teep_live.component_commit_expected_generation,
			snapshot, sizeof(snapshot), &snapshot_len);
		if (res != TEE_SUCCESS)
			return 7;
		*out_len = snapshot_len;
		if (buf_cap < snapshot_len)
			return 2;
		if (!buf)
			return 1;
		TEE_MemMove(buf, snapshot, snapshot_len);
		return 0;
	}

	*out_len = 0;
	res = teep_read_persistent_object(object_name, object_name_len, buf,
					  buf_cap, out_len);
	switch (res) {
	case TEE_SUCCESS:
		return 0;
	case TEE_ERROR_SHORT_BUFFER:
		return 2;
	case TEE_ERROR_ITEM_NOT_FOUND:
		return 3;
	case TEE_ERROR_BAD_PARAMETERS:
		return 1;
	case TEE_ERROR_CORRUPT_OBJECT:
	case TEE_ERROR_BAD_FORMAT:
	case TEE_ERROR_NOT_SUPPORTED:
		return 4;
	default:
		return 7;
	}
}

static int32_t teep_host_http_post(wasm_exec_env_t exec_env, const char *url,
				   uint32_t url_len, const uint8_t *body,
				   uint32_t body_len, uint8_t *buf,
				   uint32_t buf_cap, uint32_t *out_len)
{
	{
		struct teep_agent_hostcall_context *ctx =
			teep_hostcall_context(exec_env);

		if (!ctx || !out_len || !url || (!body && body_len))
			return 1;
		if (ctx->replay_history_index <
			    g_pending_teep_live.history_count &&
		    g_pending_teep_live.history[ctx->replay_history_index]
				    .kind == TEEP_AGENT_PENDING_HTTP_POST) {
			const uint8_t *payload =
				g_pending_teep_live
					.history[ctx->replay_history_index]
					.payload;
			size_t payload_len =
				g_pending_teep_live
					.history[ctx->replay_history_index]
					.payload_len;

			*out_len = payload_len > UINT32_MAX
					   ? UINT32_MAX
					   : (uint32_t)payload_len;
			if (payload_len > buf_cap)
				return 2;
			if (payload_len && buf)
				TEE_MemMove(buf, payload, payload_len);
			ctx->replay_history_index++;
			return 0;
		}
		if (ctx->replay == TEEP_AGENT_PENDING_HTTP_POST &&
		    !ctx->replay_used) {
			*out_len = ctx->replay_payload_len > UINT32_MAX
					   ? UINT32_MAX
					   : (uint32_t)ctx->replay_payload_len;
			if (ctx->replay_payload_len > buf_cap)
				return 2;
			if (ctx->replay_payload_len && buf)
				TEE_MemMove(buf, ctx->replay_payload,
					    ctx->replay_payload_len);
			ctx->replay_used = true;
			return 0;
		}
		if (url_len >= sizeof(ctx->url) ||
		    body_len > sizeof(ctx->body)) {
			return 2;
		}
		TEE_MemMove(ctx->url, url, url_len);
		ctx->url[url_len] = '\0';
		ctx->url_len = url_len;
		if (body_len)
			TEE_MemMove(ctx->body, body, body_len);
		ctx->body_len = body_len;
		ctx->pending = TEEP_AGENT_PENDING_HTTP_POST;
		*out_len = 0;
	}
	return 11;
}

static int32_t teep_host_create_evidence(wasm_exec_env_t exec_env,
					 const uint8_t *challenge,
					 uint32_t challenge_len,
					 const uint8_t *agent_key,
					 uint32_t agent_key_len, uint8_t *buf,
					 uint32_t buf_cap, uint32_t *out_len)
{
	(void)buf;
	(void)buf_cap;
	{
		struct teep_agent_hostcall_context *ctx =
			teep_hostcall_context(exec_env);

		if (!ctx || !out_len || (!challenge && challenge_len) ||
		    (!agent_key && agent_key_len))
			return 1;
		if (ctx->replay_history_index <
			    g_pending_teep_live.history_count &&
		    g_pending_teep_live.history[ctx->replay_history_index]
				    .kind ==
			    TEEP_AGENT_PENDING_CREATE_EVIDENCE) {
			const uint8_t *payload =
				g_pending_teep_live
					.history[ctx->replay_history_index]
					.payload;
			size_t payload_len =
				g_pending_teep_live
					.history[ctx->replay_history_index]
					.payload_len;

			*out_len = payload_len > UINT32_MAX
					   ? UINT32_MAX
					   : (uint32_t)payload_len;
			if (payload_len > buf_cap)
				return 2;
			if (payload_len && buf)
				TEE_MemMove(buf, payload, payload_len);
			ctx->replay_history_index++;
			return 0;
		}
		if (ctx->replay == TEEP_AGENT_PENDING_CREATE_EVIDENCE &&
		    !ctx->replay_used) {
			*out_len = ctx->replay_payload_len > UINT32_MAX
					   ? UINT32_MAX
					   : (uint32_t)ctx->replay_payload_len;
			if (ctx->replay_payload_len > buf_cap)
				return 2;
			if (ctx->replay_payload_len && buf)
				TEE_MemMove(buf, ctx->replay_payload,
					    ctx->replay_payload_len);
			ctx->replay_used = true;
			return 0;
		}
		if (challenge_len > sizeof(ctx->challenge) ||
		    agent_key_len > sizeof(ctx->agent_public_key_cose))
			return 2;
		if (challenge_len)
			TEE_MemMove(ctx->challenge, challenge, challenge_len);
		ctx->challenge_len = challenge_len;
		if (agent_key_len)
			TEE_MemMove(ctx->agent_public_key_cose, agent_key,
				    agent_key_len);
		ctx->agent_public_key_cose_len = agent_key_len;
		ctx->pending = TEEP_AGENT_PENDING_CREATE_EVIDENCE;
		*out_len = 0;
	}
	return 11;
}

TEE_Result teep_agent_pending_to_need_host_io(
	const struct teep_agent_hostcall_context *ctx, uint8_t *out,
	size_t out_size, size_t *out_len)
{
	if (!ctx || !ctx->request_id)
		return TEE_ERROR_BAD_FORMAT;
	if (ctx->pending == TEEP_AGENT_PENDING_HTTP_POST)
		return build_need_host_io_response(
			ctx->request_id, &ctx->command, &ctx->input,
			"teep-http-1", ctx->url, ctx->body, ctx->body_len, out,
			out_size, out_len);
	if (ctx->pending == TEEP_AGENT_PENDING_CREATE_EVIDENCE)
		return build_need_evidence_response_with_payload(
			ctx->request_id, &ctx->command, &ctx->input,
			ctx->challenge, ctx->challenge_len,
			ctx->agent_public_key_cose,
			ctx->agent_public_key_cose_len, out, out_size, out_len);
	return TEE_ERROR_BAD_FORMAT;
}

static int32_t teep_host_platform_status(wasm_exec_env_t exec_env, uint8_t *buf,
					 uint32_t buf_cap, uint32_t *out_len)
{
	static const char status[] =
		"platform-backend=" TWEP_TA_PLATFORM_BACKEND "\n"
		"runtime-location=optee-ta\n"
		"teep-agent-location=optee-ta\n"
		"catalog-resolution-location=optee-ta\n"
		"sealed-storage-security=tee-ree-fs-secure-storage\n"
		"sealed-storage-rollback-protected=false\n";
	size_t len = sizeof(status) - 1;

	if (!teep_hostcall_context(exec_env) || !out_len)
		return 1;
	*out_len = (uint32_t)len;
	if (len > buf_cap)
		return 2;
	if (len && buf)
		TEE_MemMove(buf, status, len);
	return 0;
}

static int32_t teep_host_teep_agent_measurement_sha256(wasm_exec_env_t exec_env,
						       uint8_t *buf,
						       uint32_t buf_cap,
						       uint32_t *out_len)
{
	struct teep_agent_hostcall_context *ctx =
		teep_hostcall_context(exec_env);
	uint8_t digest[32] = {};
	TEE_Result res = TEE_SUCCESS;

	if (!ctx || !out_len)
		return 1;
	if (!ctx->teep_agent_wasm.ptr || !ctx->teep_agent_wasm.len) {
		*out_len = 0;
		return 8;
	}
	*out_len = sizeof(digest);
	if (buf_cap < sizeof(digest))
		return 2;
	if (!buf)
		return 1;
	res = twep_ta_sha256_bytes(ctx->teep_agent_wasm.ptr,
				   ctx->teep_agent_wasm.len, digest);
	if (res != TEE_SUCCESS)
		return 7;
	TEE_MemMove(buf, digest, sizeof(digest));
	return 0;
}

static int32_t acceptance_host_status(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return 0;
	case TEE_ERROR_BAD_PARAMETERS:
		return 1;
	case TEE_ERROR_EXCESS_DATA:
	case TEE_ERROR_OVERFLOW:
		return 2;
	case TEE_ERROR_ITEM_NOT_FOUND:
		return 3;
	case TEE_ERROR_BAD_FORMAT:
	case TEE_ERROR_CORRUPT_OBJECT:
	case TEE_ERROR_NOT_SUPPORTED:
	case TEE_ERROR_SECURITY:
		return 4;
	case TEE_ERROR_ACCESS_CONFLICT:
		return 9;
	default:
		return 7;
	}
}

static int32_t teep_host_acceptance_generation(wasm_exec_env_t exec_env,
					       uint64_t *generation)
{
	if (!teep_hostcall_context(exec_env) || !generation)
		return 1;
#ifdef TWEP_TA_WAMR_LINK
	if (g_pending_teep_live.active &&
	    g_pending_teep_live.component_commit_recorded) {
		*generation =
			g_pending_teep_live.component_commit_expected_generation;
		return 0;
	}
#endif
	return acceptance_host_status(twep_acceptance_generation(generation));
}

static TEE_Result teep_publish_acceptance_result(uint64_t generation)
{
	uint8_t result[160] = {};
	uint8_t stored_result[160] = {};
	uint32_t result_len = 0;
	uint32_t stored_result_len = 0;
	TEE_Result res;

	res = teep_encode_attestam_acceptance_result(
		generation, result, sizeof(result), &result_len);
	if (res != TEE_SUCCESS)
		return res;
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (twep_ta_take_d043_runtime_test_fault(
		    TA_TWEP_WR_D043_FAULT_RESULT_WRITE))
		res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
	else
#endif
		res = twep_ta_write_persistent_object(
			"verified-evidence-result.cbor",
			sizeof("verified-evidence-result.cbor") - 1, result,
			result_len);
	if (res != TEE_SUCCESS)
		return res;
	res = teep_read_persistent_object(
		"verified-evidence-result.cbor",
		sizeof("verified-evidence-result.cbor") - 1, stored_result,
		sizeof(stored_result), &stored_result_len);
	if (res == TEE_SUCCESS &&
	    (stored_result_len != result_len ||
	     TEE_MemCompare(stored_result, result, result_len) != 0))
		return TEE_ERROR_CORRUPT_OBJECT;
	return res;
}

static int32_t
teep_host_commit_acceptance(wasm_exec_env_t exec_env, const uint8_t *digest,
			    uint32_t digest_len, const uint8_t *component_id,
			    uint32_t component_id_len, uint64_t sequence,
			    uint64_t expected_generation,
			    uint64_t *new_generation)
{
	struct teep_agent_hostcall_context *ctx =
		teep_hostcall_context(exec_env);
	TEE_Result res;

	if (!ctx)
		return 1;
	if (!digest || digest_len != 32 || !component_id || !component_id_len ||
	    !new_generation) {
		pending_host_io_clear(&g_pending_host_io);
		return 1;
	}
	if (!g_pending_host_io.active || !g_pending_host_io.http_transcript ||
	    !bytes_view_eq(&g_pending_host_io.kind, "http_post"))
		return 9;
	if (TEE_MemCompare(g_pending_host_io.request_body_sha256, digest, 32) !=
	    0) {
		pending_host_io_clear(&g_pending_host_io);
		return 9;
	}
	res = twep_acceptance_commit(digest, component_id, component_id_len,
				     sequence, expected_generation,
				     new_generation);
	if (res != TEE_SUCCESS) {
		IMSG("twep-wr-ta acceptance commit failed 0x%x", res);
		goto out;
	}
	res = teep_publish_acceptance_result(*new_generation);
	if (res == TEE_SUCCESS)
		IMSG("twep-wr-ta acceptance result generation %llu stored",
		     (unsigned long long)*new_generation);
	else
		IMSG("twep-wr-ta acceptance result store failed 0x%x", res);
out:
	pending_host_io_clear(&g_pending_host_io);
	return acceptance_host_status(res);
}

static int32_t
teep_host_commit_catalog(wasm_exec_env_t exec_env, const uint8_t *digest,
			 uint32_t digest_len, const uint8_t *component_id,
			 uint32_t component_id_len, uint64_t sequence,
			 uint64_t expected_generation, const uint8_t *catalog,
			 uint32_t catalog_len, const uint8_t *catalog_digest,
			 uint32_t catalog_digest_len, uint64_t *new_generation)
{
	struct teep_agent_hostcall_context *ctx =
		teep_hostcall_context(exec_env);
	TEE_Result res;

	if (!ctx)
		return 1;
	if (!digest || digest_len != 32 ||
	    !twep_catalog_component_id_is_default(component_id,
						  component_id_len) ||
	    !catalog || !catalog_len || catalog_len > 65536 ||
	    !catalog_digest || catalog_digest_len != 32 || !new_generation) {
		pending_host_io_clear(&g_pending_host_io);
		return 1;
	}
	if (!bytes_view_eq(&ctx->resolver_mode, "attestam-verified")) {
		pending_host_io_clear(&g_pending_host_io);
		return 8;
	}
#ifdef TWEP_TA_WAMR_LINK
	if (g_pending_teep_live.active &&
	    g_pending_teep_live.component_commit_recorded) {
		uint64_t current_sequence = 0;
		uint64_t current_generation = 0;
		uint8_t replay_catalog_digest[32] = {};

		res = twep_ta_sha256_bytes(catalog, catalog_len,
					   replay_catalog_digest);
		if (res != TEE_SUCCESS ||
		    g_pending_teep_live.component_commit_kind != 1 ||
		    sequence != g_pending_teep_live.component_commit_sequence ||
		    expected_generation !=
			    g_pending_teep_live
				    .component_commit_expected_generation ||
		    catalog_len !=
			    g_pending_teep_live.component_commit_payload_len ||
		    TEE_MemCompare(
			    digest,
			    g_pending_teep_live.component_commit_query_digest,
			    32) != 0 ||
		    TEE_MemCompare(
			    catalog_digest,
			    g_pending_teep_live.component_commit_payload_digest,
			    32) != 0 ||
		    TEE_MemCompare(
			    replay_catalog_digest,
			    g_pending_teep_live.component_commit_payload_digest,
			    32) != 0)
			return 9;
		res = twep_acceptance_component_sequence(
			component_id, component_id_len, &current_generation,
			&current_sequence);
		if (res != TEE_SUCCESS || current_sequence != sequence)
			return 9;
		*new_generation =
			g_pending_teep_live.component_commit_new_generation;
		IMSG("twep-wr-ta replayed committed Catalog generation %llu",
		     (unsigned long long)*new_generation);
		return 0;
	}
#endif
	if (!g_pending_host_io.active || !g_pending_host_io.http_transcript ||
	    !bytes_view_eq(&g_pending_host_io.kind, "http_post"))
		return 9;
	if (TEE_MemCompare(g_pending_host_io.request_body_sha256, digest, 32) !=
	    0) {
		pending_host_io_clear(&g_pending_host_io);
		return 9;
	}
	res = twep_catalog_commit(digest, component_id, component_id_len,
				  sequence, expected_generation, catalog,
				  catalog_len, catalog_digest, new_generation);
	if (res == TEE_SUCCESS)
		res = teep_publish_acceptance_result(*new_generation);
	if (res != TEE_SUCCESS)
		IMSG("twep-wr-ta catalog commit failed 0x%x", res);
	else {
#ifdef TWEP_TA_WAMR_LINK
		if (g_pending_teep_live.active) {
			g_pending_teep_live.component_commit_recorded = true;
			g_pending_teep_live.component_commit_kind = 1;
			TEE_MemMove(
				g_pending_teep_live.component_commit_query_digest,
				digest, 32);
			TEE_MemMove(g_pending_teep_live
					    .component_commit_payload_digest,
				    catalog_digest, 32);
			g_pending_teep_live.component_commit_sequence = sequence;
			g_pending_teep_live.component_commit_expected_generation =
				expected_generation;
			g_pending_teep_live.component_commit_new_generation =
				*new_generation;
			g_pending_teep_live.component_commit_payload_len =
				catalog_len;
		}
#endif
		IMSG("twep-wr-ta catalog generation %llu committed",
		     (unsigned long long)*new_generation);
	}
	pending_host_io_clear(&g_pending_host_io);
	return acceptance_host_status(res);
}

static int32_t
teep_host_commit_app(wasm_exec_env_t exec_env, const uint8_t *digest,
		     uint32_t digest_len, const uint8_t *component_id,
		     uint32_t component_id_len, uint64_t sequence,
		     uint64_t expected_generation, const uint8_t *wasm,
		     uint32_t wasm_len, const uint8_t *wasm_digest,
		     uint32_t wasm_digest_len, uint64_t *new_generation)
{
	struct teep_agent_hostcall_context *ctx = teep_hostcall_context(exec_env);
	TEE_Result res;

	if (!ctx || !digest || digest_len != 32 ||
	    !twep_app_component_id_is_valid(component_id, component_id_len) ||
	    !wasm || !wasm_len || wasm_len > TWEP_PROTECTED_APP_MAX_SIZE ||
	    !wasm_digest || wasm_digest_len != 32 || !new_generation)
		return 1;
	if (!bytes_view_eq(&ctx->resolver_mode, "attestam-verified"))
		return 8;
#ifdef TWEP_TA_WAMR_LINK
	if (g_pending_teep_live.active &&
	    g_pending_teep_live.component_commit_recorded) {
		uint64_t current_generation = 0;
		uint64_t current_sequence = 0;
		uint8_t replay_digest[32] = { };

		res = twep_ta_sha256_bytes(wasm, wasm_len, replay_digest);
		if (res != TEE_SUCCESS ||
		    g_pending_teep_live.component_commit_kind != 2 ||
		    sequence != g_pending_teep_live.component_commit_sequence ||
		    expected_generation !=
			    g_pending_teep_live.component_commit_expected_generation ||
		    wasm_len != g_pending_teep_live.component_commit_payload_len ||
		    TEE_MemCompare(digest,
				   g_pending_teep_live
					   .component_commit_query_digest,
				   32) != 0 ||
		    TEE_MemCompare(wasm_digest,
				   g_pending_teep_live
					   .component_commit_payload_digest,
				   32) != 0 ||
		    TEE_MemCompare(replay_digest,
				   g_pending_teep_live
					   .component_commit_payload_digest,
				   32) != 0)
			return 9;
		res = twep_acceptance_component_sequence(
			component_id, component_id_len, &current_generation,
			&current_sequence);
		if (res != TEE_SUCCESS || current_sequence != sequence)
			return 9;
		*new_generation =
			g_pending_teep_live.component_commit_new_generation;
		IMSG("twep-wr-ta replayed committed app generation %llu",
		     (unsigned long long)*new_generation);
		return 0;
	}
#endif
	if (!g_pending_host_io.active || !g_pending_host_io.http_transcript ||
	    !bytes_view_eq(&g_pending_host_io.kind, "http_post"))
		return 9;
	if (TEE_MemCompare(g_pending_host_io.request_body_sha256, digest, 32) !=
	    0) {
		pending_host_io_clear(&g_pending_host_io);
		return 9;
	}
	res = twep_app_commit(digest, component_id, component_id_len, sequence,
			      expected_generation, wasm, wasm_len, wasm_digest,
			      new_generation);
	if (res == TEE_SUCCESS)
		res = teep_publish_acceptance_result(*new_generation);
	if (res == TEE_SUCCESS) {
#ifdef TWEP_TA_WAMR_LINK
		if (g_pending_teep_live.active) {
			g_pending_teep_live.component_commit_recorded = true;
			g_pending_teep_live.component_commit_kind = 2;
			TEE_MemMove(
				g_pending_teep_live.component_commit_query_digest,
				digest, 32);
			TEE_MemMove(
				g_pending_teep_live.component_commit_payload_digest,
				wasm_digest, 32);
			g_pending_teep_live.component_commit_sequence = sequence;
			g_pending_teep_live.component_commit_expected_generation =
				expected_generation;
			g_pending_teep_live.component_commit_new_generation =
				*new_generation;
			g_pending_teep_live.component_commit_payload_len = wasm_len;
		}
#endif
		IMSG("twep-wr-ta app generation %llu committed",
		     (unsigned long long)*new_generation);
	} else {
		IMSG("twep-wr-ta app commit failed 0x%x", res);
	}
	pending_host_io_clear(&g_pending_host_io);
	return acceptance_host_status(res);
}

#ifdef TWEP_TA_D043_TEST_HOOKS
void twep_ta_pending_diagnostics(uint32_t *flags, uint32_t *count,
				 uint32_t *bytes)
{
	uint32_t pending_flags = g_pending_host_io.active ? 1u : 0u;

#ifdef TWEP_TA_WAMR_LINK
	if (g_pending_teep_live.active)
		pending_flags |= 2u;
	if (g_teep_agent_live_session.active)
		pending_flags |= 4u;
#endif
	*flags = pending_flags;
	*count = (uint32_t)g_pending_http_transcript_count;
	*bytes = (uint32_t)g_pending_http_transcript_bytes;
}
#endif
static int32_t teep_host_random(wasm_exec_env_t exec_env, uint8_t *buf,
				uint32_t buf_len)
{
	if (!teep_hostcall_context(exec_env) || (!buf && buf_len))
		return 1;
	if (buf_len)
		TEE_GenerateRandom(buf, buf_len);
	return 0;
}

static uint64_t teep_host_unix_time_ms(wasm_exec_env_t exec_env)
{
	TEE_Time time = {};

	if (!teep_hostcall_context(exec_env))
		return 0;
	TEE_GetSystemTime(&time);
	return ((uint64_t)time.seconds * 1000) + time.millis;
}

NativeSymbol teep_agent_native_symbols[14] = {
	{"twep_host_log", teep_host_log, "(i*~)", NULL},
	{"twep_host_read_file", teep_host_read_file, "(*~*~*)i", NULL},
	{"twep_host_write_file", teep_host_write_file, "(*~*~)i", NULL},
	{"twep_host_read_protected", teep_host_read_protected, "(*~*~*)i",
	 NULL},
	{"twep_host_http_post", teep_host_http_post, "(*~*~*~*)i", NULL},
	{"twep_host_create_evidence", teep_host_create_evidence, "(*~*~*~*)i",
	 NULL},
	{"twep_host_platform_status", teep_host_platform_status, "(*~*)i",
	 NULL},
	{"twep_host_teep_agent_measurement_sha256",
	 teep_host_teep_agent_measurement_sha256, "(*~*)i", NULL},
	{"twep_host_acceptance_generation", teep_host_acceptance_generation,
	 "(*)i", NULL},
	{"twep_host_commit_acceptance", teep_host_commit_acceptance,
	 "(*~*~II*)i", NULL},
	{"twep_host_commit_catalog", teep_host_commit_catalog, "(*~*~II*~*~*)i",
	 NULL},
	{"twep_host_commit_app", teep_host_commit_app, "(*~*~II*~*~*)i", NULL},
	{"twep_host_random", teep_host_random, "(*~)i", NULL},
	{"twep_host_unix_time_ms", teep_host_unix_time_ms, "()I", NULL},
};

#endif /* TWEP_TA_WAMR_LINK */
