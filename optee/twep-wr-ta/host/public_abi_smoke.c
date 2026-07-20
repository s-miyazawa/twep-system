/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
// SPDX-License-Identifier: BSD-2-Clause

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "twep_wr.h"

static const uint8_t calcadd_3_4_5_input[] = {
	0xa1,
	0x6f, 'i', 'n', 'f', 'e', 'r', 'r', 'e', 'd', '_', 'p', 'a', 'r',
	'a', 'm', 's',
	0x83,
	0xa2, 0x64, 't', 'y', 'p', 'e', 0x63, 'i', 'n', 't',
	0x65, 'v', 'a', 'l', 'u', 'e', 0x03,
	0xa2, 0x64, 't', 'y', 'p', 'e', 0x63, 'i', 'n', 't',
	0x65, 'v', 'a', 'l', 'u', 'e', 0x04,
	0xa2, 0x64, 't', 'y', 'p', 'e', 0x63, 'i', 'n', 't',
	0x65, 'v', 'a', 'l', 'u', 'e', 0x05,
};

static size_t cbor_len_size(uint64_t n)
{
	if (n < 24)
		return 1;
	if (n <= 0xff)
		return 2;
	if (n <= 0xffff)
		return 3;
	if (n <= 0xffffffff)
		return 5;
	return 9;
}

static void cbor_write_type_len(uint8_t **p, uint8_t major, uint64_t n)
{
	if (n < 24) {
		*(*p)++ = (uint8_t)((major << 5) | n);
	} else if (n <= 0xff) {
		*(*p)++ = (uint8_t)((major << 5) | 24);
		*(*p)++ = (uint8_t)n;
	} else if (n <= 0xffff) {
		*(*p)++ = (uint8_t)((major << 5) | 25);
		*(*p)++ = (uint8_t)(n >> 8);
		*(*p)++ = (uint8_t)n;
	} else {
		*(*p)++ = (uint8_t)((major << 5) | 26);
		*(*p)++ = (uint8_t)(n >> 24);
		*(*p)++ = (uint8_t)(n >> 16);
		*(*p)++ = (uint8_t)(n >> 8);
		*(*p)++ = (uint8_t)n;
	}
}

static void cbor_write_text(uint8_t **p, const char *text)
{
	size_t len = strlen(text);

	cbor_write_type_len(p, 3, len);
	memcpy(*p, text, len);
	*p += len;
}

static int looks_like_jpeg_bytes(const uint8_t *bytes, size_t len)
{
	return len >= 4 && bytes[0] == 0xff && bytes[1] == 0xd8 &&
	       bytes[len - 2] == 0xff && bytes[len - 1] == 0xd9;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
	FILE *fp;
	long len;
	uint8_t *buf;

	fp = fopen(path, "rb");
	if (!fp)
		err(1, "open %s", path);
	if (fseek(fp, 0, SEEK_END) != 0)
		err(1, "seek %s", path);
	len = ftell(fp);
	if (len < 0)
		err(1, "tell %s", path);
	if (fseek(fp, 0, SEEK_SET) != 0)
		err(1, "rewind %s", path);

	buf = malloc(len == 0 ? 1 : (size_t)len);
	if (!buf)
		err(1, "allocate %s", path);
	if (len != 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len)
		err(1, "read %s", path);
	if (fclose(fp) != 0)
		err(1, "close %s", path);
	*out_len = (size_t)len;
	return buf;
}

static void write_file(const char *path, const uint8_t *bytes, size_t len)
{
	FILE *fp;

	fp = fopen(path, "wb");
	if (!fp)
		err(1, "open output %s", path);
	if (len != 0 && fwrite(bytes, 1, len, fp) != len)
		err(1, "write output %s", path);
	if (fclose(fp) != 0)
		err(1, "close output %s", path);
}

static uint8_t *make_resolve_input(const char *target_command, size_t *out_len)
{
	size_t len = 1
		     + 1 + strlen("schema_version") + 1
		     + 1 + strlen("command") + 1 + strlen("resolve_app")
		     + 1 + strlen("target_command") +
		       cbor_len_size(strlen(target_command)) +
		       strlen(target_command)
		     + 1 + strlen("resolver_mode") + 1 + strlen("mock")
		     + 1 + strlen("state_dir") + 1
		     + 1 + strlen("attestam_url") + 1;
	uint8_t *buf = malloc(len);
	uint8_t *p = buf;

	if (!buf)
		err(1, "malloc resolve input");
	*p++ = 0xa6;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "command");
	cbor_write_text(&p, "resolve_app");
	cbor_write_text(&p, "target_command");
	cbor_write_text(&p, target_command);
	cbor_write_text(&p, "resolver_mode");
	cbor_write_text(&p, "mock");
	cbor_write_text(&p, "state_dir");
	cbor_write_text(&p, "");
	cbor_write_text(&p, "attestam_url");
	cbor_write_text(&p, "");
	*out_len = (size_t)(p - buf);
	return buf;
}

static uint8_t *make_negaposi_input(const uint8_t *jpeg, size_t jpeg_len,
				    size_t *out_len)
{
	size_t len = 1
		     + 1 + strlen("files")
		     + 1
		     + 1 + strlen("input")
		     + cbor_len_size(jpeg_len) + jpeg_len;
	uint8_t *buf = malloc(len);
	uint8_t *p = buf;

	if (!buf)
		err(1, "malloc negaposi input");
	*p++ = 0xa1;
	cbor_write_text(&p, "files");
	*p++ = 0xa1;
	cbor_write_text(&p, "input");
	cbor_write_type_len(&p, 2, jpeg_len);
	memcpy(p, jpeg, jpeg_len);
	p += jpeg_len;
	*out_len = (size_t)(p - buf);
	return buf;
}

static int cbor_read_type_len(const uint8_t *bytes, size_t len, size_t *off,
			      uint8_t want_major, uint64_t *out)
{
	uint8_t initial = 0;
	uint8_t major = 0;
	uint8_t ai = 0;
	uint64_t value = 0;
	size_t needed = 0;
	size_t i = 0;

	if (*off >= len)
		return 0;
	initial = bytes[(*off)++];
	major = initial >> 5;
	ai = initial & 0x1f;
	if (major != want_major)
		return 0;
	if (ai < 24) {
		*out = ai;
		return 1;
	}
	if (ai == 24)
		needed = 1;
	else if (ai == 25)
		needed = 2;
	else if (ai == 26)
		needed = 4;
	else
		return 0;
	if (needed > len - *off)
		return 0;
	for (i = 0; i < needed; i++)
		value = (value << 8) | bytes[(*off)++];
	*out = value;
	return 1;
}

static int cbor_read_text_key(const uint8_t *bytes, size_t len, size_t *off,
			      const char *want)
{
	uint64_t text_len = 0;
	size_t want_len = strlen(want);

	if (!cbor_read_type_len(bytes, len, off, 3, &text_len))
		return 0;
	if (text_len != want_len || text_len > len - *off)
		return 0;
	if (memcmp(bytes + *off, want, want_len) != 0)
		return 0;
	*off += want_len;
	return 1;
}

static int cbor_expect_text_value(const uint8_t *bytes, size_t len,
				  size_t *off, const char *want)
{
	uint64_t text_len = 0;
	size_t want_len = strlen(want);

	if (!cbor_read_type_len(bytes, len, off, 3, &text_len))
		return 0;
	if (text_len != want_len || text_len > len - *off)
		return 0;
	if (memcmp(bytes + *off, want, want_len) != 0)
		return 0;
	*off += want_len;
	return 1;
}

static int validate_wrapped_teep_error_response(const uint8_t *bytes,
						size_t len,
						const char *request_id,
						const char *command,
						const char *want_code,
						const char *want_message)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t error_map_len = 0;
	uint64_t details_map_len = 0;
	uint64_t value = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 5)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, request_id))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &error_map_len) ||
	    error_map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "code") ||
	    !cbor_expect_text_value(bytes, len, &off, want_code))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "message") ||
	    !cbor_expect_text_value(bytes, len, &off, want_message))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "details"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &details_map_len) ||
	    details_map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "source") ||
	    !cbor_expect_text_value(bytes, len, &off, "teep-agent"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "teep_code") ||
	    !cbor_expect_text_value(bytes, len, &off, want_code))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "command") ||
	    !cbor_expect_text_value(bytes, len, &off, command))
		return 0;
	return off == len;
}

static int validate_app_runtime_error_response(const uint8_t *bytes,
					       size_t len,
					       const char *request_id,
					       const char *command,
					       const char *want_code,
					       const char *want_message,
					       const char *want_reason)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t error_map_len = 0;
	uint64_t details_map_len = 0;
	uint64_t value = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) ||
	    map_len != 5)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, request_id))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &error_map_len) ||
	    error_map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "code") ||
	    !cbor_expect_text_value(bytes, len, &off, want_code))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "message") ||
	    !cbor_expect_text_value(bytes, len, &off, want_message))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "details"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &details_map_len) ||
	    details_map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "source") ||
	    !cbor_expect_text_value(bytes, len, &off, "app-runtime"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "command") ||
	    !cbor_expect_text_value(bytes, len, &off, command))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "reason") ||
	    !cbor_expect_text_value(bytes, len, &off, want_reason))
		return 0;
	return off == len;
}

static int validate_wrapped_catalog_not_found(const uint8_t *bytes, size_t len)
{
	return validate_wrapped_teep_error_response(
		bytes, len, "req-public-abi", "teep-agent-resolve-wrapped",
		"catalog.not_found", "target command not found");
}

static int validate_helloworld_app_output(const uint8_t *bytes, size_t len)
{
	static const uint8_t expected_stdout[] = "Hello, World!!\n";
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "ok"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != sizeof(expected_stdout) - 1 || bytes_len > len - off ||
	    memcmp(bytes + off, expected_stdout, sizeof(expected_stdout) - 1) != 0)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	return off == len;
}

static int validate_helloworld_execute_response(const uint8_t *bytes,
						size_t len)
{
	static const uint8_t expected_stdout[] = "Hello, World!!\n";
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 6)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, "req-public-helloworld"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "ok"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 0)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != sizeof(expected_stdout) - 1 || bytes_len > len - off ||
	    memcmp(bytes + off, expected_stdout, sizeof(expected_stdout) - 1) != 0)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "app_output"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off ||
	    !validate_helloworld_app_output(bytes + off, (size_t)bytes_len))
		return 0;
	off += bytes_len;
	return off == len;
}

static int validate_calcadd_app_output(const uint8_t *bytes, size_t len)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 4)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "ok"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 3 || bytes_len > len - off ||
	    memcmp(bytes + off, "12\n", 3) != 0)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "result"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "sum"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 12)
		return 0;
	return off == len;
}

static int validate_calcadd_execute_response(const uint8_t *bytes, size_t len)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 6)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, "req-public-calcadd"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "ok"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 0)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 3 || bytes_len > len - off ||
	    memcmp(bytes + off, "12\n", 3) != 0)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "app_output"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off ||
	    !validate_calcadd_app_output(bytes + off, (size_t)bytes_len))
		return 0;
	off += bytes_len;
	return off == len;
}

static int validate_negaposi_app_output(const uint8_t *bytes, size_t len,
					const char *output_path)
{
	static const uint8_t expected_stdout[] =
		"Saving a Reversed Color Image\n";
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 5)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "ok"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "files"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "output"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off ||
	    !looks_like_jpeg_bytes(bytes + off, (size_t)bytes_len))
		return 0;
	if (output_path != NULL)
		write_file(output_path, bytes + off, (size_t)bytes_len);
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "metadata"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "output_mime") ||
	    !cbor_expect_text_value(bytes, len, &off, "image/jpeg"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != sizeof(expected_stdout) - 1 || bytes_len > len - off ||
	    memcmp(bytes + off, expected_stdout, sizeof(expected_stdout) - 1) != 0)
		return 0;
	off += bytes_len;
	return off == len;
}

static int validate_negaposi_execute_response(const uint8_t *bytes, size_t len,
					      const char *output_path)
{
	static const uint8_t expected_stdout[] =
		"Saving a Reversed Color Image\n";
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 6)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, "req-public-negaposi"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "ok"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 0)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != sizeof(expected_stdout) - 1 || bytes_len > len - off ||
	    memcmp(bytes + off, expected_stdout, sizeof(expected_stdout) - 1) != 0)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "app_output"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off ||
	    !validate_negaposi_app_output(bytes + off, (size_t)bytes_len,
					  output_path))
		return 0;
	off += bytes_len;
	return off == len;
}

static void run_wrapped_error(twep_wr_context_t *ctx)
{
	twep_wr_owned_bytes_t response = { 0 };
	uint8_t *app_input = NULL;
	size_t app_input_len = 0;
	twep_wr_status_t status;

	app_input = make_resolve_input("missingapp", &app_input_len);
	twep_wr_normalized_request_t request = {
		.request_id = "req-public-abi",
		.command = "teep-agent-resolve-wrapped",
		.app_input_cbor = {
			.ptr = app_input,
			.len = app_input_len,
		},
		.request_timeout_ms = 1000,
	};
	status = twep_wr_execute(ctx, &request, &response);
	free(app_input);
	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_execute failed: %s",
		     twep_wr_status_string(status));
	if (!validate_wrapped_catalog_not_found(response.ptr, response.len)) {
		twep_wr_free_bytes(response);
		errx(1, "public C ABI returned unexpected wrapped response");
	}
	twep_wr_free_bytes(response);
	puts("public C ABI TrustZone execute wrapped error catalog.not_found ok");
}

static void run_helloworld(twep_wr_context_t *ctx)
{
	twep_wr_owned_bytes_t response = { 0 };
	twep_wr_normalized_request_t request = {
		.request_id = "req-public-helloworld",
		.command = "helloworld",
		.app_input_cbor = {
			.ptr = NULL,
			.len = 0,
		},
		.request_timeout_ms = 1000,
	};
	twep_wr_status_t status = twep_wr_execute(ctx, &request, &response);

	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_execute helloworld failed: %s",
		     twep_wr_status_string(status));
	if (!validate_helloworld_execute_response(response.ptr, response.len)) {
		twep_wr_free_bytes(response);
		errx(1, "public C ABI returned unexpected helloworld response");
	}
	twep_wr_free_bytes(response);
	puts("public C ABI TrustZone execute helloworld ok");
}

static void run_calcadd(twep_wr_context_t *ctx)
{
	twep_wr_owned_bytes_t response = { 0 };
	twep_wr_normalized_request_t request = {
		.request_id = "req-public-calcadd",
		.command = "calcadd",
		.app_input_cbor = {
			.ptr = calcadd_3_4_5_input,
			.len = sizeof(calcadd_3_4_5_input),
		},
		.request_timeout_ms = 1000,
	};
	twep_wr_status_t status = twep_wr_execute(ctx, &request, &response);

	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_execute calcadd failed: %s",
		     twep_wr_status_string(status));
	if (!validate_calcadd_execute_response(response.ptr, response.len)) {
		twep_wr_free_bytes(response);
		errx(1, "public C ABI returned unexpected calcadd response");
	}
	twep_wr_free_bytes(response);
	puts("public C ABI TrustZone execute calcadd ok");
}

static void corrupt_cached_helloworld(const char *state_dir)
{
	char path[1024];
	uint8_t *wasm = NULL;
	size_t wasm_len = 0;
	int n = snprintf(path, sizeof(path), "%s/apps/helloworld.wasm",
			 state_dir);

	if (n <= 0 || (size_t)n >= sizeof(path))
		errx(1, "state path too long");
	wasm = read_file(path, &wasm_len);
	if (wasm_len < 9) {
		free(wasm);
		errx(1, "cached helloworld wasm too short");
	}
	wasm[wasm_len - 1] ^= 0x01;
	write_file(path, wasm, wasm_len);
	free(wasm);
}

static void patch_catalog_negaposi_max_output(const char *state_dir,
					      uint32_t max_output_bytes)
{
	static const uint8_t max_output_key[] = {
		0x70, 'm', 'a', 'x', '_', 'o', 'u', 't', 'p', 'u', 't',
		'_', 'b', 'y', 't', 'e', 's',
	};
	char path[1024];
	uint8_t *catalog = NULL;
	size_t catalog_len = 0;
	size_t i = 0;
	int n = snprintf(path, sizeof(path), "%s/catalog/catalog.cbor",
			 state_dir);

	if (n <= 0 || (size_t)n >= sizeof(path))
		errx(1, "catalog path too long");
	catalog = read_file(path, &catalog_len);
	if (catalog_len < sizeof(max_output_key) + 5) {
		free(catalog);
		errx(1, "catalog too short to patch max_output_bytes");
	}
	for (i = 0; i <= catalog_len - sizeof(max_output_key) - 5; i++) {
		if (memcmp(catalog + i, max_output_key,
			   sizeof(max_output_key)) == 0 &&
		    catalog[i + sizeof(max_output_key)] == 0x1a) {
			size_t value = i + sizeof(max_output_key) + 1;

			catalog[value] = (uint8_t)(max_output_bytes >> 24);
			catalog[value + 1] = (uint8_t)(max_output_bytes >> 16);
			catalog[value + 2] = (uint8_t)(max_output_bytes >> 8);
			catalog[value + 3] = (uint8_t)max_output_bytes;
			write_file(path, catalog, catalog_len);
			free(catalog);
			return;
		}
	}
	free(catalog);
	errx(1, "catalog max_output_bytes field not found");
}

static void run_public_app_hash_negative(twep_wr_context_t *ctx,
					 const char *state_dir)
{
	twep_wr_owned_bytes_t response = { 0 };
	twep_wr_normalized_request_t prime_request = {
		.request_id = "req-public-hash-prime",
		.command = "helloworld",
		.app_input_cbor = {
			.ptr = NULL,
			.len = 0,
		},
		.request_timeout_ms = 1000,
	};
	twep_wr_normalized_request_t request = {
		.request_id = "req-public-hash-negative",
		.command = "helloworld",
		.app_input_cbor = {
			.ptr = NULL,
			.len = 0,
		},
		.request_timeout_ms = 1000,
	};
	twep_wr_status_t status = twep_wr_execute(ctx, &prime_request,
						  &response);

	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_execute hash-negative prime failed: %s",
		     twep_wr_status_string(status));
	twep_wr_free_bytes(response);
	response.ptr = NULL;
	response.len = 0;

	corrupt_cached_helloworld(state_dir);
	status = twep_wr_execute(ctx, &request, &response);
	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_execute hash-negative failed: %s",
		     twep_wr_status_string(status));
	if (!validate_wrapped_teep_error_response(
		    response.ptr, response.len, "req-public-hash-negative",
		    "helloworld", "app.hash_mismatch",
		    "app wasm hash mismatch")) {
		twep_wr_free_bytes(response);
		errx(1, "public C ABI returned unexpected hash negative response");
	}
	twep_wr_free_bytes(response);
	puts("public C ABI TrustZone execute app.hash_mismatch wrapped error ok");
}

static void run_public_resource_limit_negative(twep_wr_context_t *ctx,
					       const char *state_dir,
					       const char *input_path)
{
	twep_wr_owned_bytes_t response = { 0 };
	uint8_t *jpeg = NULL;
	uint8_t *app_input = NULL;
	size_t jpeg_len = 0;
	size_t app_input_len = 0;
	twep_wr_normalized_request_t prime_request = {
		.request_id = "req-public-resource-prime",
		.command = "helloworld",
		.app_input_cbor = {
			.ptr = NULL,
			.len = 0,
		},
		.request_timeout_ms = 1000,
	};
	twep_wr_status_t status = twep_wr_execute(ctx, &prime_request,
						  &response);

	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_execute resource-negative prime failed: %s",
		     twep_wr_status_string(status));
	twep_wr_free_bytes(response);
	response.ptr = NULL;
	response.len = 0;

	patch_catalog_negaposi_max_output(state_dir, 8);
	jpeg = read_file(input_path, &jpeg_len);
	if (!looks_like_jpeg_bytes(jpeg, jpeg_len)) {
		free(jpeg);
		errx(1, "input fixture is not a JPEG: %s", input_path);
	}
	app_input = make_negaposi_input(jpeg, jpeg_len, &app_input_len);
	free(jpeg);

	twep_wr_normalized_request_t request = {
		.request_id = "req-public-resource-negative",
		.command = "negaposi",
		.app_input_cbor = {
			.ptr = app_input,
			.len = app_input_len,
		},
		.request_timeout_ms = 1000,
	};
	status = twep_wr_execute(ctx, &request, &response);
	free(app_input);
	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_execute resource-negative failed: %s",
		     twep_wr_status_string(status));
	if (!validate_app_runtime_error_response(
		    response.ptr, response.len, "req-public-resource-negative",
		    "negaposi", "app.resource_limit",
		    "resource limit exceeded", "max_output_bytes")) {
		twep_wr_free_bytes(response);
		errx(1, "public C ABI returned unexpected resource limit response");
	}
	twep_wr_free_bytes(response);
	puts("public C ABI TrustZone execute app.resource_limit wrapped error ok");
}

static void run_negaposi(twep_wr_context_t *ctx, const char *input_path,
			 const char *output_path)
{
	twep_wr_owned_bytes_t response = { 0 };
	uint8_t *jpeg = NULL;
	uint8_t *app_input = NULL;
	size_t jpeg_len = 0;
	size_t app_input_len = 0;
	twep_wr_status_t status;

	jpeg = read_file(input_path, &jpeg_len);
	if (!looks_like_jpeg_bytes(jpeg, jpeg_len)) {
		free(jpeg);
		errx(1, "input fixture is not a JPEG: %s", input_path);
	}
	app_input = make_negaposi_input(jpeg, jpeg_len, &app_input_len);
	free(jpeg);

	twep_wr_normalized_request_t request = {
		.request_id = "req-public-negaposi",
		.command = "negaposi",
		.app_input_cbor = {
			.ptr = app_input,
			.len = app_input_len,
		},
		.request_timeout_ms = 1000,
	};
	status = twep_wr_execute(ctx, &request, &response);
	free(app_input);
	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_execute negaposi failed: %s",
		     twep_wr_status_string(status));
	if (!validate_negaposi_execute_response(response.ptr, response.len,
						output_path)) {
		twep_wr_free_bytes(response);
		errx(1, "public C ABI returned unexpected negaposi response");
	}
	twep_wr_free_bytes(response);
	puts("public C ABI TrustZone execute negaposi ok");
}

int main(int argc, char *argv[])
{
	const char *state_dir = argc > 1 ? argv[1] : "guest/state/public-abi";
	const char *mode = argc > 2 ? argv[2] : "wrapped-error";
	const char *input_path = argc > 3 ? argv[3] : "fixtures/input.jpg";
	const char *output_path = argc > 4 ? argv[4] : "/tmp/twep-public-abi-output.jpg";
	twep_wr_config_t config = {
		.state_dir = state_dir,
		.resolver_mode = "mock",
		.attestam_url = "",
		.insecure_demo_mode = true,
		.default_timeout_ms = 5000,
		.max_request_bytes = 16u * 1024u * 1024u,
		.max_response_bytes = 16u * 1024u * 1024u,
	};
	twep_wr_context_t *ctx = NULL;
	twep_wr_status_t status;

	status = twep_wr_init(&config, &ctx);
	if (status != TWEP_WR_OK)
		errx(1, "twep_wr_init failed: %s",
		     twep_wr_status_string(status));
	if (strcmp(mode, "wrapped-error") == 0)
		run_wrapped_error(ctx);
	else if (strcmp(mode, "helloworld") == 0)
		run_helloworld(ctx);
	else if (strcmp(mode, "calcadd") == 0)
		run_calcadd(ctx);
	else if (strcmp(mode, "negaposi") == 0)
		run_negaposi(ctx, input_path, output_path);
	else if (strcmp(mode, "app-hash-negative") == 0)
		run_public_app_hash_negative(ctx, state_dir);
	else if (strcmp(mode, "resource-limit-negative") == 0)
		run_public_resource_limit_negative(ctx, state_dir, input_path);
	else
		errx(1, "unsupported mode %s", mode);
	twep_wr_shutdown(ctx);
	return 0;
}
