/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "twep_wr.h"

#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct runner {
    const char *capture_dir;
    unsigned request_number;
};

struct response {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int overflow;
};

static const uint8_t calcadd_3_4_5_input[] = {
    0xa1, 0x6f, 'i','n','f','e','r','r','e','d','_','p','a','r','a','m','s',
    0x83,
    0xa2,0x64,'t','y','p','e',0x63,'i','n','t',0x65,'v','a','l','u','e',0x03,
    0xa2,0x64,'t','y','p','e',0x63,'i','n','t',0x65,'v','a','l','u','e',0x04,
    0xa2,0x64,'t','y','p','e',0x63,'i','n','t',0x65,'v','a','l','u','e',0x05,
};

static int contains_bytes(const uint8_t *buf, size_t len, const char *text)
{
    size_t text_len = strlen(text);
    for (size_t i = 0; i + text_len <= len; ++i)
        if (memcmp(buf + i, text, text_len) == 0)
            return 1;
    return 0;
}

static int contains_jpeg(const uint8_t *buf, size_t len)
{
    static const uint8_t magic[] = { 0xff, 0xd8, 0xff };
    for (size_t i = 0; i + sizeof(magic) <= len; ++i)
        if (memcmp(buf + i, magic, sizeof(magic)) == 0)
            return 1;
    return 0;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *file = fopen(path, "rb");
    uint8_t *bytes = NULL;
    long len;
    if (!file || fseek(file, 0, SEEK_END) != 0 || (len = ftell(file)) <= 0
        || fseek(file, 0, SEEK_SET) != 0)
        goto out;
    bytes = malloc((size_t)len);
    if (!bytes || fread(bytes, 1, (size_t)len, file) != (size_t)len) {
        free(bytes);
        bytes = NULL;
        goto out;
    }
    *out_len = (size_t)len;
out:
    if (file)
        fclose(file);
    return bytes;
}

static uint8_t *make_negaposi_input(const char *path, size_t *out_len)
{
    uint8_t *image, *input, *p;
    size_t image_len = 0;
    image = read_file(path, &image_len);
    if (!image || image_len > UINT32_MAX) {
        free(image);
        return NULL;
    }
    input = malloc(image_len + 32);
    if (!input) {
        free(image);
        return NULL;
    }
    p = input;
    *p++ = 0xa1; *p++ = 0x65; memcpy(p, "files", 5); p += 5;
    *p++ = 0xa1; *p++ = 0x65; memcpy(p, "input", 5); p += 5;
    *p++ = 0x5a;
    *p++ = (uint8_t)(image_len >> 24); *p++ = (uint8_t)(image_len >> 16);
    *p++ = (uint8_t)(image_len >> 8); *p++ = (uint8_t)image_len;
    memcpy(p, image, image_len); p += image_len;
    free(image);
    *out_len = (size_t)(p - input);
    return input;
}

static size_t receive_response(char *ptr, size_t size, size_t count, void *arg)
{
    struct response *response = arg;
    size_t len = size * count;
    if (len > response->cap - response->len) {
        response->overflow = 1;
        return 0;
    }
    memcpy(response->buf + response->len, ptr, len);
    response->len += len;
    return len;
}

static int save_capture(struct runner *runner, const uint8_t *body,
                        size_t body_len)
{
    char path[1024];
    FILE *file;
    int n = snprintf(path, sizeof(path), "%s/request-%02u.cbor",
                     runner->capture_dir, runner->request_number++);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return 0;
    file = fopen(path, "wb");
    if (file == NULL)
        return 0;
    int ok = fwrite(body, 1, body_len, file) == body_len;
    return fclose(file) == 0 && ok;
}

static int32_t http_post(void *arg, const uint8_t *url, size_t url_len,
                         const uint8_t *body, size_t body_len, uint8_t *buf,
                         size_t buf_cap, size_t *out_len)
{
    struct runner *runner = arg;
    struct response response = { .buf = buf, .cap = buf_cap };
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    char *url_text = NULL;
    long status = 0;
    int32_t result = 7;
    if (!out_len || !url || (!body && body_len) || !buf
        || !save_capture(runner, body, body_len))
        return 1;
    *out_len = 0;
    url_text = malloc(url_len + 1);
    if (!url_text)
        return 2;
    memcpy(url_text, url, url_len);
    url_text[url_len] = '\0';
    curl = curl_easy_init();
    headers = curl_slist_append(headers, "Content-Type: application/teep+cbor");
    headers = curl_slist_append(headers, "Accept: application/teep+cbor");
    if (!curl || !headers
        || curl_easy_setopt(curl, CURLOPT_URL, url_text) != CURLE_OK
        || curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK
        || curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
                            body_len ? (const char *)body : "") != CURLE_OK
        || curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                            (curl_off_t)body_len) != CURLE_OK
        || curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_response)
                                                               != CURLE_OK
        || curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response) != CURLE_OK
        || curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L) != CURLE_OK
        || curl_easy_perform(curl) != CURLE_OK || response.overflow
        || curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        goto out;
    *out_len = response.len;
    result = status == 200 || status == 204 ? 0 : 7;
out:
    curl_slist_free_all(headers);
    if (curl)
        curl_easy_cleanup(curl);
    free(url_text);
    return result;
}

static twep_wr_status_t init_context(const char *state_dir,
                                     const char *attestam_url,
                                     struct runner *runner,
                                     twep_wr_context_t **ctx)
{
    twep_wr_config_t config = {
        .state_dir = state_dir,
        .resolver_mode = "attestam-verified",
        .attestam_url = attestam_url,
        .default_timeout_ms = 30000,
        .max_request_bytes = 1024 * 1024,
        .max_response_bytes = 1024 * 1024,
    };
    twep_wr_host_io_t host_io = {
        .http_post = http_post,
        .user_data = runner,
    };
    twep_wr_status_t status = twep_wr_init(&config, ctx);
    if (status == TWEP_WR_OK)
        status = twep_wr_set_host_io(*ctx, &host_io);
    return status;
}

static int execute_app(twep_wr_context_t *ctx, const char *request_id,
                       const char *command, const uint8_t *input,
                       size_t input_len, int expect_jpeg)
{
    struct timespec started, finished;
    twep_wr_normalized_request_t request = {
        .request_id = request_id,
        .command = command,
        .app_input_cbor = { input, input_len },
        .request_timeout_ms = 30000,
    };
    twep_wr_owned_bytes_t response = { 0 };
    (void)clock_gettime(CLOCK_MONOTONIC, &started);
    twep_wr_status_t status = twep_wr_execute(ctx, &request, &response);
    (void)clock_gettime(CLOCK_MONOTONIC, &finished);
    uint64_t elapsed_ms = (uint64_t)(finished.tv_sec - started.tv_sec) * 1000u;
    if (finished.tv_nsec >= started.tv_nsec)
        elapsed_ms += (uint64_t)(finished.tv_nsec - started.tv_nsec) / 1000000u;
    else
        elapsed_ms -= (uint64_t)(started.tv_nsec - finished.tv_nsec) / 1000000u;
    int ok = status == TWEP_WR_OK && response.ptr && response.len
        && (expect_jpeg ? contains_jpeg(response.ptr, response.len)
            : contains_bytes(response.ptr, response.len,
                strcmp(command, "calcadd") == 0 ? "12\n" : "Hello, World!!"));
    printf("%s-status=%u (%s) response=%zu elapsed-ms=%llu\n", request_id,
           (unsigned)status, twep_wr_status_string(status), response.len,
           (unsigned long long)elapsed_ms);
    if (!ok)
        fprintf(stderr, "%s execution failed\n", request_id);
    twep_wr_free_bytes(response);
    return ok;
}

static int run_apps_restart(const char *state_dir, const char *attestam_url,
                            const char *jpeg_path, struct runner *runner,
                            twep_wr_context_t *ctx)
{
    static const struct {
        const char *command;
        const uint8_t *input;
        size_t input_len;
        int expect_jpeg;
    } fixed[] = {
        { "helloworld", NULL, 0, 0 },
        { "calcadd", calcadd_3_4_5_input, sizeof(calcadd_3_4_5_input), 0 },
    };
    uint8_t *negaposi_input = NULL;
    size_t negaposi_input_len = 0;
    int ok = 1;

    negaposi_input = make_negaposi_input(jpeg_path, &negaposi_input_len);
    if (!negaposi_input)
        return 0;
    for (size_t i = 0; ok && i < 3; ++i) {
        const char *command = i < 2 ? fixed[i].command : "negaposi";
        const uint8_t *input = i < 2 ? fixed[i].input : negaposi_input;
        size_t input_len = i < 2 ? fixed[i].input_len : negaposi_input_len;
        int expect_jpeg = i < 2 ? fixed[i].expect_jpeg : 1;
        char online_id[64], offline_id[64];
        unsigned before_offline;

        snprintf(online_id, sizeof(online_id), "sgx-hw-pr10-%s-online", command);
        snprintf(offline_id, sizeof(offline_id), "sgx-hw-pr10-%s-offline", command);
        if (i != 0) {
            if (init_context(state_dir, attestam_url, runner, &ctx)
                != TWEP_WR_OK) {
                ok = 0;
                break;
            }
        }
        ok = execute_app(ctx, online_id, command, input, input_len,
                         expect_jpeg);
        twep_wr_shutdown(ctx);
        ctx = NULL;
        if (!ok)
            break;

        before_offline = runner->request_number;
        if (init_context(state_dir, "http://127.0.0.1:1/tam", runner, &ctx)
            != TWEP_WR_OK) {
            ok = 0;
            break;
        }
        ok = execute_app(ctx, offline_id, command, input, input_len,
                         expect_jpeg)
            && runner->request_number == before_offline;
        twep_wr_shutdown(ctx);
        ctx = NULL;
        if (!ok)
            fprintf(stderr, "%s restart used HTTP or failed\n", command);
    }
    free(negaposi_input);
    return ok;
}

int main(int argc, char **argv)
{
    struct runner runner;
    const char *mode;
    twep_wr_context_t *ctx = NULL;
    twep_wr_owned_bytes_t response = { 0 };
    twep_wr_status_t status;
    if (argc != 5 && argc != 6) {
        fprintf(stderr,
                "usage: %s STATE_DIR ATTESTAM_URL CAPTURE_DIR auth|catalog|app|apps-restart [JPEG]\n",
                argv[0]);
        return 2;
    }
    mode = argv[4];
    if (strcmp(mode, "auth") != 0 && strcmp(mode, "catalog") != 0
        && strcmp(mode, "app") != 0 && strcmp(mode, "apps-restart") != 0) {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }
    if ((strcmp(mode, "apps-restart") == 0) != (argc == 6)) {
        fprintf(stderr, "apps-restart requires exactly one JPEG fixture\n");
        return 2;
    }
    runner.capture_dir = argv[3];
    runner.request_number = 0;
    twep_wr_normalized_request_t request = {
        .request_id = "sgx-hw-pr10-catalog",
        .command = "helloworld",
        .request_timeout_ms = 30000,
    };
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return 1;
    status = init_context(argv[1], argv[2], &runner, &ctx);
    if (status != TWEP_WR_OK) {
        fprintf(stderr, "SGX HW initialization failed: %s\n",
                twep_wr_status_string(status));
        if (ctx)
            twep_wr_shutdown(ctx);
        curl_global_cleanup();
        return 1;
    }
    status = twep_wr_execute(ctx, &request, &response);
    printf("twep-status=%u (%s)\nhttp-request-count=%u\n",
           (unsigned)status, twep_wr_status_string(status),
           runner.request_number);
    if (strcmp(mode, "catalog") == 0)
        printf("catalog-terminal-check=state-diagnostic\n");
    int ok = runner.request_number >= 2
        && (status == TWEP_WR_ERR_TEEP || status == TWEP_WR_ERR_CATALOG
            || status == TWEP_WR_ERR_SECURITY);
    if (strcmp(mode, "catalog") == 0)
        ok = runner.request_number >= 4 && status == TWEP_WR_ERR_TEEP;
    if (strcmp(mode, "app") == 0) {
        if (runner.request_number < 4 || status != TWEP_WR_ERR_TEEP) {
            fprintf(stderr,
                    "Catalog phase failed: status=%u requests=%u\n",
                    (unsigned)status, runner.request_number);
            ok = 0;
        } else {
            twep_wr_free_bytes(response);
            response.ptr = NULL;
            response.len = 0;
            request.request_id = "sgx-hw-pr10-app";
            status = twep_wr_execute(ctx, &request, &response);
            printf("app-twep-status=%u (%s)\nhttp-request-count-total=%u\n",
                   (unsigned)status, twep_wr_status_string(status),
                   runner.request_number);
            ok = status == TWEP_WR_OK && runner.request_number >= 7
                && response.ptr != NULL && response.len != 0
                && contains_bytes(response.ptr, response.len,
                                  "Hello, World!!");
            if (!ok)
                fprintf(stderr,
                        "app phase failed: status=%u requests=%u response=%zu\n",
                        (unsigned)status, runner.request_number, response.len);
        }
    }
    if (strcmp(mode, "apps-restart") == 0) {
        if (runner.request_number < 4 || status != TWEP_WR_ERR_TEEP) {
            fprintf(stderr,
                    "Catalog phase failed: status=%u requests=%u\n",
                    (unsigned)status, runner.request_number);
            ok = 0;
        } else {
            twep_wr_free_bytes(response);
            response.ptr = NULL;
            response.len = 0;
            ok = run_apps_restart(argv[1], argv[2], argv[5], &runner, ctx);
            ctx = NULL;
        }
    }
    twep_wr_free_bytes(response);
    if (ctx)
        twep_wr_shutdown(ctx);
    curl_global_cleanup();
    return ok ? 0 : 1;
}
