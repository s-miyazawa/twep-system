# Interface.md: IPC, CBOR, C ABI, and Wasm ABI Specifications

OP-TEE diagnostics distinguish `arm-optee` from `riscv-optee`; both use
`optee-ta` for runtime, TEEP Agent, and Catalog-resolution locations. This is
a profile clarification only and does not alter public C ABI v3.

The authoritative specification for the Trusted Wasm App ABI is `docs/ABI.md`. This file also documents the integration points among IPC, the C ABI, hostcalls, and the Wasm ABI.

## KISS / DRY

Interface updates must follow KISS and DRY. Do not define CBOR keys, error mappings, C ABI fields, or hostcall names independently in multiple places; identify and reference the authoritative definition. Do not add unnecessary conversion layers or aliases unless required for compatibility.

## 1. IPC Between twep-cli and twepd

### Transport

- Use a Unix domain socket.
- The default socket path is `$XDG_RUNTIME_DIR/twep/twepd.sock`. If
  `XDG_RUNTIME_DIR` is unset, both the client and daemon use
  `<os.TempDir()>/twep/twepd.sock`, normally `/tmp/twep/twepd.sock` on Linux.
- The basic model is one request and one response per connection.
- A frame consists of `uint32_be length` + `CBOR payload`.
- The default maximum request size is 16 MiB.
- The default maximum response size is 16 MiB.

### Request CBOR

Conceptual CDDL:

```cddl
twep-request = {
  "schema_version": 1,
  "request_id": tstr,
  "command": tstr,
  "argv": [* tstr],
  "inferred_params": [* typed-value],
  ? "app_input": bytes,
  ? "stdin": bytes,
  ? "files": { * tstr => bytes },
  ? "metadata": { * tstr => any },
  "cwd": tstr,
  ? "options": request-options,
}

typed-value =
  { "type": "int", "value": int } /
  { "type": "uint", "value": uint } /
  { "type": "text", "value": tstr } /
  { "type": "bytes", "value": bytes } /
  { "type": "bool", "value": bool }

request-options = {
  ? "timeout_ms": uint,
  ? "output_format": "text" / "cbor",
  ? "verbose": bool,
}
```

When `app_input` is present, the input passed to the Trusted Wasm App is the `app_input` bytes themselves; the host does not wrap them again. When it is absent, the twepd/Go wrapper canonicalizes `schema_version`, `command`, `argv`, `inferred_params`, and optional `stdin`, `files`, and `metadata` as the `app-input` CBOR passed to the app. `request_id`, `cwd`, `options`, and the top-level `app_input` are not passed to general apps.

`output_format` is command-specific. For IPC it is currently used only by
`tc-inventory`: omitted or `text` requests human-readable output, while `cbor`
requests the canonical CBOR response. `twep-cli diagnose verified` supports
`text` and `json` locally and does not send that operation to `twepd`.

On the normal `negaposi -i PATH -o PATH` CLI path, `twep-cli` reads the input file and writes the output file with user privileges. `twepd` and `twep-wr` do not accept arbitrary file paths for general Trusted Wasm Apps. They pass only the JPEG bytes in `files.input` to the Wasm app, and the CLI saves the JPEG bytes returned by the Wasm app in `files.output`. Output is saved by writing to a temporary file in the same directory and then renaming it. The current policy permits overwriting an existing file.

### Response CBOR

```cddl
twep-response = {
  "schema_version": 1,
  "request_id": tstr,
  "status": "ok" / "error",
  "exit_code": int,
  ? "stdout": bytes,
  ? "stderr": bytes,
  ? "app_output": bytes,
  ? "result": any,
  ? "error": twep-error,
}

twep-error = {
  "code": tstr,
  "message": tstr,
  ? "details": any,
}
```

## 2. C ABI Between twepd and twep-wr.so

### Header Policy

Only `lib/twep-wr/include/twep_wr.h` is a public header.

### Types

```c
typedef struct twep_wr_context twep_wr_context_t;

typedef struct {
    const uint8_t *ptr;
    size_t len;
} twep_wr_bytes_t;

typedef struct {
    uint8_t *ptr;
    size_t len;
} twep_wr_owned_bytes_t;

typedef struct {
    const char *request_id;
    const char *command;
    twep_wr_bytes_t app_input_cbor;
    uint32_t request_timeout_ms;
} twep_wr_normalized_request_t;

typedef enum {
    TWEP_WR_OK = 0,
    TWEP_WR_ERR_INVALID_ARGUMENT = 1,
    TWEP_WR_ERR_INIT = 2,
    TWEP_WR_ERR_CATALOG = 3,
    TWEP_WR_ERR_TEEP = 4,
    TWEP_WR_ERR_WASM_LOAD = 5,
    TWEP_WR_ERR_WASM_ABI = 6,
    TWEP_WR_ERR_WASM_RUNTIME = 7,
    TWEP_WR_ERR_SECURITY = 8,
    TWEP_WR_ERR_NO_MEMORY = 9,
    TWEP_WR_ERR_TEEP_NETWORK = 10,
    TWEP_WR_ERR_TEEP_ATTESTATION_UNSUPPORTED = 11,
    TWEP_WR_ERR_WASM_SIGNATURE = 12,
} twep_wr_status_t;

typedef struct {
    const char *state_dir;
    const char *resolver_mode; /* "mock", "attestam-insecure", or "attestam-verified" */
    const char *attestam_url;
    bool insecure_demo_mode;
    uint32_t default_timeout_ms;
    uint32_t max_request_bytes;
    uint32_t max_response_bytes;
} twep_wr_config_t;

typedef int32_t (*twep_wr_http_post_fn)(
    void *user_data,
    const uint8_t *url,
    size_t url_len,
    const uint8_t *body,
    size_t body_len,
    uint8_t *buf,
    size_t buf_cap,
    size_t *out_len);

typedef int32_t (*twep_wr_create_evidence_fn)(
    void *user_data,
    const uint8_t *challenge,
    size_t challenge_len,
    const uint8_t *agent_public_key_cose,
    size_t agent_public_key_cose_len,
    uint8_t *buf,
    size_t buf_cap,
    size_t *out_len);

typedef struct {
    twep_wr_http_post_fn http_post;
    twep_wr_create_evidence_fn create_evidence;
    void *user_data;
} twep_wr_host_io_t;
```

Both limit fields must be nonzero. `max_request_bytes` limits the combined byte lengths of `request_id`, `command`, and `app_input_cbor` passed to `twep_wr_execute`; an oversized request returns `TWEP_WR_ERR_INVALID_ARGUMENT`. `max_response_bytes` limits the owned response buffer returned across the C ABI; an oversized successful backend response is freed inside `twep-wr`, the output is cleared, and `TWEP_WR_ERR_WASM_RUNTIME` is returned. `TWEP_WR_ERR_SECURITY` is retained for Catalog hash mismatches and maps to `app.hash_mismatch`; `TWEP_WR_ERR_WASM_SIGNATURE` maps to `app.signature_unverified` when a Wasm module lacks a valid role-specific `twep.sig` code signature.

### Functions

```c
uint32_t twep_wr_get_abi_version(void);

twep_wr_status_t twep_wr_init(
    const twep_wr_config_t *config,
    twep_wr_context_t **out_ctx);

twep_wr_status_t twep_wr_execute(
    twep_wr_context_t *ctx,
    const twep_wr_normalized_request_t *request,
    twep_wr_owned_bytes_t *out_response_cbor);

twep_wr_status_t twep_wr_set_host_io(
    twep_wr_context_t *ctx,
    const twep_wr_host_io_t *host_io);

void twep_wr_free_bytes(twep_wr_owned_bytes_t bytes);

void twep_wr_shutdown(twep_wr_context_t *ctx);

const char *twep_wr_status_string(twep_wr_status_t status);
```

### Ownership

- On success, `twep_wr_init` returns a context through `out_ctx`.
- `twep_wr_shutdown` destroys the context.
- The C side allocates `out_response_cbor.ptr` returned by `twep_wr_execute`.
- The Go side must call `twep_wr_free_bytes` after use.
- `request->command`, `request->request_id`, and `request->app_input_cbor.ptr` passed by the Go side need only remain valid for the duration of the call. The C side copies them if necessary.
- Callbacks registered with `twep_wr_set_host_io` must remain valid until `twep_wr_shutdown`. HTTP communication is implemented by TEEP_Broker; the C side performs only policy checks and buffer copies. Normal sessions generate the development Generic EAT inside the Rust TEEP_Agent and do not install an REE Evidence callback. The `create_evidence` callback field remains in ABI v3 for diagnostic compatibility and, when unset, retains the existing `unsupported` behavior.

### ABI version

- The public C ABI version is `3`. Version 3 changed the input to `twep_wr_execute` from top-level request CBOR to `twep_wr_normalized_request_t`.
- In version 3, `internal/twepwr` owns final request normalization. The CLI and
  daemon decode and transport user input, `internal/twepwr.Context.Execute`
  produces the routing command, app-input CBOR, and effective timeout, and the
  C side does not scan top-level request CBOR.
- Increment the version for breaking ABI changes.

### Timeout policy

`0` for `request_timeout_ms` means unspecified, not unlimited. If the Catalog entry has `resource_limits.timeout_ms`, use it as both the app default and the upper limit; otherwise, use `twep_wr_config_t.default_timeout_ms`. A request-supplied timeout may shorten the effective timeout only when it is less than this upper limit.
- twepd checks the version at startup and fails to start if it does not match.

## 3. Trusted Wasm App ABI

### Exported Functions

Every Trusted Wasm App exports the following:

```c
uint32_t twep_app_abi_version(void);
uint32_t twep_app_alloc(uint32_t len);
void twep_app_free(uint32_t ptr, uint32_t len);
int32_t twep_app_main(uint32_t input_ptr, uint32_t input_len, uint32_t out_desc_ptr);
```

The host allocates an 8-byte region in Wasm memory and passes it as `out_desc_ptr`. The app writes the following values there:

```text
out_desc[0..4] = little-endian u32 output_ptr
out_desc[4..8] = little-endian u32 output_len
```

Return values:

| code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Invalid input CBOR |
| 2 | Invalid argument |
| 3 | Output generation failed |
| 4 | Insufficient memory |
| 5 | Unsupported command |
| 6 | Unsupported format |
| 7 | Resource limit exceeded |
| 127 | Panic or internal error |

### Input CBOR

The host passes the following to the app:

```cddl
app-input = {
  "schema_version": 1,
  "command": tstr,
  "argv": [* tstr],
  "inferred_params": [* typed-value],
  ? "stdin": bytes,
  ? "files": { * tstr => bytes },
  ? "metadata": { * tstr => any },
}
```

Top-level `app_input` supplied through `--cbor-file` or `--cbor-hex` is treated as a complete escape hatch from this `app-input` schema. The host passes the specified bytes directly to the Trusted Wasm App without schema validation or re-encoding.

`negaposi` supports JPEG only. The host reads the JPEG file specified by `-i`, places its JPEG bytes in `files["input"]`, and passes them to the app. The app returns JPEG bytes in `files["output"]`, and the host saves them to the `-o` path. This policy avoids granting file system privileges to general apps.

The `-o` destination may be any path writable with user privileges. Because twepd runs as a user service in the REE for every implemented profile, whether output can be saved is governed by normal user privileges and host-side path validation. A system-service deployment must define a separate output policy.

### Output CBOR

```cddl
app-output = {
  "schema_version": 1,
  "status": "ok" / "error",
  ? "stdout": bytes,
  ? "stderr": bytes,
  ? "result": any,
  ? "files": { * tstr => bytes },
  ? "metadata": { * tstr => any },
  ? "error": {
    "code": tstr,
    "message": tstr,
    ? "details": any,
  },
}
```

`stdout` is optional. A successful output containing only `files`, `result`, or `metadata` is also treated as a valid `app-output`.

## 4. TEEP_Agent Wasm ABI

TEEP_Agent also generally follows the Trusted Wasm App ABI. However, it uses the following commands for internal management.

TEEP_Agent Wasm is bundled as a repository build artifact. The Linux backend installs it in the state directory and verifies its demo code-signing identity. The TrustZone TA verifies the same role-specific demo signature before enabling TEEP Agent hostcalls or loading it into WAMR, then measures the exact loaded bytes and compares them with the protected identity fixture. Self-update through AttesTAM is outside the current protocol profile.

| command | Meaning |
| --- | --- |
| `resolve_app` | Resolve an app entry from a command name and install it if necessary |
| `refresh_catalog` | Retrieve or update the Catalog File from AttesTAM |
| `install_app` | Install the Trusted Wasm App with the specified component id |
| `list_apps` | Return the list of apps in the catalog |

### resolve_app Input

```cddl
resolve-app-input = {
  "schema_version": 1,
  "command": "resolve_app",
  "target_command": tstr,
  "resolver_mode": "mock" / "attestam-insecure" / "attestam-verified",
  "state_dir": tstr,
  "attestam_url": tstr,
}
```

### resolve_app Output

```cddl
resolve-app-output = {
  "schema_version": 1,
  "status": "ok" / "error",
  ? "app": {
    "command": tstr,
    "component_id": tstr,
    "version": tstr,
    "abi": "twep-app-v1",
    "wasm_file": tstr,
    "sha256": bytes,
    ? "accepted_formats": [* tstr],
    ? "resource_limits": resource-limits,
  },
  ? "error": twep-error,
}

resource-limits = {
  ? "stack_bytes": uint,
  ? "heap_bytes": uint,
  ? "timeout_ms": uint,
  ? "max_output_bytes": uint,
}
```

### Installed Component Metadata

The current TEEP_Agent accepts only supported App and Catalog component identifiers. A mismatched or unsupported component, including the AttesTAM demo `hello.txt`, is rejected before payload staging, Success, or installation. Successful supported installations record common metadata under `components/`; this directory name does not mean unsupported payloads are retained.

The Milestone 8.5 development fixture placed the additional text key `twep-app-v1-metadata` in the SUIT envelope. From Milestone 9 preparation onward, this metadata remains only for compatibility fixtures and is not used as grounds for storing a payload in the `apps/` cache or promoting it to a Catalog File entry. Promotion is based on the SUIT Component Identifier, SUIT payload digest, and a hash-verified integrated payload.

```cddl
twep-app-install-metadata = {
  "schema_version": 1,
  "command": tstr,
  "component_id": tstr,
  "version": tstr,
  "abi": "twep-app-v1",
  "wasm_file": tstr,
}
```

From Milestone 9 onward, the metadata key above is not used as the basis for classification. In the AttesTAM TEEP flow, `requested-tc-list[*].component-id` and `tc-list[*].system-component-id` in QueryResponse are the TAM-side manifest lookup keys, so twep app classification is also based on the SUIT Component Identifier.

An Evidence-bearing QueryResponse includes option 12 with the exact media type
`application/eat+cwt; eat_profile="urn:ietf:rfc:rfc9711"`. This selects the
Generic EAT verifier and permits AttesTAM to decode the Evidence nonce before
creating the Veraison challenge-response session. The Veraison session nonce,
the EAT nonce, and the outstanding TEEP QueryRequest challenge must represent
the same bytes; a successful EAR with an unrelated nonce is not sufficient for
TEEP Agent authentication.

```cddl
twep-app-component-id = [
  bstr .size 11, ; UTF-8 bytes for "twep-app-v1"
  command: bstr, ; UTF-8 bytes, [A-Za-z0-9_-]{1,32}
]
```

TEEP_Agent constructs this encoded component identifier from the target command and sends it as `requested-tc-list[*].component-id`. It may derive `command` and `<command>.wasm` and install the payload in the `apps/` cache only when the component identifier in the SUIT manifest within the Update matches the requested value and payload digest verification also succeeds. For backward compatibility, `attestam-insecure` also generates a development Catalog File from the installed app. In final verified mode, however, the Catalog File is not modified until the Catalog TC described below has been verified separately. A different identifier such as that of `hello.txt` is rejected before staging or installation.

In final verified mode, the Catalog File is not derived from or rewritten by an app TC; it is distributed as an independent Catalog TC. The following is the authoritative SUIT Component Identifier for the Catalog TC.

```cddl
twep-catalog-component-id = [
  bstr .size 15, ; UTF-8 bytes for "twep-catalog-v1"
  catalog-name: bstr, ; UTF-8 bytes, [A-Za-z0-9_-]{1,32}
]
```

The default Catalog File uses `catalog-name = "default"`, and its payload is canonical-CBOR `catalog.cbor`. TEEP_Agent may update the Catalog File only when COSE/SUIT verification, payload digest verification, sequence freshness, and trust anchor binding all succeed for this Catalog TC. Debug JSON, artifacts retrieved from the AttesTAM management API, and metadata from a `twep-app-v1` app TC are not grounds for updating the Catalog File in final verified mode.

```cddl
tc-artifact-install-metadata = {
  "schema_version": 1,
  "component_id_cbor": bytes,
  "sequence_number": uint,
  "payload_uri": tstr,
  "payload_file": tstr,
  "payload_sha256": bytes .size 32,
}
```

The `tc-artifact-install-metadata` schema name is retained for ABI compatibility even though current successful records describe supported App or Catalog installations.

Current storage locations after a successful supported installation:

| path | Contents |
| --- | --- |
| `apps/<command>.wasm` | Hash-verified App payload |
| `catalog/catalog.cbor` | Catalog payload, or insecure generated app Catalog |
| `components/install-metadata.cbor` | `tc-artifact-install-metadata` |
| `components/install-status.txt` | `install=ready\n` on success |

`payload_file` is a path relative to the state directory and identifies the installed App or Catalog payload.

### Development Trust Anchor Fixture

`teep-agent/dev-trust-anchors.cbor` is an observation fixture for the plain Linux development version, not final verified trust anchor storage. TEEP_Agent treats only the following minimal CBOR map as loadable.

```cddl
dev-trust-anchors = {
  "attestam_message_verification_keys": [* dev-trust-anchor-key],
  "suit_content_verification_keys": [* dev-trust-anchor-key],
}

dev-trust-anchor-key = {
  "kid": bytes,
  "purpose": "attestam-message-verification" / "suit-content-verification",
  "alg": "ESP256",
  "crv": "P-256",
  "x": bytes .size 32,
  "y": bytes .size 32,
}
```

If the top-level CBOR is malformed, TEEP_Agent records `trust-anchor-load=malformed` in `teep-agent/credential-status.txt`. If it is valid CBOR but does not match the schema above, it records `trust-anchor-load=unsupported`; if it matches, it records `trust-anchor-load=loaded-unbound`. `attestam_message_verification_keys[*].purpose` must be `attestam-message-verification`, and `suit_content_verification_keys[*].purpose` must be `suit-content-verification`. An entry with a mismatched purpose is treated as a schema mismatch. When the COSE `kid` extracted from `verified-input.cose` matches `attestam_message_verification_keys[*].kid`, this is observed as `attestam-message-verification-key-binding=observed-kid-entry-unbound`. This Linux fixture remains observation-only. The D045 TrustZone PoC uses the separate fixed protected fixture described below and retains `final-verified=false` because the keys are development material, not because a production lifecycle service is pending.

### Protected Credential Store

The protected credential store used by the D045 OP-TEE PoC is distinct from `dev-trust-anchors.cbor` above. Both OP-TEE profiles store the fixed public-key and policy fixtures in OP-TEE REE FS Secure Storage. `CFG_REE_FS=y` and `CFG_RPMB_FS=n` are permanent settings, and rollback attacks are outside this repository's threat model. Files in the REE state directory and file-backed sealed objects under `platform/linux` remain observation fixtures rather than protected OP-TEE state.

Initial population uses repository fixtures rather than a production credential service. Platform implementations are separated under `lib/twep-wr/src/platform/<backend>/`: Linux, shared ARM/RISC-V OP-TEE, and SGX hardware are implemented; Keystone remains a portability boundary. Linux objects are observation-only files, OP-TEE uses REE FS Secure Storage, and SGX uses Enclave-owned measurement-bound sealed records. Private slot names are not exposed through generic protected reads.

When the COSE `kid` extracted from the TAM-signed Update matches `attestam_message_verification_keys[*].kid` in `protected-credential-store.cbor` within TEE-protected storage, TEEP_Agent records `protected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound` in `teep-agent/credential-status.txt`. The fixed PoC fixture can satisfy the protocol and protected-state binding checks, but the development trust material means `final-verified=false` remains mandatory even after store freshness, revocation-state consistency, AttesTAM acceptance, and TEEP_Agent identity checks succeed.

The minimal schema is the following collection of credential entries organized by purpose. `schema_version` and `store_epoch` are used for store-wide compatibility and rollback detection. `entry_id` is a stable identifier unique within the store, `issuer_id` identifies the authority that issued or provisioned the credential, `kid` is the key id observed in COSE messages or SUIT authentication wrappers, and `not_before`/`not_after` define the validity period evaluated together with time inside the TEE or Verifier/RATS results.

`issuer_id` is not an arbitrary string. It is the SHA-256 digest bytes of the normalized CBOR/DER representation of the issuer public key or the root public key in the issuer certificate chain. In final verified mode, TEEP_Agent compares the store's `issuer_id` against the issuer allowlist sealed within the TEE. `issuer_key_id` is the issuer-side key rotation identifier and is used only to distinguish old and new issuer signing keys under the same `issuer_id`. A matching `kid` alone does not establish issuer binding.

```cddl
protected-credential-store = {
  "schema_version": 1,
  "store_epoch": uint,
  "attestam_message_verification_keys": [* protected-public-key-credential],
  "suit_content_verification_keys": [* protected-public-key-credential],
  ? "evidence_signing_keys": [* protected-signing-key-credential],
  ? "wasm_app_code_signature_verification_keys": [* protected-public-key-credential],
  ? "revoked_entry_ids": [* bytes],
}

protected-public-key-credential = {
  "entry_id": bytes,
  "purpose": "attestam-message-verification" /
             "suit-content-verification" /
             "wasm-app-code-signature-verification",
  "issuer_id": bytes,
  "kid": bytes,
  "alg": "ESP256",
  "crv": "P-256",
  "x": bytes .size 32,
  "y": bytes .size 32,
  "not_before": uint,
  "not_after": uint,
  "provisioning_epoch": uint,
  ? "issuer_key_id": bytes,
}

protected-signing-key-credential = {
  "entry_id": bytes,
  "purpose": "evidence-signing-cpu" / "evidence-signing-teep-agent",
  "issuer_id": bytes,
  "kid": bytes,
  "alg": "ES256",
  "crv": "P-256",
  "public_x": bytes .size 32,
  "public_y": bytes .size 32,
  "private_key_ref": bytes,
  "not_before": uint,
  "not_after": uint,
  "provisioning_epoch": uint,
  ? "issuer_key_id": bytes,
}

protected-issuer-allowlist = {
  "schema_version": 1,
  "issuer_ids": [1* bytes],
}

protected-store-freshness = {
  "schema_version": 1,
  "max_store_epoch": uint,
}

protected-revocation-state = {
  "schema_version": 1,
  "revoked_entry_ids": [* bytes],
}

protected-agent-identity = {
  "schema_version": 1,
  "platform_backend": "linux" / "trustzone" / "sgx" / "keystone",
  ? "runtime_location": text,
  ? "teep_agent_location": text,
  ? "measurement_sha256": bytes .size 32,
}

attestam-acceptance-result = {
  "schema_version": 2,
  "decision_source": "attestam-signed-update",
  "tam_response_verified": true,
  "challenge_response_bound": true,
  "acceptance_generation": uint,
}

teep-acceptance-state = {
  "schema_version": 1,
  "generation": uint,
  ? "last_consumed_query_response_sha256": bytes .size 32,
  "component_sequences": { * bytes => uint },
}
```

AttesTAM is the Relying Party for Veraison. TEEP_Agent does not receive, parse, or verify a Veraison Attestation Result or EAR. The TEEP_Agent-facing result records only AttesTAM acceptance communicated by a non-empty TAM-signed TEEP Update. The current implementation still uses the compatibility object name `verified-evidence-result.cbor`; new specification text refers to this as the AttesTAM acceptance result object until the persistence name is migrated. Legacy direct-result observations are not final-capable. NoContent and empty responses are not positive decision sources.

For the AttesTAM-specific path, acceptance is first communicated by the TAM-signed Update returned in the live challenge-response session after AttesTAM accepts the Evidence-bearing QueryResponse. No additional COSE extension is required. TEEP_Agent verifies the TAM signature and uses the D043 acceptance-generation state for one-time consumption and replay control. If AttesTAM later returns a component Update without a new Evidence challenge, TEEP_Agent accepts it only while that protected acceptance remains current and binds the new commit to the later session's own rolling tokens and exact preceding component-list QueryResponse.

One-time consumption follows D043. This tranche rejects an Update unless it contains exactly one non-empty, sequence-bearing SUIT manifest. `teep-acceptance-state.cbor` advances the consumed digest and that component sequence in one dedicated TA commit. Component keys are the raw encoded SUIT Component Identifier bytes. When both slots are absent and `protected-sequence-freshness.cbor` exists, valid canonical legacy state must be migrated once; only total absence starts empty generation 0. The logical record is then the sole freshness authority, while the old object remains a Linux dry-run and pre-D043 compatibility fixture. The logical record is at most 4096 bytes with at most 32 component entries. It uses two TA-internal slots, complete canonical parsing, and highest-valid-generation selection rather than the non-atomic generic overwrite command; an incomplete or structurally malformed peer is ignored when another valid slot exists, but a complete canonical unsupported-schema peer fails closed. An AttesTAM-derived positive result is current only when its mandatory `acceptance_generation` equals that object's generation. Pending transcript bytes and continuation ownership are bound to a real TA session context and are invalidated, not restored, after session close or restart. A transcript is at most 32 KiB, with at most two pending transcripts and 64 KiB total per TA instance. See `docs/ABI.md` for the authoritative schema and strict validation rules.

The minimum entries required for the Milestone 9 PoC protocol checks are `attestam_message_verification_keys` and `suit_content_verification_keys`. TEEP_Agent confirms the matching COSE `kid`, `purpose`, `issuer_id`, `alg`, fixed validity values, revocation-state consistency, and `store_epoch`/`provisioning_epoch` consistency. The purposes of `evidence_signing_keys` and `wasm_app_code_signature_verification_keys` are reserved, but no production private-key or credential-lifecycle service is required for Catalog/app promotion in this PoC.

Evaluate the current fixed fixture's revocation and freshness fields in the following order. These checks validate fixture consistency; they do not imply a runtime key-lifecycle service.

1. From the store envelope signature or sealed storage metadata, confirm that `store_epoch` is greater than the maximum epoch already stored inside the TEE. Reject an equal or lower value as a rollback.
2. For each purpose, consider only entries whose `entry_id` is not in `revoked_entry_ids` and for which the time inside the TEE or time derived from Verifier/RATS satisfies `not_before <= now <= not_after`.
3. If multiple entries have the same `purpose` and `kid`, use only the candidate with the greatest `provisioning_epoch`. Treat older candidates as rotated.
4. Require the `issuer_id` of the selected AttesTAM message verification key and SUIT content verification key to be present in the issuer allowlist inside the TEE. If necessary, also confirm that `issuer_key_id` is an active issuer key in the allowlist.
5. Persist the verified component only when these evaluation results and component sequence freshness in TEE-protected storage can be updated in the same transaction. Apply a `twep-app-v1` app TC to the `apps/` cache and a `twep-catalog-v1` Catalog TC to the Catalog File.

The PoC does not fetch or update revocation data at runtime. `revoked_entry_ids`, the issuer allowlist, and store freshness are fixed fixture inputs. A service that issues or maintains them is intentionally outside scope.

The plain Linux development version reads `teep-agent/protected-credential-store.cbor` from the REE state directory, but this is a schema observation fixture. TEEP_Agent writes `protected-credential-store-issuer-binding=unverified` to `teep-agent/credential-status.txt`. If store freshness or revocation state cannot be checked, it also writes `protected-credential-store-rotation-policy=unverified`, `protected-credential-store-revocation-status=unverified`, and `protected-credential-store-freshness=unverified`. If these values can only be matched on Linux, it writes them as `matched-unbound`. It maintains `trust-anchor-bound=false`. The AttesTAM acceptance result object is a dry-run observation artifact on Linux and is not a Veraison/EAR input to TEEP_Agent. On the TrustZone final path, AttesTAM acceptance can bind only when the TAM-signed Update is verified and D043 `acceptance_generation` is current in OP-TEE REE FS Secure Storage. When the `platform/linux` backend can read policy objects through its sealed-storage-like API, `platform-issuer-allowlist-load`, `platform-store-freshness-load`, `platform-revocation-state-load`, and `protected-agent-identity-load` are observed as `loaded-unbound`. When the backend/location specified by `protected-agent-identity.cbor` matches the platform status, it is observed as `agent-identity-binding=matched-unbound`. On the TrustZone final path, processing advances to `agent-identity-binding=bound` and `agent-identity-bound=true` only when `measurement_sha256` matches the SHA-256 of `teep-agent.wasm` loaded inside the TA.

This schema is the minimal public-key and policy-fixture contract used by OP-TEE and retained as a portability shape for future sealed-storage backends. The current fixed TEEP Agent private signer and the separate fixed development Evidence signer are compiled into the Rust PoC. Their private keys are publicly recoverable from the Wasm binary and are not protected credentials. `private_key_ref` is reserved for a future product that chooses to add a protected private-key service and is not required here.

### TC Artifact Inventory Command

`tc-inventory` is a management/debug command handled by twepd and is not run as a Trusted Wasm App. The CLI invokes it with the same IPC request format as a normal command.

```sh
twep-cli tc-inventory
twep-cli --output-format cbor tc-inventory > tc-inventory.cbor
```

On success, human-readable text is returned to `stdout` by default. With `--output-format cbor`, the following CBOR map is returned to `stdout`. If no TC artifact is installed, or if the SHA-256 of the stored payload does not match the metadata, a `tc.inventory` error is returned.

```cddl
tc-artifact-inventory = {
  "schema_version": 1,
  "component_id_cbor": bytes,
  "sequence_number": uint,
  "payload_uri": tstr,
  "payload_file": tstr,
  "payload_sha256": bytes .size 32,
  "payload_hash_status": "ok",
  "status": tstr,
  "size": uint,
}
```

## 5. Hostcall ABI

### Hostcalls for General Apps

General Trusted Wasm Apps have no hostcalls. If hostcalls become necessary, only logging is a candidate for a baseline allowlist. Management hostcalls for file/network/cose/evidence/random/time/log operations are restricted to TEEP_Agent. Any additional general-app hostcall requires a separate namespace explicitly allowlisted by Catalog policy.

The runtime for general apps is not given the TEEP_Agent capability. If a general app imports a TEEP_Agent hostcall from the legacy `env` namespace, it fails as an unresolved call. If a general app imports the `twep_teep_env` namespace, it is still rejected because the hostcall entry point requires the TEEP_Agent capability in exec_env user data.

```c
void twep_host_log(uint32_t level, uint32_t msg_ptr, uint32_t msg_len);
```

### Hostcalls for TEEP_Agent

File/http/cose/evidence/random/time/log hostcalls are provided only to TEEP_Agent. The import module name is `twep_teep_env`; the legacy `env` namespace is not used for TEEP_Agent hostcalls.

```c
void twep_host_log(uint32_t level, uint32_t msg_ptr, uint32_t msg_len);

int32_t twep_host_read_file(
    uint32_t path_ptr,
    uint32_t path_len,
    uint32_t buf_ptr,
    uint32_t buf_cap,
    uint32_t out_len_ptr);

int32_t twep_host_write_file(
    uint32_t path_ptr,
    uint32_t path_len,
    uint32_t data_ptr,
    uint32_t data_len);

int32_t twep_host_read_protected(
    uint32_t object_name_ptr,
    uint32_t object_name_len,
    uint32_t buf_ptr,
    uint32_t buf_cap,
    uint32_t out_len_ptr);

int32_t twep_host_http_post(
    uint32_t url_ptr,
    uint32_t url_len,
    uint32_t body_ptr,
    uint32_t body_len,
    uint32_t buf_ptr,
    uint32_t buf_cap,
    uint32_t out_len_ptr);

int32_t twep_host_create_evidence(
    uint32_t challenge_ptr,
    uint32_t challenge_len,
    uint32_t agent_public_key_cose_ptr,
    uint32_t agent_public_key_cose_len,
    uint32_t buf_ptr,
    uint32_t buf_cap,
    uint32_t out_len_ptr);

int32_t twep_host_platform_status(
    uint32_t buf_ptr,
    uint32_t buf_cap,
    uint32_t out_len_ptr);

int32_t twep_host_teep_agent_measurement_sha256(
    uint32_t buf_ptr,
    uint32_t buf_cap,
    uint32_t out_len_ptr);

int32_t twep_host_acceptance_generation(
    uint32_t generation_ptr);

int32_t twep_host_commit_acceptance(
    uint32_t query_response_sha256_ptr,
    uint32_t query_response_sha256_len,
    uint32_t component_id_ptr,
    uint32_t component_id_len,
    uint64_t sequence,
    uint64_t expected_generation,
    uint32_t new_generation_ptr);

int32_t twep_host_commit_catalog(
    uint32_t query_response_sha256_ptr,
    uint32_t query_response_sha256_len,
    uint32_t component_id_ptr,
    uint32_t component_id_len,
    uint64_t sequence,
    uint64_t expected_generation,
    uint32_t catalog_ptr,
    uint32_t catalog_len,
    uint32_t catalog_sha256_ptr,
    uint32_t catalog_sha256_len,
    uint32_t new_generation_ptr);

int32_t twep_host_commit_app(
    uint32_t query_response_sha256_ptr,
    uint32_t query_response_sha256_len,
    uint32_t component_id_ptr,
    uint32_t component_id_len,
    uint64_t sequence,
    uint64_t expected_generation,
    uint32_t wasm_ptr,
    uint32_t wasm_len,
    uint32_t wasm_sha256_ptr,
    uint32_t wasm_sha256_len,
    uint32_t new_generation_ptr);

int32_t twep_host_random(
    uint32_t buf_ptr,
    uint32_t buf_len);

uint64_t twep_host_unix_time_ms(void);
```

`twep_host_commit_catalog` is the only D047 protected Catalog publication
boundary. It is TEEP-Agent-only and TrustZone-only; generic file writes, the
REE broker, public Secure Storage commands, and general applications cannot
publish or select a protected Catalog slot.

`twep_host_commit_app` is the distinct M9.3 protected-app publication boundary.
Rust TEEP_Agent calls it only after the verified app TC's command and payload
digest exactly match the active protected Catalog entry. The TA stages one
inactive protected app record, reopens it, and makes it active through the
matching D043 component sequence. The record contains one command, its Wasm
bytes, and digest; two physical slots provide atomic replacement of that one
active app and are not a general app store. Generic file writes, public Secure
Storage commands, the REE broker, and general applications cannot publish or
select these slots.

Return values:

| code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | invalid argument |
| 2 | buffer too small. Write the required size to `out_len_ptr` |
| 3 | not found |
| 4 | permission denied |
| 5 | network error |
| 6 | timeout |
| 7 | internal error |
| 8 | unsupported |
| 9 | stale generation, replay, sequence conflict, or missing/mismatched transcript |

### AttesTAM Remote Attestation Evidence Contract

When AttesTAM detects an unregistered or unauthenticated TEEP Agent key, QueryRequest contains `options.challenge` and requests attestation through `data-item-requested`. TEEP_Agent uses this challenge to create `options.attestation-payload` in QueryResponse.

`attestation-payload` contains COSE_Sign1 bytes, and the COSE_Sign1 payload is EAT CBOR. The EAT contains at least the following:

```cddl
eat-evidence-payload = {
  10: bstr, ; eat_nonce, AttesTAM QueryRequest challenge
  8: {
    1: cose-key, ; cnf COSE_Key, TEEP Agent public key
    ? 3: bstr,   ; kid for the same TEEP Agent public key
  },
  ? 256: bstr, ; ueid, when platform can provide it
  * int => any,
}
```

AttesTAM sends `attestation-payload` to the Verifier and requires an `affirming` result. It then confirms that `eat_nonce` in the EAT matches the stored challenge and that the QueryResponse COSE signature can be verified with `cnf.key`. Therefore, `cnf.key` in the Evidence and the QueryResponse signing key must be the same key.

Evidence selection is runtime-specific while the Wasm ABI remains common. Linux and OP-TEE select Generic EAT, which the Rust TEEP_Agent constructs and signs with its fixed development ES256 key. SGX hardware selects the canonical Quote3 bundle and uses `create_evidence` to bind the challenge and Agent public key inside the Enclave. Fake QE behavior is test-only. Neither path advances `final-verified=true` with the repository credentials.

### AttesTAM Insecure Demo HTTP Payload

Even when `resolver.mode="attestam-insecure"` and `insecure_demo_mode=true`, HTTP payloads exchanged with AttesTAM follow the AttesTAM specification. To start the first session, TEEP_Agent sends an empty body to `POST /tam`, and TEEP_Broker adds the following headers.

- `Accept: application/teep+cbor`
- `Content-Type: application/teep+cbor`

The response body of `200 OK` is treated as a COSE-wrapped TEEP message (CBOR). `204 No Content` is treated as normal session termination. At this stage, TEEP_Agent extracts the COSE_Sign1 payload and determines whether the TEEP message type is QueryRequest. If QueryRequest contains a challenge, the Rust TEEP_Agent generates the development Generic EAT COSE_Sign1 directly and places it in the QueryResponse `attestation-payload`; this path does not call `twep_host_create_evidence`. For a QueryRequest with a token, TEEP_Agent creates a QueryResponse payload containing a `twep-app-v1` SUIT Component Identifier generated from the target command. In the development insecure demo, the development ESP256 signer inside the Rust TEEP_Agent signs the payload as COSE_Sign1 before the second POST. If the second POST returns a QueryRequest with a challenge, TEEP_Agent creates a QueryResponse containing the development Generic EAT Evidence, saves it to `teep-agent/last-attestation-query-response.cose`, and performs a third POST. The status of the challenge-response POST is saved to `teep-agent/last-attestation-query-response-status.txt`; if a body is present, it is saved to `teep-agent/last-attestation-query-response-body.cose`.

For an Update, TEEP_Agent may save raw, manifest, and payload diagnostics under
`teep-agent/update-*` before validating installation eligibility. A mismatched
or unsupported component returns `teep.protocol` before payload staging, the
Success POST, or installation, so `tmp/update-*`, `teep-agent/success*`, and
`components/install-*` remain absent for that rejected path. A matching,
supported App or Catalog component proceeds through payload digest verification,
staging under `tmp/`, a signed Success POST, and installation after NoContent.
An App is installed at `apps/<command>.wasm`; a Catalog component is installed
at `catalog/catalog.cbor`; common installation status and metadata are stored
under `components/`.

In `attestam-insecure`, installing a matching App also generates a development
Catalog File with source `attestam-insecure`. This is not the final trusted
authority path: final verified Catalog updates require a separately verified
`twep-catalog-v1` Catalog TC.

### Hostcall Security

- `read_file` and `write_file` permit access only beneath the state directory. On the host side, `write_file` writes to `<path>.tmp` and renames it within the same directory after closing it, making observation of completed files approximately atomic. In both OP-TEE profiles, generic writes to `teep-agent/verified-evidence-result.cbor` are rejected. The public REE Secure Storage PUT command likewise rejects the D043 and D047 logical and physical protected-object names. Only the dedicated acceptance and Catalog commits may update their slots. In `attestam-verified`, `read_file("catalog/catalog.cbor")` returns the D047 Catalog whose sequence matches current D043 state; it does not promote an REE-transient Catalog into the protected authority.
- `read_protected` accepts a stable object name, not a path. Linux maps allowed names to observation-only files, OP-TEE maps them to REE FS Secure Storage, and SGX maps a fixed allowlist to Enclave-validated sealed records. Generic reads and provisioning cannot access or publish the private acceptance, Catalog, or app slots. Keystone remains unsupported.
- `platform_status` is an observation hostcall dedicated to TEEP_Agent. It returns the platform backend name, sealed storage security, protected storage support, and file/random/time support as text lines. During an `attestam-verified` dry run, the result is saved to `teep-agent/platform-status.txt`.
- `twep_host_teep_agent_measurement_sha256` returns the SHA-256 of the TEEP_Agent Wasm bytes loaded by the current runtime. It is used only to bind `protected-agent-identity.cbor` to the runtime-loaded TEEP_Agent. A standalone TrustZone C diagnostic measurement is not a final identity binding.
- `twep_host_acceptance_generation`, `twep_host_commit_acceptance`, `twep_host_commit_catalog`, and `twep_host_commit_app` are TEEP_Agent-only authority boundaries in OP-TEE and SGX. Linux registers the symbols but returns `unsupported`.
- `http_post` permits only the AttesTAM URL allowed by the configuration.
- `attestam-verified` does not use a development Catalog File seed, the `TWEP_CATALOG_CBOR` override, mock app installation, or Catalog/app promotion during M9.1. Linux permits only verified dry-run observation artifacts. TrustZone may run the D045 live PoC acceptance-only path and commit D043 once, then returns `teep.verified_required` without app execution and with `final-verified=false`.
- During M9.2, TrustZone may accept only `[bstr("twep-catalog-v1"), bstr("default")]`, validate the D047 bounded canonical metadata-only Catalog, and publish it through the dedicated protected two-slot/D043 transaction. The Catalog payload is at most 64 KiB, the complete inbound response at most 128 KiB, and Success follows protected readback. Wasm app bytes remain separate TCs; M9.2 performs no app installation or execution and retains `final-verified=false`.
- During M9.3, the default TrustZone path first establishes that protected Catalog, then obtains the requested `[bstr("twep-app-v1"), bstr(command)]` TC in a later verified session. Rust authorizes the exact command and digest against the protected Catalog before the TA stores at most one active app of 128 KiB. After protected readback and D043 publication, the same request executes the protected bytes in TA-local WAMR. A later process can execute the protected app without contacting AttesTAM, provided Catalog resolution returns the same digest. The path retains fixed development credentials and `final-verified=false`.
- Under D046, the live AttesTAM exchange echoes the initial non-empty bounded QueryRequest token in the first signed QueryResponse, then accepts a newly issued non-empty bounded token in the immediate TAM-signed Update. These two tokens need not be byte-equal. The live session is bound by the ordered continuation and exact Evidence QueryResponse transcript consumed by D043. Fixed-input Linux dry-run fixtures continue to require byte equality with `teep-agent/verified-expected-token.bin`.
- The Rust TEEP_Agent uses its fixed development ES256 Evidence key in `attestam-insecure` with `insecure_demo_mode=true` and in the D045 `attestam-verified` PoC path. QueryResponse COSE_Sign1 generation is performed by the separate development ESP256 signer inside the Rust TEEP_Agent and is not delegated to the Go/REE TEEP_Broker or a C hostcall. `twepd --insecure-demo-agent-key alternate` is the explicit development option for exercising a QueryRequest challenge from a real AttesTAM in either path. The REE side only writes the alternate public COSE_Key to `teep-agent/dev-agent-public-key.cbor`. When this file exists, TEEP_Agent selects the alternate TEEP message signer and places the same public key in `cnf.key`; the Evidence signing key does not change. These signers are publicly embedded development material, require no credential-issuance service, and cannot establish `final-verified=true`. The Go/REE side remains IPC and exact-URL HTTP byte transport; COSE/TEEP/SUIT generation, validation, and acceptance decisions remain inside TEEP_Agent.
- The inactive Agent public-key and ESP256 signing compatibility imports are
  no longer part of the Wasm hostcall ABI. The Evidence creation and payload
  format hostcalls remain active. Public C ABI v3 is unchanged.
- An insecure flag is required to disable TLS verification.
- Enforce request and response size limits.

## 6. IDL Policy

For now, the CDDL-like schema in `docs/ABI.md` is authoritative. When an Interface Definition Language is introduced in the future, it must preserve `twep-app-v1` wire-format compatibility and support generation of Go/C/Rust type definitions.

## 7.CBOR canonicalization

- Canonical CBOR is recommended for internal CBOR exchanged among twep-cli, twepd, twep-wr, and TEEP_Agent.
- TWEP-specific CBOR such as `twep-app-v1`, IPC, and the Catalog retains string keys for now.
- TEEP protocol messages themselves follow the IETF specification.
- A future transition to integer labels through an IDL must not break `twep-app-v1` compatibility. If necessary, design it as `twep-app-v2`.

## 8. NegaPosi App I/O Policy

`negaposi` handles only JPEG, as follows.

1. twep-cli sends `-i image.jpg -o output.jpg` as argv.
2. twep-cli validates the input path and reads the JPEG file bytes.
3. During request normalization owned by `internal/twepwr`, the input JPEG bytes are placed in `files["input"]` of app-input and `metadata.input_mime="image/jpeg"` is added. The CLI and twepd supply the decoded request and file bytes but do not own the final normalized C-ABI request.
4. The app places the color-inverted JPEG bytes in `files["output"]` of app-output and returns `metadata.output_mime="image/jpeg"`.
5. twep-cli validates the output path and saves the file to the user-specified path using a temporary file followed by rename.
6. twep-cli emits a message indicating that the save completed.

PPM, PNG, and host-decoded RGB bytes are outside the current `negaposi` interface. Support for another format requires a compatible `negaposi.wasm` and interface update.

The output path may be any path writable with user privileges. General apps are not provided with file hostcalls; the host saves output to the user-specified path.
