# File and Module Layout

`wasm/teep-agent` is a single crate whose source is split across `src/*.rs`.
The public external ABI consists only of the four export functions in `lib.rs`;
the other functions are used for internal responsibility separation.

## Directory

```text
wasm/teep-agent/
├── Cargo.toml
├── README.md
├── docs/
│   ├── book.toml
│   └── src/
└── src/
    ├── lib.rs
    ├── host_io.rs
    ├── catalog.rs
    ├── session.rs
    ├── teep.rs
    ├── cose.rs
    ├── suit.rs
    ├── verified.rs
    ├── credential_management.rs
    ├── protected_credentials.rs
    ├── freshness.rs
    ├── evidence.rs
    └── cbor.rs
```

## Module List

| module | Main responsibility |
| --- | --- |
| `lib.rs` | `twep-app-v1` export, bump allocator, input dispatch, common CBOR error output |
| `host_io.rs` | Rust wrapper for `twep_teep_env` hostcalls |
| `catalog.rs` | Catalog File parsing, app entry validation, Wasm payload hash verification, `resolve_app` output generation |
| `session.rs` | `mock` / `attestam-insecure` resolution, TEEP session, Update staging/install/promotion |
| `teep.rs` | TEEP message type, token, QueryResponse payload, Update `manifest-list` extraction |
| `cose.rs` | COSE_Sign1 parsing, payload extraction, ESP256 verification adapter, development signing |
| `suit.rs` | SUIT envelope/manifest parsing, component-id classification, payload digest verification, Success report |
| `verified.rs` | `attestam-verified` dry-run, verification-step state, diagnostic artifact generation |
| `credential_management.rs` | Parsing credential/policy state and diagnosing trust-anchor binding |
| `protected_credentials.rs` | Detailed validation of the protected credential-store schema |
| `freshness.rs` | CBOR processing for reading and writing the sequence-freshness map |
| `evidence.rs` | QueryRequest challenge extraction, EAT evidence hostcall integration, evidence-result CBOR |
| `cbor.rs` | Small no_std CBOR reader/writer |

## Function Layout

### `lib.rs`

| Function | Role |
| --- | --- |
| `twep_app_abi_version()` | Return ABI version `1` |
| `twep_app_alloc(len)` | Allocate an output buffer from the fixed Wasm heap |
| `twep_app_free(ptr, len)` | Currently a no-op; the bump allocator does not free individually |
| `twep_app_main(input_ptr, input_len, out_desc_ptr)` | Read input CBOR and dispatch to probe / verified / resolve flow |
| `write_output(out_desc_ptr, output)` | Write ptr/len into the ABI 8-byte output descriptor |
| `sha256(input)` | SHA-256 helper for payload verification |
| `error_output(code, message)` | Build the common `app-output` error map as CBOR |

`twep_app_main` reads `target_command` as a required input and builds the CBOR
component id `[b"twep-app-v1", command]` with `suit::twep_app_component_id`.
If `resolver_mode` is `attestam-verified`, it enters
`verified::run_verified_dry_run`; otherwise it hands off to
`session::run_resolve_app`.

### `host_io.rs`

| Function | Corresponding hostcall | Role |
| --- | --- | --- |
| `log` | `twep_host_log` | TEEP Agent logging |
| `read_file_len` / `read_file` / `read_file_alloc` | `twep_host_read_file` | Fetch files from the state directory |
| `write_file` | `twep_host_write_file` | Request atomic writes in the state directory |
| `read_protected_len` / `read_protected` / `read_protected_alloc` | `twep_host_read_protected` | Read by protected object name |
| `http_post` | `twep_host_http_post` | POST to the configured AttesTAM URL |
| `create_evidence` | `twep_host_create_evidence` | Create EAT evidence from a challenge and agent public key |
| `platform_status` | `twep_host_platform_status` | Observe backend state |
| `teep_agent_measurement_sha256` | `twep_host_teep_agent_measurement_sha256` | Get the measurement of the loaded Wasm |
| `random` | `twep_host_random` | Random bytes for nonce/probe |
| `unix_time_ms` | `twep_host_unix_time_ms` | Time for session observation |

### `catalog.rs`

| Function | Role |
| --- | --- |
| `resolve_from_catalog` | Search the catalog entry, verify the app hash, and build the resolve output |
| `verify_app_file` | Read `apps/<wasm_file>` and confirm the SHA-256 matches |
| `catalog_entry` | Find the target command in the `apps` map inside `catalog.cbor` |
| `parse_app_entry` | Read `component_id`, `version`, `abi`, `wasm_file`, and `sha256` from an entry |
| `is_safe_wasm_basename` | Reject path traversal and absolute-path-like names |
| `resolve_output` | Generate the `resolve-app-output` CBOR |

### `session.rs`

| Function | Role |
| --- | --- |
| `run_resolve_app` | Entry point for catalog resolution as a whole. Try AttesTAM first if a URL exists |
| `run_attestam_session` | Initial POST, QueryRequest retrieval, QueryResponse send, response handling |
| `handle_session_response` | Handle Update or additional QueryRequest responses |
| `sign_query_response` | Build the QueryResponse payload and sign it with the development agent key |
| `build_query_response_payload` | Build QueryResponse payloads with or without attestation challenges |
| `process_update_payload` | Observe Update, validate candidate, stage, and POST Success |
| `write_update_candidate_observation_or_127` | Write Update / SUIT information to diagnostic artifacts |
| `stage_update_or_127` | Stage payload and metadata under `tmp/` |
| `post_success` | Build a Success with SUIT report and POST it to AttesTAM |
| `install_payload` | Write payload to the final path after Success completes |
| `write_promoted_app_catalog` | Generate a development Catalog for insecure app TCs |
| `promoted_app_catalog` | Build the minimal Catalog CBOR for `source=attestam-insecure` |
| `dev_sequence_is_fresh` | Check sequence freshness using the protected or development freshness map |
| `write_dev_sequence_freshness` | Update the development freshness map after NoContent |
| `resolve_catalog` | Read `catalog/catalog.cbor` and pass it to `catalog::resolve_from_catalog` |

### `teep.rs`

| Function | Role |
| --- | --- |
| `teep_message_type` | Read the message type from the head of a TEEP CBOR array |
| `update_manifest_list` | Read the manifest-list from TEEP option `9` |
| `query_response_payload` | Build a token-bearing QueryResponse payload |
| `query_response_payload_with_attestation` | Build a QueryResponse payload with evidence |
| `teep_message_token` | Read TEEP option `19` token |

### `suit.rs`

| Function | Role |
| --- | --- |
| `teep_update_candidate` | Build an Update candidate and confirm that it matches the requested component id |
| `teep_update_candidate_any` | Extract an Update candidate without requiring component match |
| `suit_manifest_info` | Read the manifest, auth block, and integrated payload from a SUIT envelope |
| `parse_suit_manifest` | Read sequence, common, and payload-fetch information from the SUIT manifest body |
| `parse_suit_common` | Read the component id and payload digest |
| `installed_payload_path` | Decide the install path by component kind |
| `twep_app_component_id` | Build a `twep-app-v1` SUIT Component Identifier from the command |
| `success_response_payload` | Build the TEEP Success payload |
| `update_metadata` | Build install/staging metadata CBOR |

### `cose.rs`

| Function | Role |
| --- | --- |
| `outer_teep_cose_sign1_payload_unverified` | Extract the COSE_Sign1 payload without verification |
| `outer_teep_cose_sign1_key_id` | Read the COSE protected/unprotected kid |
| `outer_teep_cose_sign1_payload_verified_with` | Verify the ESP256 signature with a verifier callback |
| `cose_sign1_detached_payload_verified_with` | Verify a detached-payload signature |
| `sign_demo_agent_esp256_cose_sign1` | Build a COSE_Sign1 with the development agent key |

`attestam-insecure` signing happens inside this crate. Do not move the COSE
signing boundary into the Go broker or the C hostcall layer.
