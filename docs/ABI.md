# ABI.md: Trusted Wasm App ABI Specification

The OP-TEE profile split does not change public C ABI v3, TA command IDs, CBOR
schemas, or protected object names. New deployments report backend
`arm-optee` or `riscv-optee` and location `optee-ta`. The legacy pair
`trustzone`/`trustzone-ta` is migration-only and must never be mixed with new
profile values.

This file defines the Trusted Wasm App ABI for twep. An ABI change must update
this file, `docs/Interface.md`, and `Spec.md` together.

## KISS / DRY

Follow KISS and DRY when updating the ABI. This document is the source of truth for the wire format, error codes, hostcalls, and schemas. Keep duplicate definitions in Go, C, and Rust synchronized through generation, shared tables, or explicit references. Generalize only when multiple ABI versions or multiple backends actually require it.

## Basic Policy

- ABI name: `twep-app-v1`
- Input: CBOR byte sequence
- Output: CBOR byte sequence
- Implementation language: Rust `no_std` + `alloc`
- Runtime: Prefer `wasm32-unknown-unknown` on WAMR
- Future policy: Make it possible to define this ABI with an Interface Definition Language. For now, the CDDL-like schemas and exported function specifications are authoritative.

The TEEP_Agent Wasm Application and general Trusted Wasm Applications must be distributed and executed as the same platform-backend-independent Wasm binaries. Do not produce separate Wasm artifacts for platform backends. Accommodate platform differences in hostcall implementations, private TEE commands, protected storage, and runtime resource policies. The same Rust TEEP_Agent binary generates Generic EAT on the currently supported Linux and OP-TEE paths.

## IDL Policy

The IDL is not finalized at this time. A future IDL must satisfy the following conditions:

- Preserve compatibility with the `twep-app-v1` wire format.
- If a breaking ABI change is required, increment the version to `twep-app-v2`.
- Support generation of type definitions for Go, C/C++, and Rust/Wasm.
- Allow the argument schema for each command to be referenced from the Catalog File.
- Keep it distinct from the CBOR/COSE messages of the TEEP protocol itself.

## Schema-to-implementation navigation

| CBOR schema or envelope | Go | C public/backend | Rust/Wasm | OP-TEE TA |
| --- | --- | --- | --- | --- |
| Public request/response | `internal/cborcodec.Request`, `Response`, `EncodeRequest`, `DecodeRequest`, `EncodeResponse`, `DecodeResponse` | `twep_wr_execute`, `twep_wr_normalized_request_t` | general app `twep_app_main` input/output helpers | final-response transport in `TA_TWEP_WR_CMD_EXECUTE` |
| Common app input/output | `internal/cborcodec.BuildAppInput`, `DecodeAppOutput` | WAMR invocation and output mapping in `lib/twep-wr` | `cbor`, app-specific crates, `write_output` | TA-local general-app WAMR invocation |
| TEEP Agent resolve input/output | `internal/twepwr.NormalizeRequest` and resolver configuration | TEEP Agent invocation in the selected platform backend | `twep_app_main`, `session::run_resolve_app`, `verified` | TA-local TEEP Agent WAMR invocation |
| OP-TEE INIT/EXECUTE/RESUME envelopes | OP-TEE broker callbacks through `internal/twepwr` | `twep_optee_make_execute_envelope` and host-I/O result encoding | opaque normalized input and continuation result consumption | `parse_production_envelope`, `TA_TWEP_WR_CMD_INIT`, `TA_TWEP_WR_CMD_EXECUTE`, `TA_TWEP_WR_CMD_RESUME_HOST_IO` |
| D043 acceptance state | no authoritative Go writer | dedicated acceptance hostcalls only | `VerificationState`, live acceptance commit | `acceptance_state.c`, dedicated commit command |
| D047 protected Catalog | no authoritative Go writer | `twep_host_commit_catalog` transport | Catalog validation and live Catalog commit | protected Catalog slots plus D043 activation |

Canonical cross-language byte vectors and their expected fields live in
`testdata/abi/`. They are compatibility fixtures, not a second schema source.

## Exported Functions

Every Trusted Wasm App exports the following functions:

```c
uint32_t twep_app_abi_version(void);
uint32_t twep_app_alloc(uint32_t len);
void twep_app_free(uint32_t ptr, uint32_t len);
int32_t twep_app_main(uint32_t input_ptr, uint32_t input_len, uint32_t out_desc_ptr);
```

`twep_app_abi_version()` returns `1`.

`out_desc_ptr` points to an 8-byte region allocated by the host in Wasm memory. On success, the app writes the following:

```text
out_desc[0..4] = little-endian u32 output_ptr
out_desc[4..8] = little-endian u32 output_len
```

The host copies the CBOR output from `output_ptr` and `output_len`, then calls the app's `twep_app_free(output_ptr, output_len)`.

## Return Values

| code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Invalid input CBOR |
| 2 | Invalid arguments |
| 3 | Output generation failure |
| 4 | Insufficient memory |
| 5 | Unsupported command |
| 6 | Unsupported format |
| 7 | Resource limit exceeded |
| 127 | Panic or internal error |

When mapping these values to a host response, map `3` to `app.output_generation`, `7` to `app.resource_limit`, and `127` to `app.internal`. For a nonzero return code, include `return_code`, `command`, and `wasm_file` in `error.details`.

## Common Input Schema

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

typed-value =
  { "type": "int", "value": int } /
  { "type": "uint", "value": uint } /
  { "type": "text", "value": tstr } /
  { "type": "bytes", "value": bytes } /
  { "type": "bool", "value": bool }
```

When `app_input` is specified in the top-level request, the host treats those bytes as a complete escape hatch from this schema and passes them to the app without re-encoding. The host constructs this `app-input` map only when `app_input` is not specified.

## Wasm code-signing package format

Every executable Wasm module loaded by the plain Linux backend carries a final
custom section named `twep.sig`. Both OP-TEE profiles require the same section
on the privileged TEEP_Agent Wasm. WAMR ignores the section at execution time,
but the Linux `twep-wr` or the OP-TEE TA verifies it before loading the
module. The signature binds the exact Wasm bytes before the `twep.sig` section;
catalog hashes and SUIT payload digests are computed over the complete signed
Wasm file.

The section payload is:

```cddl
twep-sig-section = custom-section(
  name: "twep.sig",
  contents: {
    "alg": "ESP256",
    "kid": bytes,
    "sig": bytes .size 64, ; raw P-256 ECDSA r || s
    "role": "teep-agent" / "app",
  }
)
```

The `twep.sig` section must be the last section of the module. A `twep.sig`
section in any earlier position, a missing section, malformed CBOR, an
unsupported `alg`, an unexpected `role`, or a signature mismatch is rejected.
The ESP256 signature operation receives the Wasm prefix bytes as the message;
the ECDSA implementation applies SHA-256 internally. The `role` is a packaging
consistency check, but authority comes from verifying with the expected
role-specific public key.

The PoC build signs `build/teep-agent.wasm` with the insecure demo TEEP Agent
code-signing key and signs general app artifacts with the insecure demo app
code-signing key. Both the Linux runtime and TrustZone TA embed only the demo
TEEP Agent public key and grant TEEP Agent hostcall capability only after the
`role="teep-agent"` signature verifies. In TrustZone this check occurs before
WAMR initialization, native-hostcall registration, and `wasm_runtime_load()`;
failure returns `TEE_ERROR_SECURITY`. General app execution first checks the
Catalog File SHA-256 and then verifies the app code-signing signature through
the TEEP_Agent flow. A hash mismatch continues to map to `app.hash_mismatch`;
a code-signature failure maps to `app.signature_unverified` through
`TWEP_WR_ERR_WASM_SIGNATURE`. This change adds no public C ABI or CBOR schema.

## Common Output Schema

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

## helloworld convention

Input:

```cddl
helloworld-input = app-input ; command == "helloworld"
```

Output:

```cddl
helloworld-output = {
  "schema_version": 1,
  "status": "ok",
  "stdout": bytes, ; "Hello, World!!
" or "Hello, World!!"
}
```

`twep-cli` displays the stdout bytes to the user.

## calcadd convention

`calcadd` accepts any number of integers and returns their sum.

Input:

```cddl
calcadd-input = app-input ; command == "calcadd"
```

Values in `inferred_params` whose `type` is `"int"` or `"uint"` are included in the sum. A Catalog `args_schema` or an IDL-derived schema may define stricter argument handling in a later ABI version.

Output:

```cddl
calcadd-output = {
  "schema_version": 1,
  "status": "ok",
  "stdout": bytes, ; decimal text
  "result": { "sum": int },
}
```

## negaposi convention

`negaposi` accepts JPEG only. PPM, PNG, and host-decoded RGB bytes are not part of this ABI.

In the normal CLI path, `twep-cli` validates the input path with user privileges before placing the JPEG bytes in `files.input`. Validation requires no NUL characters, a `.jpg` or `.jpeg` extension, a regular file no larger than 16 MiB, and JPEG magic bytes. `output_path_hint` is a hint to the Wasm app; it does not grant twepd/twep-wr or a general app runtime permission to write to an arbitrary path. The CLI saves only `files.output` from the app output to the user-specified path using an atomic rename. The current policy permits overwriting an existing file.

Input:

```cddl
negaposi-input = {
  "schema_version": 1,
  "command": "negaposi",
  "argv": [* tstr],
  "inferred_params": [* typed-value],
  "files": {
    "input": bytes, ; JPEG file bytes
  },
  "metadata": {
    "input_mime": "image/jpeg",
    ? "input_path_hint": tstr,
    ? "output_path_hint": tstr,
  },
}
```

Output:

```cddl
negaposi-output = {
  "schema_version": 1,
  "status": "ok",
  "files": {
    "output": bytes, ; JPEG file bytes
  },
  "metadata": {
    "output_mime": "image/jpeg",
  },
  ? "stdout": bytes,
}
```

Requirements:

- Return `status="error"` if the input bytes cannot be decoded as JPEG.
- Return the output as JPEG bytes.
- Support for formats other than JPEG will be added in a future `negaposi.wasm` update.
- The host validates input and output paths and performs file reads and writes. Do not provide file hostcalls to general apps.

## TEEP_Agent ABI

TEEP_Agent also uses the exported functions of `twep-app-v1`. However, it accepts administrative commands and can use dedicated hostcalls.

| command | Meaning |
| --- | --- |
| `resolve_app` | Resolve an app entry from a command name and install it if necessary |
| `refresh_catalog` | Retrieve or update the Catalog File from AttesTAM |
| `install_app` | Install the Trusted Wasm App with the specified component ID |
| `list_apps` | Return the list of apps in the Catalog File |

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

### TC artifact install metadata

When a Trusted Component distributed through a TEEP Update is not a `twep-app-v1` Wasm app, such as the AttesTAM demo `hello.txt`, TEEP_Agent does not promote it to the Catalog File or the `apps/` cache. It stores the component under `components/` as a TC artifact.

The insecure Milestone 8.5 fixture used the additional SUIT envelope text key `twep-app-v1-metadata` as a development bridge. Starting with the Milestone 9 preparation, this metadata remains only for fixture compatibility and is not used as the basis for app classification or Catalog promotion.

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

### Verified mode SUIT Component Identifier

Neither the development promotion path in `attestam-insecure` nor `attestam-verified` uses `twep-app-v1-metadata` for trust decisions. The authoritative classification key in AttesTAM/TEEP/SUIT is the encoded SUIT Component Identifier used in `requested-tc-list[*].component-id` of the TEEP QueryResponse and in `trusted_component_id` of the SUIT manifest repository.

The following CBOR bytes are authoritative for the SUIT Component Identifier of a twep app:

```cddl
twep-app-component-id = [
  bstr .size 11, ; UTF-8 bytes for "twep-app-v1"
  command: bstr, ; UTF-8 bytes, [A-Za-z0-9_-]{1,32}
]
```

For example, `remotehello` corresponds to the following diagnostic notation:

```text
[ h'747765702d6170702d7631', h'72656d6f746568656c6c6f' ]
```

TEEP_Agent recovers `command` from this identifier and derives the Catalog File's `wasm_file` as `<command>.wasm`. Only the raw encoded component identifier bytes, SUIT manifest sequence number, SUIT payload digest, and hash-verified integrated payload form the basis for app installation. A Trusted Component whose identifier does not match this form is treated as a TC artifact and is not executed as a general Trusted Wasm App.

The following CBOR bytes are authoritative for the Catalog File's SUIT Component Identifier, which identifies a Trusted Component distinct from an app TC:

```cddl
twep-catalog-component-id = [
  bstr .size 15, ; UTF-8 bytes for "twep-catalog-v1"
  catalog-name: bstr, ; UTF-8 bytes, [A-Za-z0-9_-]{1,32}
]
```

The default Catalog File uses `catalog-name = "default"`, and its payload is canonical-CBOR `catalog.cbor`. The debug `catalog.dev.json` and responses from the AttesTAM management API are not a basis for updating the Catalog File in final verified mode unless they are verified as a SUIT TC carrying this identifier. A `twep-app-v1` app TC is installed into the `apps/` cache and is not an authoritative basis for rewriting the Catalog File.

Under D047, the M9.2 verified PoC accepts only `[bstr("twep-catalog-v1"), bstr("default")]`. The Catalog contains metadata and references such as `wasm_file` and `sha256`; it does not embed Wasm application bytes. The canonical Catalog payload is at most 65536 bytes, contains at most 256 app entries, and has at most 16 nested CBOR levels. Its authoritative decoder rejects duplicate keys, trailing bytes, indefinite-length items, a schema version other than 1, invalid required fields, an ABI other than `twep-app-v1`, unsafe Wasm basenames, and non-canonical encoding. The complete inbound COSE/TEEP/SUIT response carrying it is at most 131072 bytes. These are independent of the D043 outbound pending-QueryResponse limits.

The following schema is authoritative for metadata stored after a supported App or Catalog Update completes. Mismatched or unsupported components are rejected before staging, Success, or installation.

```cddl
tc-artifact-install-metadata = {
  "schema_version": 1,
  "component_id_cbor": bytes, ; SUIT component identifier CBOR bytes
  "sequence_number": uint,
  "payload_uri": tstr,
  "payload_file": tstr,      ; path relative to the state directory
  "payload_sha256": bytes .size 32,
}
```

The `tc-artifact-install-metadata` schema name is retained for ABI compatibility even though current successful records describe supported App or Catalog installations.

Storage locations after a successful supported installation:

| path | Contents |
| --- | --- |
| `apps/<command>.wasm` | Hash-verified `twep-app-v1` payload |
| `catalog/catalog.cbor` | Verified Catalog payload, or insecure generated app Catalog |
| `components/install-metadata.cbor` | `tc-artifact-install-metadata` |
| `components/install-status.txt` | Text; `install=ready\n` on success |

`payload_file` is a path relative to the state directory and must not contain an absolute path, `..`, or path traversal. In `attestam-insecure`, installing a matching `twep-app-v1` payload also generates a development Catalog File. In final verified mode, only a separately verified `twep-catalog-v1` Catalog TC is authoritative for Catalog updates.

### D047 protected Catalog state

The logical protected Catalog object is `twep-catalog-state.cbor`; only the internal physical slots `twep-catalog-state.0.cbor` and `twep-catalog-state.1.cbor` are stored. The logical record is:

```cddl
protected-catalog-record = {
  "schema_version": 1,
  "acceptance_generation": uint,
  "component_id_cbor": bytes .cbor twep-catalog-component-id,
  "sequence_number": uint,
  "catalog_sha256": bytes .size 32,
  "catalog_cbor": bytes .size (1..65536),
}
```

The record and embedded Catalog must be canonical CBOR. The record's component id must be the exact default Catalog id, its digest must equal SHA-256 of `catalog_cbor`, and its sequence must be nonzero. A record is active only when its `sequence_number` equals the value for its raw `component_id_cbor` key in the current D043 `component_sequences`. A later D043 commit for another component may advance the acceptance generation without hiding the Catalog. If two structurally valid slots match the current Catalog sequence but disagree in any field, loading fails closed; identical matching records select the one with the higher `acceptance_generation`. An incomplete or structurally malformed peer may be ignored when the other slot is valid, while a complete canonical unsupported-schema peer fails closed.

The Catalog commit writes, closes, reopens, and verifies the inactive Catalog slot before advancing D043. Until D043 contains the candidate sequence, that candidate is not visible and the prior matching Catalog remains authoritative. After publication, `read_file("catalog/catalog.cbor")` in the TrustZone TEEP_Agent/runtime boundary returns the active protected `catalog_cbor`; it must not prefer an REE-transient Catalog over a valid protected Catalog in `attestam-verified`.

## Protected credential store ABI

The credential store object used in final verified mode is named `protected-credential-store.cbor`. This object is read through the TEEP_Agent-only `read_protected` hostcall. The related platform policy objects are named `protected-issuer-allowlist.cbor`, `protected-sequence-freshness.cbor`, `protected-store-freshness.cbor`, `protected-revocation-state.cbor`, and `protected-agent-identity.cbor`. AttesTAM is the Relying Party for Veraison and keeps the Verifier result internal; TEEP_Agent does not receive or verify Veraison Attestation Results. The TEEP_Agent-facing acceptance object records only AttesTAM acceptance proven by a TAM-signed Update returned in the live Evidence challenge-response session. The current implementation still uses the compatibility object name `verified-evidence-result.cbor`; new specification text refers to it as the AttesTAM acceptance result object until the persistence name is migrated. D043 adds the logical `teep-acceptance-state.cbor` record, stored by its dedicated TA command in two internal crash-recovery slots. `protected-sequence-freshness.cbor` is a CBOR map whose keys are raw encoded SUIT Component Identifier bytes and whose values are the last accepted SUIT sequence numbers as uint values; it is only an initial migration source and compatibility fixture after D043. Both OP-TEE profiles use OP-TEE REE FS Secure Storage as their authoritative object storage. The plain Linux development version can observe the same schema as the `teep-agent/protected-credential-store.cbor` fixture, but neither files in the REE state directory nor file-backed sealed objects under `platform/linux` are authoritative bases for trust anchors.

The following minimal CBOR schemas are authoritative. As with the current `twep-app-v1` family of CBOR structures, map keys are text strings, and values are encoded as canonical CBOR.

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
  "platform_backend": "linux" / "arm-optee" / "riscv-optee" / "trustzone" / "sgx" / "keystone",
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

The final verified path has no direct-Verifier result consumed by TEEP_Agent. Veraison's Relying Party is AttesTAM, and AttesTAM decides whether the Evidence makes the TEEP Agent acceptable. TEEP_Agent first observes that decision when AttesTAM returns a non-empty TAM-signed TEEP Update that TEEP_Agent can verify against its AttesTAM trust anchor in the live session following the Evidence-bearing QueryResponse. A later component session may receive a direct signed Update after its component-list QueryResponse, without another Evidence challenge, only while that protected AttesTAM-acceptance generation remains current. The legacy schema version 1 and `direct-verifier` source are retained only as dry-run compatibility observations and are not final-capable. HTTP `204 No Content` is never a valid positive source.

For `attestam-signed-update`, `challenge_response_bound=true` means the initial TAM-signed Update was accepted after the Evidence-bearing QueryResponse and passed the TEEP_Agent's TAM signature, D046 rolling-token, Update, SUIT, and D043 acceptance checks. In the live protocol, the non-empty bounded token echoed from the initial QueryRequest and the non-empty bounded token in the signed Update have different protocol roles and need not be byte-equal. The initial binding comes from the ordered continuation and the exact session-owned Evidence QueryResponse consumed by D043. A later direct Update is accepted only with a current protected `attestam-signed-update` result, fresh non-empty bounded rolling tokens for that session, and a D043 commit bound to that session's exact immediately preceding component-list QueryResponse. The Linux fixed-input dry-run retains byte equality with `teep-agent/verified-expected-token.bin`. No additional COSE extension is required; the implementation follows the current AttesTAM server behavior.

Under D043, `acceptance_generation` is mandatory for `decision_source="attestam-signed-update"` and must equal `teep-acceptance-state.generation` in the current protected store. This tranche accepts exactly one non-empty, sequence-bearing SUIT manifest per Update. The acceptance state is the single logical transaction boundary for the consumed QueryResponse digest and that component sequence. Its `component_sequences` keys use the same raw encoded SUIT Component Identifier bytes as `protected-sequence-freshness.cbor`. The D043 final path migrates a valid initial sequence map once and thereafter treats the two-slot logical acceptance record as authoritative; it must not independently update or consult `protected-sequence-freshness.cbor` for acceptance. Equality with the last digest is rejected, while an older A-B-A digest replay is rejected by the mandatory strict component-sequence check. Zero or multiple manifests, a missing or mismatched generation, an equal or lower component sequence, or a positive result written before the acceptance commit fails closed.

The acceptance record uses canonical CBOR, rejects duplicate map or component keys, is limited to 4096 bytes and 32 component entries, and uses generations 1 through `UINT64_MAX`. When both slots are absent, an existing valid canonical legacy sequence map must be imported as generation 0; only absence of both slots and the legacy object starts with an empty generation 0. The first commit writes generation 1. At least one valid slot is sufficient: an incomplete or structurally malformed peer is ignored and the highest-generation valid slot is selected. A complete canonical peer with an unsupported schema version fails closed because falling back could roll replay state back. If slots exist but none is valid, or two highest-generation valid slots differ, loading fails closed. Overflow and invalid legacy state fail closed. Once a valid slot exists, the legacy object is no longer an authority and is not consulted, even if its bytes diverge from the slot. The generic protected-object write ABI must not write this record.

TA-owned pending QueryResponse transcripts are limited to 32 KiB each, two concurrent pending transcripts, and 64 KiB in aggregate. A limit violation returns a resource-limit error and does not establish a new transcript; if the session was replacing an existing pending transcript, that old transcript is invalidated. These limits are independent of the normal-world 16 MiB request limit.

`issuer_id` is the SHA-256 digest bytes of the normalized CBOR/DER representation of the issuer public key or the root public key of the issuer certificate chain. The D045 PoC fixture must keep `kid`, `purpose`, `issuer_id`, `alg`, the validity period, `revoked_entry_ids`, `store_epoch`, and `provisioning_epoch` internally consistent and bind them to the issuer allowlist and freshness state inside the TEE. The complete fixed fixture is sufficient for this repository; no production issuance, enrollment, rotation, revocation, recovery, or credential service is required. Because the fixture contains development trust material, retain `final-verified=false` even when all protocol checks succeed. In the current `platform/linux` backend, even when these policy objects can be read, they are observed only as `loaded-unbound` and are not used for authoritative binding.

In either OP-TEE profile, proceed to AttesTAM-acceptance binding only when the acceptance result is loaded from OP-TEE REE FS Secure Storage, its TAM-signed Update has been verified in the live challenge-response session, and its `acceptance_generation` equals the current D043 acceptance state generation. The mere presence of `measurement_sha256` in `protected-agent-identity.cbor` is insufficient. It can be the basis for `agent-identity-bound=true` only when it matches byte-for-byte the SHA-256 of the `teep-agent.wasm` bytes loaded inside the TA. The Linux backend remains observation-only even when it can observe the same schema.

## Hostcall policy

### General Trusted Wasm Apps

General Trusted Wasm Apps receive no hostcalls. A future ABI may permit logging only through a separate namespace and an explicit Catalog allowlist.

```c
void twep_host_log(uint32_t level, uint32_t msg_ptr, uint32_t msg_len);
```

### TEEP_Agent-Only Hostcalls

Provide the following hostcalls to TEEP_Agent. The import module name is `twep_teep_env`; these hostcalls are not provided through the legacy `env` module. Every hostcall entry point requires the TEEP_Agent capability in the exec_env user data. Do not set this capability in a general Trusted Wasm App runtime.

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

Hostcall constraints:

- Permit file reads and writes only under the state directory. On the host side, `write_file` writes to `<path>.tmp` and renames it within the same directory after closing it. This appears as a normal write to TEEP_Agent, but an installed payload or Catalog File must become observable only after the atomic rename. In both OP-TEE profiles, generic writes to the compatibility path `teep-agent/verified-evidence-result.cbor` are rejected. The public REE Secure Storage PUT command also rejects `verified-evidence-result.cbor`, the logical and physical D043 names, and the logical and physical D047 Catalog names. Only the dedicated TEEP_Agent hostcalls may update those slots; `twep_host_commit_catalog` couples Catalog publication to the same D043 authority rather than creating a second freshness authority.
- Protected reads are for platform protected storage, and `object_name` is a stable object name rather than a path. Permit only `[A-Za-z0-9_.-]` in object names. The Linux backend maps an object to `$STATE/platform/linux/sealed/<object_name>`, but marks it as `observation-only` in internal platform metadata and does not use it for security claims in final verified mode. Both OP-TEE profiles map it to OP-TEE REE FS Secure Storage and treat it as `tee-ree-fs-secure-storage` in internal platform metadata. Because this repository's threat model does not include rollback attacks, `sealed-storage-rollback-protected=false` is not a blocker for the PoC protocol path. Unsupported backends return unsupported until they map it to platform-specific protected storage. No protected-storage write hostcall is currently provided to TEEP_Agent. For this PoC, the fixture generator and legacy TrustZone-named smoke provisioning commands inject the fixed credential and freshness objects, excluding the D043-reserved names above; a production provisioning or credential service is outside scope.
- Platform status is for observation and returns the backend name and sealed-storage security as text lines. An `attestam-verified` dry run stores it in `teep-agent/platform-status.txt`.
- Permit HTTP POST only to the AttesTAM URL specified in the configuration.
- COSE_Sign1 signing is performed by the Rust TEEP_Agent inside the TEE. For `attestam-insecure` and the D045 `attestam-verified` PoC protocol path, use only the fixed development ESP256 signer inside TEEP_Agent. This is explicitly insecure demo/test key material, not a production credential or trust anchor, and it cannot produce `final-verified=true`. `twepd --insecure-demo-agent-key alternate` selects the development key used to exercise a QueryRequest challenge from a real AttesTAM. On the REE side, it only writes the alternate public COSE_Key to `teep-agent/dev-agent-public-key.cbor`; TEEP_Agent selects the corresponding development signer and Generic EAT `cnf.key` only when this file exists. The Go/REE TEEP_Broker and C hostcalls are not the TEEP message COSE_Sign1 generation boundary.
- The inactive `twep_host_agent_public_key` and `twep_host_agent_sign_esp256`
  compatibility imports are removed from the Wasm hostcall ABI. This does not
  change public C ABI v3.
- For Linux and OP-TEE, the Rust TEEP_Agent constructs Generic EAT and signs it with the fixed development ES256 Evidence key. Other backends return unsupported until they implement an Evidence payload and matching media type. The development Evidence path cannot establish `final-verified=true`.
- `twep_host_teep_agent_measurement_sha256` returns the SHA-256 of the `teep-agent.wasm` bytes actually loaded by the current TEEP_Agent runtime as 32 bytes. On success, it returns `0` with `out_len=32`; for a short buffer, it returns `2` with `out_len=32`; when there is no measurement target, it returns `8`. This hostcall is used only by the Rust TEEP_Agent to compare the value byte-for-byte with `measurement_sha256` in `protected-agent-identity.cbor`. Do not treat the result of the TrustZone C diagnostic `TA_TWEP_WR_CMD_MEASURE_WASM` as the authoritative final-bound value.
- `twep_host_acceptance_generation` reads the current D043 acceptance generation. `twep_host_commit_acceptance` compares `expected_generation`, the mandatory component sequence, and the supplied 32-byte QueryResponse digest, then advances them through the TA-owned two-slot record and persists the matching positive version 2 acceptance result before returning success. Rust must not rewrite that protected result through `twep_host_write_file`; the dedicated commit is the sole live-path publication boundary. The digest must match the exact active session-owned pending HTTP request body; success or failure consumes that pending transcript. Return `9` for stale generation, replay, sequence conflict, or missing/mismatched transcript; return `4` for corrupt, ambiguous, or unsupported protected state. These hostcalls are reserved for the fully verified D041 Update path. The `attestam-insecure` compatibility path must not call them.
- `twep_host_commit_catalog` applies the same session-owned transcript and expected-generation checks, requires the exact D047 Catalog component id, recomputes and compares the 32-byte Catalog digest, writes and reopens the inactive protected Catalog slot, verifies that staged record byte-for-byte, and only then performs the D043 compare-and-commit that makes the matching slot active. It returns success and the new generation only after both steps complete. A failure before D043 publication leaves the candidate invisible; a committed D043 state is not rolled back after a later transport failure. This hostcall is unavailable on Linux and to `attestam-insecure`, general Wasm apps, and the REE broker.
- `twep_host_commit_app` is the separate M9.3 protected-app publication boundary. Before calling it, Rust TEEP_Agent must verify the app Update and require both the requested command and the exact payload digest to match the active protected Catalog entry. The hostcall then applies the same session transcript and generation checks, accepts only a canonical `[bstr("twep-app-v1"), bstr(command)]` component identifier, verifies that the supplied 32-byte digest matches the supplied Wasm bytes, stages and reopens one inactive protected app slot, and publishes the matching D043 component sequence. At execution time the TA reloads that protected record and requires its stored digest to match the digest returned by TEEP_Agent Catalog resolution. The two protected slots are an atomic publication mechanism for one active app, not a multi-app inventory. This hostcall is unavailable on Linux and to `attestam-insecure`, general Wasm apps, and the REE broker.
- Randomness, time, and logging are used for TEEP processing by TEEP_Agent, Catalog updates, and debugging.
- Do not expose TEEP_Agent-only hostcalls to general Trusted Wasm Apps. If a general app imports a legacy hostcall from `env`, it fails with an unlinked call. If it imports from `twep_teep_env`, the hostcall is still rejected without the capability.

## Versioning

- The current ABI is `twep-app-v1`.
- Increment the ABI major version when changing an exported function signature.
- Adding only optional fields to a CBOR schema is permitted within the same major version.
- Changes to the meaning of an existing field, addition of a required field, and type changes are breaking changes.
