# ABI and Runtime Behavior

The TEEP Agent follows the `twep-app-v1` ABI. The host places the input CBOR in
Wasm memory and calls `twep_app_main(input_ptr, input_len, out_desc_ptr)`. On
success, the TEEP Agent allocates the output CBOR on its own heap and writes
the little-endian `output_ptr` and `output_len` into the 8-byte region at
`out_desc_ptr`.

## Export ABI

| export | Description |
| --- | --- |
| `twep_app_abi_version() -> u32` | ABI version `1` |
| `twep_app_alloc(len) -> u32` | Also used by the host to allocate an input region |
| `twep_app_free(ptr, len)` | Currently a no-op |
| `twep_app_main(input_ptr, input_len, out_desc_ptr) -> i32` | Main command dispatch |

The heap is a fixed bump allocator with `HEAP_SIZE = 512 * 1024`. It does not
free individual allocations, and it is designed to handle the small CBOR / TEEP
artifacts needed for a single Wasm instance execution.

## Input

The important fields for `resolve_app`-style input are:

| key | type | required | description |
| --- | --- | --- | --- |
| `target_command` | text | yes | User command to resolve |
| `resolver_mode` | text | no | `mock`, `attestam-insecure`, `attestam-verified` |
| `attestam_url` | text | mode-dependent | AttesTAM endpoint. If empty, use local catalog only |
| `command` | text | probe use | Used by hostcall probe commands |

`target_command` is passed to `suit::twep_app_component_id` and becomes CBOR
bytes in the form `[h"747765702d6170702d7631", h"<command>"]`. The command is
limited to ASCII letters and digits, `-`, `_`, and 1 to 32 bytes.

## Dispatch

```text
twep_app_main
  |
  +-- command == hostcall_*_probe
  |     run probes for hostcall boundary tests
  |
  +-- resolver_mode == "attestam-verified"
  |     verified::run_verified_dry_run(out_desc, requested_component_id)
  |
  +-- otherwise
        session::run_resolve_app(out_desc, target_command, requested_component_id, attestam_url)
```

If `attestam_url` is empty, `session::run_resolve_app` immediately reads
`catalog/catalog.cbor`. If a URL is present, it first tries an AttesTAM session
and then performs catalog resolution after install or update succeeds.

## Hostcalls

All TEEP Agent hostcalls are declared in the `twep_teep_env` import module.

| hostcall | TEEP Agent wrapper | Main use |
| --- | --- | --- |
| `twep_host_read_file` | `read_file*` | Read catalog, app, diagnostic, and staging files |
| `twep_host_write_file` | `write_file` | Write diagnostic, staging, and installed payload files |
| `twep_host_read_protected` | `read_protected*` | Read credential, freshness, and platform-identity objects |
| `twep_host_http_post` | `http_post` | AttesTAM session |
| `twep_host_create_evidence` | `create_evidence` | Create EAT evidence for a challenge response |
| `twep_host_platform_status` | `platform_status` | Diagnose backend state |
| `twep_host_teep_agent_measurement_sha256` | `teep_agent_measurement_sha256` | Measurement of the loaded TEEP Agent Wasm |
| `twep_host_random` | `random` | Probe / session helper |
| `twep_host_unix_time_ms` | `unix_time_ms` | Session helper |

General Trusted Wasm Apps do not receive these management hostcalls. Their main
data exchange is CBOR input/output, and they must not directly depend on file,
network, protected storage, evidence, random, or time.

## Catalog Resolution

Local resolution proceeds in this order:

1. Read the length of `catalog/catalog.cbor`.
2. Load the Catalog bytes.
3. Find the `target_command` entry in the `apps` map.
4. Confirm `abi == "twep-app-v1"`, the `sha256` length, and `wasm_file`
   basename safety.
5. Read `apps/<wasm_file>` and compute SHA-256.
6. If the hash matches, return `resolve-app-output` in CBOR.

A hash mismatch becomes `app.hash_mismatch`. An invalid Catalog entry becomes
`catalog.invalid`, and a missing target command becomes `catalog.not_found`.
