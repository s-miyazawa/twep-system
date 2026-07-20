# Overall Architecture

The TEEP Agent is a Rust `cdylib` compiled with `no_std + alloc` and runs on
WAMR. From the host's point of view it exports the same
`twep_app_abi_version`, `twep_app_alloc`, `twep_app_free`, and
`twep_app_main` functions as a normal Trusted Wasm App. However, its execution
environment is separated from general apps, and it imports only the
TEEP-Agent-specific hostcalls from the `twep_teep_env` module.

## Boundaries

The TEEP Agent boundary is split as follows:

| Area | Role | Trust handling |
| --- | --- | --- |
| Go broker / CLI | Receive user commands, manage configuration, call WAMR, assist transport | Does not own final COSE / SUIT / Catalog decisions |
| C / twep-wr / WAMR | Load Wasm, execute ABI, implement hostcalls | Capability enforcement and transport / storage assistance |
| TEEP Agent Wasm | TEEP / COSE / SUIT / Catalog processing, app-promotion decisions | Management-oriented Trusted Wasm App |
| State directory | Catalog, apps, diagnostic, staging artifacts | Development storage on Linux |
| Protected storage | Credentials, freshness, platform identity, and similar state | Trust strength depends on the platform backend |
| AttesTAM | Counterpart for QueryRequest / Update / Success | Development-only in insecure mode; final verification target in verified mode |

## Mode-specific responsibilities

`twep_app_main` branches broadly based on the `resolver_mode` field in the
input CBOR.

| mode | Entry point | Purpose |
| --- | --- | --- |
| `mock` or unspecified | Catalog resolution through `session::run_resolve_app` | Resolve using only the existing Catalog / cache |
| `attestam-insecure` | AttesTAM session through `session::run_resolve_app` | Fetch or update apps and Catalog through a development TEEP session |
| `attestam-verified` | `verified::run_verified_dry_run` | Observe state and generate diagnostics for final verified mode |

`attestam-insecure` performs app promotion and development Catalog generation,
but that is not a trust basis for final verified mode. `attestam-verified` is
conservative, diagnoses incomplete verification steps, and does not proceed to
easy Catalog updates or app execution.

## Main artifacts in the state directory

| path | Source | Content |
| --- | --- | --- |
| `catalog/catalog.cbor` | Existing Catalog or insecure promotion | App list and hashes |
| `apps/<command>.wasm` | `session::install_payload` | Installed Wasm app payload |
| `tmp/update-payload-0.bin` | `session::stage_update_or_127` | Update payload staging |
| `tmp/update-staging-metadata.cbor` | `suit::update_metadata` | Staging metadata |
| `components/install-metadata.cbor` | `session::install_payload` | Installed TC metadata |
| `teep-agent/last-*.cose` | Session processing | COSE messages exchanged with AttesTAM |
| `teep-agent/update-*.cbor` | Session processing | Update / SUIT observation artifacts |
| `teep-agent/verified-*.txt` | Verified dry-run | Diagnostics for why final verified mode is not yet complete |

File read / write hostcalls are limited to the state directory. The TEEP Agent
passes relative paths and the host side controls path traversal and atomic
writes.
