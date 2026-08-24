# twep TEEP Agent

One platform-independent Wasm artifact supports both `arm-optee` and
`riscv-optee`. Verified identity binding treats those as distinct profiles
with the shared `optee-ta` location; a cross-profile identity is rejected.

`wasm/teep-agent` contains the special Trusted Wasm App that manages twep
catalog lookup, AttesTAM development flows, and verified-mode observation. It
uses the same `twep-app-v1` exported ABI as other Trusted Wasm Apps, but it is
not a normal user-command app. The host loads it in a separate WAMR instance
and grants it only the TEEP-specific hostcalls under the `twep_teep_env`
import module.

## Responsibilities

- Resolve a user command to a Catalog File entry and verify the cached Wasm
  payload SHA-256 before execution.
- Run the `attestam-insecure` development flow against an AttesTAM endpoint:
  QueryRequest parsing, QueryResponse generation, Update observation, SUIT
  payload digest checks, Success generation, and development-only app
  promotion.
- Generate development COSE_Sign1 QueryResponse and Success messages inside
  the Rust TEEP Agent rather than in the REE Go broker.
- Parse and observe TEEP/COSE/SUIT data needed for the `attestam-verified`
  dry-run path.
- Write diagnostic artifacts such as `teep-agent/verified-state.txt`,
  `credential-status.txt`, `platform-status.txt`, and `suit-auth-status.txt`.

Final trust decisions must stay in this TEEP Agent / verified-mode path. The Go
broker and C host layer are transport, storage, and policy-enforcement helpers;
they must not become the final verifier for COSE, SUIT, catalog promotion, or
trusted component installation.

## Current Security Model

The crate supports development and observation paths. It is not yet a complete
final-verified TEEP implementation.

- `mock` and `attestam-insecure` may use development catalog/app seeding and
  development AttesTAM flows.
- `attestam-verified` is milestone-gated. Linux performs dry-run observation and
  returns `teep.verified_required`. M9.1 TrustZone is acceptance-only. D047 M9.2
  may commit only the verified default Catalog TC through protected storage and
  send Success after readback; it still forbids mock installation, app
  promotion/execution, and all `attestam-insecure` promotion shortcuts.
- Linux protected storage is observation-only. File-backed sealed storage under
  the Linux backend is not a final trust anchor and must not make
  `final-verified=true`.
- The TEEP Agent Wasm artifact is currently built with the repository and
  copied to `build/teep-agent.wasm`. In final verified mode, the platform root
  of trust is expected to measure or fix this component; AttesTAM self-update
  of the TEEP Agent is out of scope for the initial final verified design.

## Hostcalls

The only import module for TEEP Agent hostcalls is `twep_teep_env`.

Implemented wrappers live in `src/host_io.rs` and cover:

- logging
- state file read/write
- protected object read
- HTTP POST
- evidence creation
- platform status
- random bytes
- Unix time in milliseconds

These hostcalls are for the TEEP Agent runtime only. General Trusted Wasm Apps
must not receive file, network, evidence, protected-storage, random, or time
hostcalls.

## Source Layout

- `src/lib.rs`: `twep-app-v1` entrypoint, allocator, command dispatch, shared
  SHA-256 helper.
- `src/host_io.rs`: safe-ish Rust wrappers around `twep_teep_env` hostcalls.
- `src/catalog.rs`: Catalog File lookup and app hash validation.
- `src/session.rs`: mock and `attestam-insecure` resolution/session flow.
- `src/teep.rs`: TEEP message parsing and QueryResponse payload generation.
- `src/cose.rs`: COSE_Sign1 parsing, verification adapters, and development
  ESP256 signing.
- `src/suit.rs`: SUIT manifest parsing, component-id classification, payload
  digest checks, and install metadata generation.
- `src/verified.rs` and `src/verified/`: verified-mode coordination, state,
  credentials/policy, live acceptance, diagnostics, and focused test modules.
- `src/credential_management.rs`, `src/protected_credentials.rs`,
  `src/freshness.rs`, `src/evidence.rs`: verified-mode credential, freshness,
  and evidence support.
- `src/cbor.rs`: small internal CBOR reader/writer used by the current
  no_std implementation.

## Build and Test

From the repository root:

```sh
cargo test --manifest-path wasm/teep-agent/Cargo.toml
cargo clippy --manifest-path wasm/teep-agent/Cargo.toml --tests
cargo clippy --manifest-path wasm/teep-agent/Cargo.toml --release --target wasm32-unknown-unknown
make test
```

`make test` rebuilds the Wasm artifact and copies it to `build/teep-agent.wasm`
before running Go tests. Prefer it when Rust changes could affect C/Go tests
that execute the built TEEP Agent.

## Design References

The authoritative project documents are in the repository root:

- `Spec.md`
- `docs/Architecture.md`
- `docs/Interface.md`
- `docs/ABI.md`
- `docs/Security.md`

Update those documents when a change alters security boundaries, external wire
formats, ABI behavior, credential semantics, hostcall semantics, or verified-
mode trust decisions.
