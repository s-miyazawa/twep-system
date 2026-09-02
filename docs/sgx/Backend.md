# SGX Backend Profile

This document is the canonical implementation profile for the SGX backend. It
describes how the backend realizes the common TWEP architecture; it does not
redefine the public C ABI, Wasm ABI, CBOR schemas, security guarantees, or test
procedures.

## Scope and build modes

`TWEP_WR_PLATFORM_BACKEND=sgx` selects the SGX hardware runtime, including
DCAP Quote3 generation, QE transport, and live AttesTAM HTTP transport.
`TWEP_WR_SGX_BACKEND_TESTS=ON` replaces the hardware transport with Intel SDK
Simulation solely for non-deployable backend integration tests. It is not a
runtime mode or security profile. `TWEP_WR_SGX_TEST_HOOKS=ON` is accepted only
with that test option and selects the private test EDL.

Neither configuration falls back to Linux REE WAMR. Both use the same signed,
platform-independent TEEP Agent and application Wasm artifacts as the Linux
and TrustZone backends. Build targets, prerequisites, and expected results are
specified in [Testing.md](../Testing.md); the short hardware walkthrough
remains in [README.md](README.md).

## Trusted and untrusted components

The untrusted `twep-wr` shared library owns URTS lifecycle and bounded byte
transport. Private ECALLs carry normalized execution requests into the
Enclave. OCALLs provide only allowlisted artifact reads, opaque sealed-blob
persistence, QE interaction, synchronous HTTP, and diagnostic output.
The common C runtime reaches SGX through direct compile-time calls for Enclave
initialization, execution, and shutdown; no backend operation table is used.

The Enclave owns all decisions that can authorize protected state or
execution:

- it verifies and measures the role-signed TEEP Agent before granting the
  `twep_teep_env` hostcalls;
- it runs the TEEP Agent and general applications in separate WAMR instances;
- it parses resolver output and checks command, digest, embedded app-role
  signature, ABI, and resource limits;
- it creates and validates Evidence report data in HW mode; and
- it validates, seals, reads back, publishes, reloads, and authorizes protected
  Catalog and application state.

General applications receive no native hostcalls. REE files, HTTP responses,
diagnostic artifacts, and sealed blobs do not become authority merely because
the REE supplied or persisted them. They affect a trusted decision only after
the Enclave applies the required signature, digest, protocol, component, and
allowlist checks. The `mock` and `attestam-insecure` modes remain development
paths; only `attestam-verified` applies the protected publication checks, and
even that fixed-credential PoC remains `final-verified=false`. The private
ECALL/OCALL definitions are implementation details and do
not extend public C ABI v3. See [Interface.md](../Interface.md) for that public
boundary and [ABI.md](../ABI.md) for the hostcall contract.

## Enclave-local WAMR

The selected WAMR `linux-sgx` platform is linked only into the Enclave. A
TEEP-Agent instance performs protocol and Catalog work with its restricted
hostcall namespace. A separate general-app instance executes the selected
application without native imports. Every failure path tears down request-local
state so that a later request can execute independently.

## Runtime sequence

1. `twep_wr_init` validates configuration and creates the Enclave through the
   Intel SGX untrusted runtime system (URTS). Its initialization ECALL verifies
   and measures the signed TEEP Agent,
   and provisions the fixed resolver policy and fixed PoC policy records.
2. The first `twep_wr_execute` enters the Enclave and lazily initializes
   Enclave-local WAMR. Each execution creates request-local TEEP Agent and, when
   needed, general-app WAMR module/instance/exec-env state.
3. HTTP, Quoting Enclave (QE), sealed-blob, artifact, and diagnostic operations
   are synchronous OCALLs within that ECALL. SGX does not use the OP-TEE
   yield/resume continuation model: the OCALL returns bytes to the still-active
   Enclave invocation.
4. The Enclave validates returned bytes and completes any protected acceptance,
   Catalog, or app publication before loading an app.
5. The Enclave reloads the protected app, verifies its authorization, and runs
   it in a separate WAMR instance without native hostcalls.
6. Every execute path destroys its request-local WAMR instances and modules.
   `twep_wr_shutdown` separately clears Enclave configuration/key state and
   destroys the Enclave through URTS; Enclave destruction ends the lazily
   initialized process-wide WAMR state.

## Protected state

The SGX hardware runtime and backend-test harness use the same
measurement-bound sealed-object engine. The REE
broker accepts only fixed physical object names, persists opaque blobs by
atomic replacement, and cannot decrypt, validate, select, or activate them.
The Enclave envelope authenticates the physical name, object type, backend,
policy, TEEP Agent measurement, payload length, and digest.

The protected logical objects are:

- protected acceptance state, including the accepted QueryResponse digest,
  generation, and per-component sequences;
- the protected default Catalog;
- one active application; and
- fixed PoC credential, identity, freshness, revocation, and compatibility
  records used by the demonstrated flow.

The acceptance state, Catalog, and application each use two private slots. A
standalone acceptance commit advances the acceptance record itself. Catalog or
app publication is a distinct sequence: the candidate is sealed into an
inactive slot, reopened and compared, and only then made active by publishing
its matching component sequence through the acceptance transaction. Only the
Enclave selects the active valid generation. Slot names and transaction records
are unavailable through generic protected reads.

The application slots are an atomic publication mechanism for one active app,
not a multi-app inventory. Installing another reference app replaces the
active app. Offline execution after a daemon/Enclave restart reloads the
protected Catalog and app, matches the command and stored/resolver/recomputed
digests, verifies the app-role signature, and then enters general-app WAMR.

The logical protected acceptance, Catalog, and hostcall schemas are defined in
[ABI.md](../ABI.md). The sealed envelope and binary app record are SGX-private
persistence formats; they are not public C ABI, Wasm ABI, or shared CBOR
schemas.

## Transcript-bound publication

For live verified provisioning, each successful outbound QueryResponse POST
establishes one invocation-local pending digest of the exact HTTP request
body. A later acceptance, Catalog, or app commit must consume that value while
checking the expected protected generation and component sequence. A new POST
attempt invalidates the preceding pending value, and every commit attempt
consumes it whether it succeeds or fails. Missing, stale, mismatched, or
replayed state fails closed.

Catalog publication and app publication are separate transactions. Rust TEEP
Agent code validates TEEP, COSE, SUIT, component identity, and Catalog
semantics. Enclave C code owns bounded persistence, readback, and protected acceptance
publication. Only a verified `twep-catalog-v1` default Catalog TC may authorize
a Catalog change. An app TC, REE file, debug JSON, management artifact, or
personalization object is not a Catalog authority.

## Evidence and AttesTAM

In the hardware runtime, the Enclave validates the canonical Wasm-supplied Agent public key
and binds that key and the fresh AttesTAM challenge into DCAP Quote3 report
data. The untrusted side transports QE and HTTP bytes but cannot approve the
Evidence. Intel's Quote Verification Library (QVL) evaluates Quote
authenticity, integrity, and Trusted Computing Base (TCB) status. AttesTAM verifies that
the report data corresponds to its challenge and the TEEP Agent key. AttesTAM
also verifies the QueryResponse signature. The TEEP Agent and protected state
then separately authorize Catalog and app publication.

These stages do not confer one another's authority:

1. the Enclave and Quoting Enclave (QE) generate Quote3;
2. QVL appraises Quote authenticity/integrity and TCB status;
3. AttesTAM checks the challenge, Agent key, and QueryResponse signature;
4. AttesTAM communicates acceptance through a TAM-signed live-session Update;
5. the TEEP Agent validates the requested TC; and
6. Enclave-owned transactions publish the Catalog or app.

The Quote3 media type, canonical bundle, key/challenge binding, and byte limits
are normative only in the Evidence contract in [ABI.md](../ABI.md). AttesTAM
setup and protocol compatibility are described in
[AttesTAM.md](../AttesTAM.md) and [Compatibility.md](../Compatibility.md).

## Limitations and non-claims

- The default HW configuration uses a debug Enclave unless an externally
  signed non-debug Enclave is explicitly supplied.
- Repository credentials and personalization inputs are fixed development
  material. They do not provide issuance, rotation, revocation service, or a
  production credential lifecycle.
- SGX sealing detects tampering but does not prevent restoration of an older
  valid same-policy blob. Host rollback and availability are outside this PoC
  threat model.
- SDK Simulation is confined to the backend-test harness and provides neither
  hardware isolation nor an attestation claim. Fake QE output is test-only.
- Diagnostic HW OCALL output uses bounded safe names and is write-only from the
  Enclave's perspective. It cannot be read back as protected or protocol input.
- The active protocol signer is the fixed development key held by the Wasm
  TEEP Agent. SGX does not provision a separate sealed Agent signing key.
- All demonstrated hardware paths remain `final-verified=false`.

The cross-backend guarantees and explicit non-guarantees are authoritative in
[Security.md](../Security.md).

## Private test hooks

`TWEP_WR_SGX_TEST_HOOKS=ON` exposes narrowly scoped private test ECALLs and a
fake-QE path for deterministic failure injection. Hook builds exercise the
same protected-state and Evidence-builder helpers, but they are not the
hardware runtime, do not alter public C ABI v3, and cannot establish a
hardware or production verification claim. Negative-test ownership and the
normal-versus-hook matrix are defined in [Testing.md](../Testing.md).

## Implementation map

- `make/sgx.mk`: repository-level SGX build and test entry points.
- `lib/twep-wr/cmake/sgx.cmake`: SGX-specific SDK discovery, bridge and
  Enclave construction, signing, target configuration, and backend tests
  attached to the common `twep_wr` target.
- `lib/twep-wr/src/platform/sgx/platform_sgx.c`: untrusted lifecycle and OCALL
  transport.
- `lib/twep-wr/src/platform/sgx/enclave/sgx_teep_runtime.c`: TEEP Agent runtime,
  hostcalls, and transcript gate.
- `lib/twep-wr/src/platform/sgx/enclave/sgx_app_runtime.c`: general-app runtime.
- `lib/twep-wr/src/platform/sgx/enclave/sgx_acceptance_state.c`: protected acceptance state.
- `lib/twep-wr/src/platform/sgx/enclave/sgx_protected_catalog.c`: protected Catalog.
- `lib/twep-wr/src/platform/sgx/enclave/sgx_protected_app.c`: active app.
- `lib/twep-wr/src/platform/sgx/enclave/sgx_sealed_store.c`: sealed objects and
  fixed PoC provisioning.

For the surrounding system, start with [Architecture.md](../Architecture.md).
