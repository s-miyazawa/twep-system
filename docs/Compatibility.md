# Upstream compatibility baseline

This compatibility slice was audited against these exact historical
revisions:

| Component | Revision |
| --- | --- |
| twep-system | `e6723b1ab0e463009d20e71d4f1e88dcd5dc1ae5` |
| AttesTAM | `aa8d4c0dc0ce4ba1f8f8f90fe88bb8cf903141b5` |
| TAWS | `92f6a8e6f6b9ce7820d4e17b229a73baf6b4f99a` |
| TAWS WAMR submodule | `dcf137e961e7d84ed1fdff90bcc40ccadfc01090` |
| selected twep WAMR | `392e7ccbf419555360ae48644bf394f583d22a3c` |

`testdata/compat/upstream-revisions.env` is the machine-readable record. The
read-only `scripts/compat/resolve-upstream-revisions.sh` helper reports newer
remote heads; it does not silently change this reviewed baseline.
These WAMR revisions record that audit and do not constrain future backend
builds. A backend must document and test its own accepted WAMR source layout.

## AttesTAM wire contract

At the recorded AttesTAM revision, `/tam` requires exact `Accept` and
`Content-Type` values of `application/teep+cbor`. An empty initial POST returns
a token-bearing QueryRequest. For an unknown Agent, the token response can be
followed by a QueryRequest containing a 32-byte challenge and no token. HTTP
`200` continues the exchange and `204` terminates it successfully. Requests are
limited to 32 KiB; the server does not impose an explicit response-body limit.

Non-empty TEEP messages use tagged COSE_Sign1 (tag 18), protected ESP256, an
empty protected `kid`, and an unprotected 32-byte `kid`. The `kid` is the
SHA-256 thumbprint of the canonical public EC2 COSE_Key. Tokens and challenges
are 32-byte one-time values. Missing or non-bstr `kid` is fatal. Unknown,
wrong-length, and another public key's `kid` enter the unauthenticated
attestation route. For an unknown Agent, Evidence must establish the key that
verifies the outer QueryResponse. Current stored-key handling does not repeat
that Evidence/signing-key comparison.

QueryResponse uses `selected-version` plus either `tc-list` and a required
echoed token, or paired `attestation-payload`/`attestation-payload-format` and
`requested-tc-list`, with a token only when that QueryRequest had one. Update,
Success, and Error correlate using the current one-time token. AttesTAM routes
Generic EAT Evidence to its configured verifier and stores a successfully
established unknown-agent key for subsequent requests.

Current Linux and OP-TEE Evidence is Generic EAT and is labeled exactly:

```text
application/eat+cwt; eat_profile="urn:ietf:rfc:rfc9711"
```

AttesTAM does not reject every missing or arbitrary format during generic CBOR
decoding. Generic EAT key establishment nevertheless requires an EAT format,
so TWEP emits the exact Veraison Generic EAT value above.

The TEEP Agent echoes a token only when one was present in that QueryRequest.
A challenge is never treated as a token. Evidence payload and format are
emitted together. Evidence is capped at 30 KiB, reserving 2 KiB of AttesTAM's
request limit for CBOR, COSE, format, and component metadata; the final tagged
COSE QueryResponse is independently rejected above 32 KiB.

For the recorded historical baseline, the media type came from the TEEP-Agent-only
`twep_host_attestation_payload_format` hostcall. General applications cannot
import it. Linux and TA-local TrustZone provide Generic EAT, while other
backends return unsupported at this PR boundary.
This historical baseline does not change public C ABI v3, `trustzone`, protected-app,
protected acceptance, D046 token binding, protected Catalog publication, resolver-mode distinctions, or `final-verified=false`.

## Execution record (2026-07-23)

### Reproducible AttesTAM v26 checkpoint

`make attestam-v26-conformance` reads `ATTESTAM_REV` only from
`testdata/compat/upstream-revisions.env`. The runner archives that commit from
`ATTESTAM_ROOT` into a temporary source tree, tests `internal/tam` and
`internal/server`, and builds a temporary server binary. It starts the server
on loopback with a new temporary SQLite database and isolated Intel collateral
cache and log. Consequently neither the AttesTAM checkout nor an existing
`tam_state.db` contributes state to the result.

The checkpoint waits on the read-only manifest-list endpoint and then reuses
`e2e-attestam-live`. It verifies sequence-1 manifest registration, Generic EAT
challenge-response, the TAM-signed Update and payload hash, Success and final
HTTP 204, `helloworld` execution, and absence of
`verified-evidence-result.cbor`. The default server address is
`127.0.0.1:18080`; non-loopback addresses are rejected.

```sh
make WAMR_DIR="$WAMR_DIR" \
  ATTESTAM_ROOT=/path/to/AttesTAM \
  VERAISON_PROVISION_URL="$VERAISON_PROVISION_URL" \
  attestam-v26-conformance
```

`VERAISON_CHALLENGE_URL` optionally overrides the default
`https://127.0.0.1:8443`, and `ATTESTAM_CONFORMANCE_ADDR` optionally selects a
different `127.0.0.1` port. Veraison remains an external disposable
development deployment; the live test provisions its Generic EAT CoRIM.
AttesTAM startup, address conflicts, missing revisions, and Verifier/E2E
failures are fatal, with the isolated AttesTAM log printed on failure.

On 2026-07-23 this checkpoint passed against the revisions above and a local
disposable Veraison development deployment. The pinned AttesTAM tests passed,
the fresh database accepted the sequence-1 manifest, and the live E2E observed
the Generic EAT challenge-response, TAM-signed Update, valid payload hash,
Success, terminal 204, and `Hello, World!!`; it did not create
`verified-evidence-result.cbor`. Negative runner checks also confirmed explicit
failures for an unavailable pinned revision and an occupied listen port.

The resolver reproduced all five revisions above. The selected local WAMR
checkout reported one unrelated dirty sample Makefile; a disposable copy of
its `392e7ccb...` tree was therefore used for the TWEP build. Toolchain:
Go 1.22.0, rustc/cargo 1.95.0, GCC 11.4.0, CMake 3.22.1, Linux
5.15.0-186-generic x86_64.

- PASS: `make fmt`, `make build`, `make test`, `make e2e`, and
  `make e2e-attestam-insecure` (socket-using tests were run with local-listener
  permission).
- PASS: TEEP Agent host and wasm32 clippy with warnings denied, host tests,
  wasm32 release build, and formatting check.
- PASS: Linux and reserved SGX/Keystone platform translation units; OP-TEE
  static smoke mapping; pinned AttesTAM `internal/tam` and `internal/server`
  tests.
- NOT RUN: TrustZone/QEMU build and runtime smokes because `optee_postrun.py`,
  the configured Buildroot cross-toolchain, and `qemu-system-aarch64` were each
  absent.
- NOT RUN: additional live format, `kid`, key-mismatch, and replay negative
  cases. Deterministic TWEP and focused pinned AttesTAM tests cover the
  corresponding wire logic; the pinned positive live checkpoint is recorded
  above.
