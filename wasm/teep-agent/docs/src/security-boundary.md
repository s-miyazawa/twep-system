# Security Boundary and Verified Mode

`wasm/teep-agent` contains both the development `attestam-insecure` flow and
the `attestam-verified` dry-run path toward final verified mode in the same
crate. It is important not to mix them.

## Allowed in insecure mode

`attestam-insecure` is a convenient path for development and E2E.

- Sign QueryResponse / Success with a development agent key using COSE_Sign1.
- Hash-verify and store the integrated payload from AttesTAM Update.
- Save a `twep-app-v1` app TC to `apps/<command>.wasm`.
- Generate a minimal Catalog from `source=attestam-insecure` app TCs.
- Update `teep-agent/dev-sequence-freshness.cbor`.

These are not final verified security claims. In particular, development keys,
Linux file-backed sealed storage, and insecure-promotion catalogs are not trust
anchors.

## What to protect in verified mode

`attestam-verified` stops conservatively until the final verification
conditions are satisfied.

- Do not perform mock install.
- Do not promote app TCs into the Catalog.
- Do not mix development fixtures such as `TWEP_CATALOG_CBOR` into the final
  path.
- Do not proceed to Success POST or general app execution.
- Observe COSE, SUIT auth, session token, trust anchor, credential policy,
  freshness, evidence binding, and agent-identity binding as separate steps.

The `VerificationState` in `verified.rs` represents which verification steps
have been completed and which are still outstanding. Outstanding states appear
in artifacts such as `teep-agent/verified-state.txt`, `credential-status.txt`,
`platform-status.txt`, `evidence-status.txt`, and
`agent-identity-status.txt`.

## Thinking about verification steps

The important steps in verified mode are conceptually ordered as follows:

1. Verify the outer COSE_Sign1 received from AttesTAM.
2. Check the session token.
3. Verify the SUIT manifest and payload digest in the Update.
4. Bind the SUIT auth block to the trust anchor.
5. Read the protected credential store, issuer allowlist, freshness, and
   revocation state.
6. Confirm whether the platform protected storage can act as the final trust
   anchor.
7. Confirm whether the evidence result is bound to the platform and the agent
   public key.
8. Confirm whether the measurement of the currently loaded TEEP Agent Wasm
   matches the protected agent identity.

On the Linux backend, even if a file-backed object can be read, it is often
only observed as `loaded-unbound` or `matched-unbound` and does not reach final
verified mode.

## Component update state

## Implementation boundaries to preserve

| Decision | Where it belongs |
| --- | --- |
| COSE_Sign1 payload extraction and signature verification | `cose.rs` / `verified.rs` |
| TEEP message type, token, QueryResponse generation | `teep.rs` |
| SUIT manifest / component id / payload digest verification | `suit.rs` |
| Catalog entry parsing and app hash verification | `catalog.rs` |
| App install, staging, and Success POST | `session.rs` |
| Protected credential / policy diagnostics | `credential_management.rs`, `protected_credentials.rs` |
| Reading protected platform objects | Through the `host_io.rs` wrapper |

The Go broker and C host layer are only helpers for transport, Wasm execution,
hostcall policy, and state-directory I/O. Moving the final COSE / SUIT /
Catalog promotion decision to the REE side would break the TEE / Trusted Wasm
App boundary.

## Notes when changing this document

- If you add hostcalls, check `docs/ABI.md` and the host-side capability
  enforcement at the same time.
- If you change the Catalog File format, app entry schema, or SUIT Component
  Identifier, update the specification documents.
- Do not reuse `attestam-insecure` fixtures in `attestam-verified`.
- Do not treat Linux protected storage as a final trust anchor.
- Diagnostic artifact names are used by E2E and operations checks, so update
  tests and documentation together if they change.
