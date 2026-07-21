# AGENTS.md: TWEP Repository Guidance

Read only the documents needed for the task after classifying it.

## Always-On Rules

- Check `git status --short` before editing, and preserve unrelated user changes.
- `twep-wr` is the public C ABI boundary. Go must not call WAMR or the OP-TEE TA directly, and public C ABI v3 changes require explicit approval and synchronized documentation.
- `docs/ABI.md` is authoritative for Wasm ABI, hostcalls, CBOR schemas, TA envelopes, diagnostic keys, and compatibility rules.
- Only a verified `twep-catalog-v1` Catalog TC may authorize a protected Catalog update. App TCs, REE files, debug JSON, management API data, and personalization data are not Catalog authorities.
- Keep `mock`, `attestam-insecure`, and `attestam-verified` behavior distinct. Never present a development signer, REE-produced Evidence, or `final-verified=false` path as production verification.
- The Linux backend is an REE development backend. On TrustZone, the REE transports bytes and provides availability; TA-local code owns protected-state and execution authorization decisions.
- When a change affects an ABI, CBOR schema, persistence object, security boundary, trust claim, or resolver behavior, update the applicable specification, architecture, interface, ABI, security, status, and testing documents in the same change.

## Document Routing

| Task | Read as needed |
| --- | --- |
| Go, daemon, CLI, or resolver changes | `docs/Interface.md`, `docs/Architecture.md`, `docs/ABI.md` |
| C or `twep-wr` changes | `lib/twep-wr/README.md`, `docs/Interface.md`, `docs/ABI.md` |
| Rust or Wasm changes | `wasm/teep-agent/README.md`, `wasm/teep-agent/docs/`, `docs/ABI.md` |
| OP-TEE or TrustZone changes | `optee/twep-wr-ta/README.md`, `optee/twep-wr-ta/ARCHITECTURE.md`, `docs/Security.md` |
| Tests, fixtures, or smoke targets | `docs/Testing.md` |
| Security, COSE, SUIT, Evidence, credentials, or AttesTAM | `docs/Security.md`, `docs/AttesTAM.md`, `docs/Architecture.md`, `docs/ABI.md` |
| Current milestone or decision status | `docs/Status.md`, then `Spec.md` for the target specification |

## Subagent Policy

Use subagents only when explicitly requested or for independent specialist work. The main agent retains orchestration, design and security judgment, ABI/schema/protocol decisions, final integration, and release approval.

## Work Checks

Before work, identify the authoritative documents and verify the worktree. After work, report the change summary, files changed, tests run, tests not run and why, specification differences, and the next recommended task.
