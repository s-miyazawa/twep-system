# AGENTS.md: TWEP Repository Guidance

Read only the documents needed for the task after classifying it.

## Always-On Rules

- Check `git status --short` before editing, and preserve unrelated user changes.
- This repository is a small academic reference implementation, not a product platform. Prefer the least code and the most direct design that clearly demonstrates the protocol and trust boundaries; prioritize readability over generality, extensibility, operational completeness, or production credential lifecycle features. Do not add frameworks, provider layers, background services, multi-profile machinery, or speculative abstractions unless the current PoC requires them or the user explicitly approves them.
- `twep-wr` is the public C ABI boundary. Go must not call WAMR or the OP-TEE TA directly, and public C ABI v3 changes require explicit approval and synchronized documentation.
- `docs/ABI.md` is authoritative for Wasm ABI, hostcalls, CBOR schemas, TA envelopes, diagnostic keys, and compatibility rules.
- Only a verified `twep-catalog-v1` Catalog TC may authorize a protected Catalog update. App TCs, REE files, debug JSON, management API data, and personalization data are not Catalog authorities.
- Keep `mock`, `attestam-insecure`, and `attestam-verified` behavior distinct. Never present a development signer, REE-produced Evidence, or `final-verified=false` path as production verification.
- The Linux backend is an REE development backend. On TrustZone, the REE transports bytes and provides availability; TA-local code owns protected-state and execution authorization decisions.
- Treat `arm-optee` and `riscv-optee` as co-equal supported OP-TEE profiles. A result may be described as complete/full OP-TEE coverage only when every applicable scenario has run on both profiles. A one-profile run is profile-specific evidence only; if a counterpart is missing or blocked, report the exact coverage gap and do not call the result complete.
- Use `make smoke-optee-all-profiles` for the quick shared baseline and `make smoke-optee-all-profiles-offline-full` for complete offline OP-TEE coverage. The full aggregate must retain every non-live guest scenario on both profiles; do not replace it with the quick baseline in a full-coverage report.
- New or changed architecture-neutral OP-TEE behavior must have an ARM/RISC-V test mapping in `docs/Testing.md`. Add the missing profile runner when practical; document a genuinely profile-specific exception explicitly rather than silently omitting a profile.
- Live AttesTAM/Veraison coverage follows the same two-profile rule. Run each applicable live phase separately on ARM and RISC-V with independently fresh, disposable, sequence-safe service state as required by `docs/Testing.md` and `docs/AttesTAM.md`.
- When a change affects an ABI, CBOR schema, persistence object, security boundary, trust claim, or resolver behavior, update the applicable specification, architecture, interface, ABI, security, status, and testing documents in the same change.

## Document Routing

| Task | Read as needed |
| --- | --- |
| Go, daemon, CLI, or resolver changes | `docs/Interface.md`, `docs/Architecture.md`, `docs/ABI.md` |
| C or `twep-wr` changes | `lib/twep-wr/README.md`, `docs/Interface.md`, `docs/ABI.md` |
| Rust or Wasm changes | `wasm/teep-agent/README.md`, `wasm/teep-agent/docs/`, `docs/ABI.md` |
| OP-TEE, ARM TrustZone, or RISC-V TEE changes | `optee/twep-wr-ta/README.md`, `optee/twep-wr-ta/ARCHITECTURE.md`, `docs/Testing.md`, `docs/Security.md` |
| Tests, fixtures, or smoke targets | `docs/Testing.md` |
| Security, COSE, SUIT, Evidence, credentials, or AttesTAM | `docs/Security.md`, `docs/AttesTAM.md`, `docs/Architecture.md`, `docs/ABI.md` |
| Current milestone or decision status | `docs/Status.md`, then `Spec.md` for the target specification |

## Subagent Policy

Use subagents only when explicitly requested or for independent specialist work. The main agent retains orchestration, design and security judgment, ABI/schema/protocol decisions, final integration, and release approval.

## Work Checks

Before work, identify the authoritative documents and verify the worktree. After work, report the change summary, files changed, tests run, tests not run and why, specification differences, and the next recommended task.
