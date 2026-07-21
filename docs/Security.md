# Security.md: TWEP Security Design Notes

## KISS / DRY

The security design follows KISS and DRY. Trust boundaries, assets, threats, and mitigations are organized by the smallest unit of responsibility, and the same validation condition is not defined under different names in multiple paths. Commonization and simplification are permitted only when they do not weaken privilege separation, validation strength, or auditability.

## Security Goals

- Execute only the Trusted Wasm App corresponding to the command intended by the User.
- Detect tampering with the Catalog File and Wasm app binary.
- Do not grant direct file system or network permissions to general Trusted Wasm Apps.
- Separate the privileges of TEEP_Agent from those of general apps.
- Enforce explicit trust boundaries for both the plain Linux backend and the TrustZone backend, with REE-side `twepd` outside the TrustZone trust boundary.

## Platform Trust Boundaries

### Plain Linux Backend

The plain Linux backend provides no TEE isolation. Its security boundary consists of:

- in-process WAMR sandbox
- hostcall restrictions within twep-wr.so
- file path validation
- hash validation
- UDS permissions
- explicit resolver modes and isolation of insecure modes

Resolver selection does not change this boundary. The mock and AttesTAM modes on Linux remain development and integration facilities rather than a TEE security claim.

### TrustZone Backend

The TrustZone backend runs TEEP_Agent, Catalog resolution, and general Trusted Wasm Apps in TA-local WAMR. The REE transports requests, cache and state bytes, HTTP responses, and Evidence bytes, but it does not decide Catalog contents, component classification, payload validity, promotion eligibility, or execution authorization. OP-TEE REE FS Secure Storage holds protected acceptance, credential, identity, and Catalog state according to the schemas in `docs/Interface.md` and `docs/ABI.md`.

## Assets

| asset | protection objective |
| --- | --- |
| Trusted Wasm App binary | Tamper detection and rollback prevention |
| Catalog File | Tamper detection for the command mapping table |
| TEEP_Agent Wasm | Tamper detection for management logic. A privileged Wasm App that can use file/http/evidence/read-protected/random/time/log hostcalls. It also generates COSE_Sign1 for TEEP messages. In final verified mode, it is measured or pinned by the platform root of trust |
| TAM trust anchor | Exclusion of unauthorized TAMs |
| agent key | Protection of the agent identity |
| User input/output file | Prevention of path traversal and unintended reads or writes |
| twepd socket | Prevention of unauthorized execution by other users |

## Threat and Authority Matrix

| Asset or decision | Attacker capability considered | Trusted authority | Guaranteed now | Not guaranteed | Linux / TrustZone | Time horizon |
| --- | --- | --- | --- | --- | --- | --- |
| Evidence production | REE can replace or replay transported bytes | Current PoC TEEP Agent plus fixed development Evidence key | Protocol shape, nonce/key correspondence, and Veraison interoperability can be exercised | Hardware-rooted Evidence or production key custody | Linux and the current TrustZone PoC use REE-produced development Evidence; neither can claim final verification from it | Current PoC; hardware Evidence is future work |
| Veraison appraisal | Network and REE can delay, drop, or alter responses | Veraison, consumed by AttesTAM as Relying Party | AttesTAM requires an affirming appraisal before its acceptance step | TEEP Agent does not receive or independently validate a Veraison Attestation Result | Same authority model on both backends | Current |
| AttesTAM acceptance | REE can replay or mix sessions and responses | TAM signature plus TA-session transcript, D046 token handling, and D043 protected generation | A current TAM-signed Update is bound to the live Evidence exchange and consumed once | Availability, production credential lifecycle, or `final-verified=true` | Linux observes; TrustZone can commit the protected acceptance state | Current PoC |
| Catalog authorization | REE can supply arbitrary Catalog or app bytes | TEEP Agent semantic validation plus the TA-owned D047/D043 publication transaction | Only the exact default Catalog TC can become the active protected Catalog | App TCs, debug JSON, management data, and personalization cannot authorize Catalog changes | Linux is observation-only; TrustZone is authoritative | Current M9.2 |
| App installation and execution authorization | REE can substitute candidate bytes or names | Future verified app-TC checks plus protected Catalog lookup | Existing local/mock apps still receive hash/signature checks; M9.2 rejects verified app Update and performs no app execution | Verified app installation, protected authorization, and execution are not implemented | Linux development paths exist; TrustZone M9.2 is Catalog-only | Future verified lifecycle |
| Protected state | REE controls storage availability and can roll back REE FS | TA object access rules, two-slot validation, and current D043 linkage | Corruption, ambiguous slots, stale generations, and unauthorized object access fail closed | Rollback resistance and availability are outside this PoC threat model | Linux files are observations; TrustZone REE FS Secure Storage is authoritative | Current PoC |
| General app sandbox | App may be malicious and import host functions | TA or Linux `twep-wr` runtime policy and Catalog entry | General apps currently receive no hostcalls and must match authorized bytes | Host confidentiality from the Linux process owner and denial-of-service resistance are not claimed | Linux has no TEE isolation; TrustZone isolates execution inside the TA | Current |

These are four separate decisions, in order: Evidence is generated; Veraison
appraises it; AttesTAM accepts the TEEP Agent in a live protocol session; and
the TEEP Agent plus TA-local protected state authorize a Catalog or, in a
future lifecycle, an app. Success at one stage does not grant the authority of
the next. In particular, the TrustZone REE provides availability, HTTP/TLS and
byte transport, cache access, and development Evidence brokering. It does not
decide appraisal, AttesTAM acceptance, Catalog publication, app promotion, or
app execution authorization.

## Threats

| threat | mitigation |
| --- | --- |
| A local attacker modifies the catalog | State directory permissions, catalog signature or hash validation, atomic updates |
| The app Wasm is replaced | Validate the sha256 in the catalog |
| Path traversal | Basename restrictions, canonical path validation, rejection of paths outside the state directory |
| An app reads host files | Do not provide file hostcalls to general apps |
| An app communicates arbitrarily with AttesTAM | Do not provide network hostcalls to general apps |
| TEEP_Agent communicates with an arbitrary URL | Permit only the AttesTAM URL from the configuration |
| Replayed TEEP Update | Validate sequence and acceptance freshness in `attestam-verified` mode |
| An insecure demo is used in production | Require an explicit resolver mode and config flag, emit log warnings, and prohibit mixing it into verified mode |
| C ABI buffer ownership bug | Owned-buffer conventions, tests, and sanitizers |
| Resource exhaustion | WAMR heap/stack/timeout/output size limits |

## UDS Permissions

- For a user service, set `$XDG_RUNTIME_DIR/twep` to `0700`.
- After listening, set the default `twepd.sock` to `0600` so that only the owning user can connect.
- For a custom socket path, verify at startup that the parent directory is owned by the current user and is not group- or world-writable.
- If converted to a system service, define an explicit group policy.

## Catalog/Wasm Validation

Baseline checks on both backends:

- Include sha256 in each catalog entry.
- Calculate sha256 before loading Wasm and confirm that it matches.
- If it does not match, reject it with `app.hash_mismatch`.

Additional checks in verified provisioning:

- Validate the Catalog File itself in association with TEEP/COSE/SUIT.
- Verify the Trusted Component Signer's signature.
- Detect rollback using the version or SUIT sequence number.

## Hostcall Policy

### General Trusted Wasm Apps

- No hostcalls by default.
- Do not provide even the log hostcall to general apps. If logging is needed, permit it only after adding a Catalog allowlist and a namespace for general apps.
- Do not set the TEEP_Agent capability on a general app runtime.
- Register TEEP_Agent management hostcalls only in the `twep_teep_env` namespace, not in the legacy `env` namespace.
- Every `twep_teep_env` hostcall entry point requires the TEEP_Agent capability in the exec_env user data.
- The host reads file input and passes it to the app as CBOR bytes.
- The app returns file output as CBOR bytes, and the host stores it according to policy.
- For `negaposi -i PATH`, the CLI reads the file with User privileges and places it in CBOR `files.input` only after validating that the path contains no NUL, has a `.jpg`/`.jpeg` extension, refers to a regular file, is no larger than 16 MiB, and has JPEG magic.
- For `negaposi -o PATH`, the CLI permits any path writable with User privileges. twepd/twep-wr do not handle arbitrary file paths for general apps; the CLI writes `files.output` to a temporary file in the same directory and then renames it. Overwriting an existing file is permitted according to User privileges. A system-service deployment must define a separate output policy.
- `negaposi` handles only JPEG bytes. Both the CLI and app reject formats other than JPEG.

The general app policy is the same for the TrustZone backend. `twep_wr_execute` runs the production WAMR runtime inside the TA without setting the TEEP_Agent capability on general apps. If a general app imports `env.*` or `twep_teep_env.*`, reject it through link/capability checks inside the TA, and do not allow it to use file/network/evidence/random/time/read-protected hostcalls. Keep reads and writes of `negaposi` User file paths on the CLI/REE side, and pass only CBOR input containing JPEG bytes to the TA.

### TEEP_Agent

- Permit reads and writes of files under the state directory.
- Permit HTTP POST to the AttesTAM URL.
- Permit random/time/log.
- Do not permit DNS or communication with arbitrary URLs.

For the TrustZone backend, run TEEP_Agent in the WAMR runtime inside the TA and register `twep_teep_env` hostcalls inside the TA. Restrict file reads and writes to TA-managed object IDs rather than arbitrary paths; the REE side is responsible only for transporting object bytes. The TA retains the policy, request ID, and transcript for HTTP POST and Evidence creation, explicitly requests them from the REE broker as `need_host_io`, and receives the result bytes through `RESUME_HOST_IO`. The REE broker is responsible for actual HTTP communication, cache byte transport, and Evidence byte brokering; it must not interpret Catalog lookup, TC/app classification, payload hash validation, or promotion eligibility as trust decisions. Per D027, the TrustZone path does not retain a WAMR call frame across an REE round trip. Instead, the same TEEP_Agent Wasm binary is re-executed or entered through an explicit continuation entry using TA session-local continuation state, a transcript digest or sequence, and host I/O result validation.

There are two distinct SHA-256 trust boundaries. SHA-256 for Catalog/app/SUIT payloads is part of the trust-decision logic executed by the same TEEP_Agent Wasm binary across platforms and is ultimately consolidated in TEEP_Agent Wasm. TA-side C code may use SHA-256 only for transcript binding, such as `request_body_sha256` or `normalized_input_sha256` in the TA-private host I/O envelope. This digest comparison exists to reject tampering with or mix-ups in REE broker resume operations; it must not be used as the basis for determining Catalog entries, app payloads, Trusted Component classification, or promotion eligibility.

## Resource Limits

- Set stack/heap/timeout/max output for each app.
- Limits may be overridden by the catalog but may not exceed the global maximum.
- Convert `timeout_ms` to an instruction-count budget and stop WAMR execution when the budget is exceeded.
- `timeout_ms = 0` means unspecified, not unlimited. Determine the effective timeout from Catalog `resource_limits.timeout_ms` or `twep_wr_config_t.default_timeout_ms`; request `options.timeout_ms` may only shorten it.
- If the output size is exceeded, reject it with `app.runtime` or `app.output_too_large`.

## Resolver Modes and Insecure Mode

The following three resolver modes are explicit:

| mode | purpose | security claim |
| --- | --- | --- |
| `mock` | Local development and E2E | Installs local fixtures and makes no security claim |
| `attestam-insecure` | AttesTAM connectivity checks | For development. Explicitly identifies an unverified state |
| `attestam-verified` | PoC protocol-validation path | Requires TEEP/COSE/SUIT validation but remains explicitly insecure and `final-verified=false` under D045 |

`insecure_demo_mode` may be enabled only with `attestam-insecure`. Under D045, `attestam-verified` is also an explicitly insecure PoC protocol path because it uses fixed development TEEP Agent and Generic EAT signers; it must retain `final-verified=false` and is not a production trust claim. It rejects unverifiable TEEP messages, unsigned components, and components with SUIT mismatches. During M9.1, it must not proceed to development catalog seeding, the `TWEP_CATALOG_CBOR` override, mock app installation, Catalog/app promotion, or general app execution.

TEEP_Agent Wasm itself is the root-side component that validates, obtains, and installs the Catalog File and Trusted Wasm Apps. In the plain Linux PoC, it is installed from a repository build artifact into the state directory, but privileged TEEP_Agent hostcall capability is granted only after `twep-wr` verifies the embedded `twep.sig` code signature with the insecure demo TEEP Agent code-signing public key. General Trusted Wasm Apps must verify with the separate insecure demo app code-signing public key and are rejected if signed as a TEEP Agent. TEEP Agent privilege therefore derives from the code-signing identity, not from the state-directory file path alone. The D045 TrustZone PoC additionally checks the TA-local TEEP_Agent measurement but does not claim a production root of trust. Updating TEEP_Agent itself through AttesTAM is outside the PoC scope, avoiding circular trust in which TEEP_Agent updates itself in the same TEEP session.

Even in `attestam-insecure`, the HTTP payload exchanged with AttesTAM follows the AttesTAM specification. At this stage, TEEP_Agent extracts the COSE_Sign1 payload, determines that the TEEP message type is QueryRequest, and creates a QueryResponse payload containing a `twep-app-v1` SUIT Component Identifier derived from the target command. In the insecure development demo, that payload is signed as COSE_Sign1 by the development ESP256 signer in the Rust TEEP_Agent and sent in a second POST. For an Update returned by the second POST, raw body, manifest, and payload diagnostics may be saved before installation eligibility is validated. A mismatched or unsupported component is rejected before staging, the Success POST, or installation. A matching supported App proceeds through payload SHA-256 verification and the embedded `twep.sig` app code-signature check before staging; a matching supported Catalog component remains under the Catalog TC boundary and is not treated as a Wasm app signature target. After staging, TEEP_Agent sends a signed Success POST and installs after NoContent. In `attestam-insecure`, installing a matching App at `apps/<command>.wasm` also generates a development Catalog File. This development behavior is not a final trust basis; final verified Catalog updates require a separately verified `twep-catalog-v1` Catalog TC.

`twepd --insecure-demo-agent-key alternate` is a development option for observing real AttesTAM challenges. Permit it with `attestam-insecure` only when `insecure_demo_mode=true`, and permit it with the D045 `attestam-verified` PoC while `insecure_demo_mode=false`. The `teep-agent/dev-agent-public-key.cbor` written to state is REE-visible development material and must not be treated as part of a production trust boundary or as an official agent identity.

The Milestone 8.5 `twep-app-v1-metadata` was a development payload used to create a vertical slice for Wasm app promotion with an AttesTAM insecure demo fixture. From the Milestone 9 preparation onward, it is not used as the basis for classification or Catalog promotion even in `attestam-insecure`; in `attestam-verified`, this development key and unverified COSE/SUIT must not be used for trust decisions. In verified mode, only TEEP/COSE/SUIT-validated components conforming to the official AttesTAM specification are used as the basis for Trusted Component installation, and Catalog updates are restricted to the Catalog TC.

From Milestone 9 onward, `attestam-verified` uses only the SUIT Component Identifier as the basis for classifying a twep app. The only permitted `twep-app-v1` identifier is `[ bstr("twep-app-v1"), bstr(command) ]`, a CBOR array of byte strings, and `command` is restricted to `[A-Za-z0-9_-]{1,32}`. TEEP_Agent confirms that the requested component identifier matches the component identifier in the Update's SUIT manifest, that the SUIT payload digest matches the SHA-256 of the integrated payload, and that the sequence number is not a rollback before installing the payload in the `apps/` cache. An identifier mismatch, digest mismatch, unverified COSE/SUIT, or a TC containing only development metadata is not executed as an app.

In the D047 PoC Catalog milestone, the Catalog File is handled as an independent SUIT Trusted Component. M9.2 accepts only `[bstr("twep-catalog-v1"), bstr("default")]`. The Catalog is canonical CBOR metadata of at most 64 KiB and 256 app entries; Wasm binaries remain separate app TCs. Updating it requires successful COSE/SUIT validation, integrated-payload digest validation, sequence freshness, D043 generation comparison, complete bounded Catalog decoding, and the fixed development-key checks selected for this explicitly insecure PoC. Debug JSON, data obtained from the AttesTAM management API, personalization data in a TEEP Update, and metadata from a `twep-app-v1` app TC are not used as a Catalog authority.

D047 makes Catalog activation a TA-owned protected transaction without moving Catalog policy into C. Rust validates the Catalog semantics, while the TA reserves two protected Catalog slots, verifies session ownership and readback, and makes a candidate visible only when its sequence matches the current D043 Catalog component sequence. A pre-publication failure therefore retains the prior Catalog. Generic writes, public secure-storage provisioning, general Wasm apps, and the REE broker cannot address the internal slots. Success is generated only after protected publication and readback. Fixed development signers, REE mock Evidence, and the absence of production credential lifecycle services still require the path to remain explicitly insecure, non-production, and `final-verified=false`.

As the entry point for Milestone 9, `internal/verifiedteep` parses an AttesTAM-like COSE_Sign1 TEEP Update and confirms that the payload digest in the SUIT manifest matches the SHA-256 of the integrated payload. When given the fixture developer key, it can also verify the outer TEEP message COSE_Sign1 and the detached COSE_Sign1 in the SUIT authentication wrapper. It can also confirm that the session token retained from QueryRequest/QueryResponse matches the Update token, rejecting an empty, missing, or mismatched token. Sequence freshness accepts an in-memory map of the last sequence for each raw encoded component identifier and rejects an equal or lower sequence as a rollback/replay. `VerifyFixtureUpdateCOSE` is a fixture API that applies all these checks together and, even on success, reports `FixtureVerified=true` and `Verified=false` to distinguish the result from final verified mode. However, this is an REE-side parser test implementation and must be treated as `Verified=false` until an official trust anchor and persistent freshness storage inside the TEE have been validated. To use it as the basis for updating the Catalog File or `apps/` cache in `attestam-verified`, these validations must be moved to the TEE-side TEEP_Agent.

D046 separates that fixed-fixture equality rule from the live AttesTAM state machine. In a live session, token A from the initial QueryRequest is echoed in the first signed QueryResponse and validated by AttesTAM before it returns the challenge. The immediate TAM-signed Update later contains a newly generated token B for a possible Success message. TEEP_Agent requires both tokens to be non-empty and at most 128 bytes, but does not require A and B to match. Token presence is not independently sufficient: the ordered continuation, exact pending Evidence QueryResponse transcript, TAM signature, Update/SUIT/component checks, protected policy and identity bindings, and D043 one-time commit collectively establish the PoC acceptance result.

The TEE-side Rust TEEP_Agent has a `VerificationState` representing `cose_outer_verified`, `session_token_bound`, `suit_auth_verified`, `sequence_fresh`, `evidence_affirming`, `agent_identity_bound`, and `trust_anchor_bound`. The `evidence_affirming` name is retained for compatibility, but the final-capable meaning is AttesTAM acceptance of this TEEP_Agent, not direct Veraison result verification by TEEP_Agent. On the TrustZone final path, OP-TEE REE FS Secure Storage is the official Secure Storage, and rollback attacks are outside the threat model. Advancing to `trust-anchor-bound=true` requires the fixture verification step, protected credential store, issuer allowlist, store freshness, revocation state, AttesTAM acceptance proven by a TAM-signed Update with current D043 acceptance generation, and TEEP_Agent identity binding to be consistent across TrustZone REE FS Secure Storage and the TEEP_Agent boundary inside the TA. Individual binding of the credential/policy objects alone is insufficient to promote the state to `trust-anchor-bound=true`. AttesTAM is the Relying Party for Veraison; TEEP_Agent does not receive or verify Attestation Results. Legacy `verified-evidence-result.cbor` observations remain compatibility diagnostics and should migrate toward an AttesTAM acceptance result object. The TEEP_Agent identity is written to `teep-agent/agent-identity-status.txt` with the backend, runtime location, TEEP_Agent location, and observation source derived from platform status. On TrustZone, the state advances to `agent-identity-binding=bound` and `agent-identity-bound=true` only if the backend/location in `protected-agent-identity.cbor` matches platform status and `measurement_sha256` byte-for-byte matches the SHA-256 of `teep-agent.wasm` loaded inside the TA. The plain Linux development version stores a CBOR map from raw encoded component identifier bytes to the last accepted SUIT sequence number in `teep-agent/dev-sequence-freshness.cbor` and rejects an equal or older sequence. Because this file is in the REE state directory, it is observation-only. D043 replaces the final-path sequence map with the generation-based, two-slot `teep-acceptance-state` object in TrustZone REE FS Secure Storage; the implementation migrates the legacy protected sequence map once and then treats the acceptance object as the sole final-path authority.
`twep-cli diagnose verified --output-format json` reports the broad categories blocking final verified mode in `summary.final_blockers` and separately reports missing trust-anchor details in `summary.trust_anchor_blockers`. This makes it possible to track credential/policy blockers such as an unmatched issuer allowlist, unbound store freshness, or unbound revocation state mechanically without collapsing the broad `teep.trust_anchor_unbound` category.

Credential management in TEEP_Agent explicitly separates credential purposes. The currently distinguished purposes are AttesTAM message verification, SUIT content verification, Generic EAT signing, TEEP_Agent-specific Evidence signing, and Wasm App code signature verification. The D045 acceptance-only PoC requires distinct AttesTAM message-verification and SUIT content-verification entries; the fixture generator supplies both from fixed development keys. Hardware-specific key binding and a production credential service are not PoC requirements. When `attestam-verified` runs, it writes the following observation data to `teep-agent/credential-status.txt`: the COSE `kid` extracted from `verified-input.cose`; purpose-specific entry selection; the load state of `teep-agent/dev-trust-anchors.cbor`; and the load state of `teep-agent/protected-credential-store.cbor`. A matching entry in TrustZone REE FS Secure Storage may satisfy the PoC key-selection and policy checks, but D045 still prohibits treating the fixed development key as a production trust anchor or reporting `final-verified=true`. An entry must match both its purpose-specific array and its `purpose`, preventing an AttesTAM message-verification key and a SUIT content-verification key from being misused for each other. Invalid CBOR is `malformed`, and a schema/purpose/algorithm mismatch is `unsupported`; neither may be used. The credential-store schema in `docs/Interface.md` is authoritative; the public integration and demo-key roles are documented in `docs/AttesTAM.md`.

The Protected credential store schema in `docs/Interface.md` is authoritative. For the D045 TrustZone PoC, the generated fixture is provisioned into OP-TEE REE FS Secure Storage and exact `kid`, purpose, algorithm, issuer/policy, and epoch consistency checks remain fail-closed. The fixed fixture is sufficient; this repository does not require a credential issuance, developer/device enrollment, rotation, revocation-feed, recovery, or protected private-key service. A file in the REE state directory is not authoritative for TrustZone, and Linux may only observe it. These limitations, plus the fixed development private keys, require `final-verified=false`. A future production system could define lifecycle, validity, revocation, and freshness requirements, but that design is outside this repository's current plan and must not be inferred from the extensible fixture fields.

When store freshness and revocation state can be compared against protected objects in TrustZone REE FS Secure Storage, determine whether they can be bound based on object loading, schema validation, epoch/ID consistency with the credential store, and consistency with the issuer allowlist, AttesTAM acceptance, and TEEP_Agent identity, rather than on the presence of rollback protection. `sealed-storage-rollback-protected=false` remains diagnostic information and is not by itself a blocker for `protected-credential-store-freshness=bound`, `protected-credential-store-revocation-status=bound`, `store-freshness-bound=true`, or `revocation-state-bound=true`. The Linux backend continues to remain `matched-unbound` or `loaded-unbound`.

The PoC fixture generator creates the credential store and issuer-policy objects, and the TrustZone smoke provisions them through the existing TA Secure Storage helper rather than a network service or TEEP Update. Keep platform-dependent processing under `lib/twep-wr/src/platform/<backend>/`. Because `platform/linux` is an REE-only development backend, its sealed-storage-like APIs remain observation-only.

On the TrustZone backend, run TEEP_Agent, Catalog resolution, and general app execution in the WAMR runtime inside the TA. The current OP-TEE configuration, `CFG_REE_FS=y` and `CFG_RPMB_FS=n`, adopts REE FS Secure Storage for this PoC. Successful execution inside the TA, TA Secure Storage PUT/GET, Catalog/app resolution, TEEP/COSE/SUIT validation, fixed-key policy consistency, a TAM-signed Update with current D043 generation, and TEEP_Agent identity matching are all useful PoC evidence, but D045 requires the aggregate outcome to remain explicitly insecure and `final-verified=false`. Diagnostics report `runtime-location=trustzone-ta`, `teep-agent-location=trustzone-ta`, `catalog-resolution-location=trustzone-ta`, `sealed-storage-security=tee-ree-fs-secure-storage`, and `sealed-storage-rollback-protected=false`; rollback is outside the PoC threat model.

The official responsibilities of the Go/REE side are IPC with `twep-cli`, HTTP/TLS communication, buffer transport, and state file I/O. The REE-side Go module `internal/teepbroker` is called `TEEP_Broker` in the design. Generation and validation of COSE data, generation and validation of TEEP protocol messages, Evidence generation, SUIT manifest processing, Wasm App validation, Catalog lookup, and Catalog/app promotion decisions are the responsibility of TEEP_Agent inside the TEE. QueryResponse/Success COSE_Sign1 signing in TEEP_Broker is discontinued; the Rust TEEP_Agent generates them using the development ESP256 signer. COSE_Sign1 validation in `internal/verifiedteep` is an intermediate REE-side implementation for development fixture/parser testing and is not considered a trusted application. The insecure demo key is for development only; in `attestam-verified`, only TEEP/COSE/SUIT messages validated by TEEP_Agent inside the TEE are used as the basis for applying Trusted Components. Ultimately, the Rust TEEP_Agent inside the TEE generates and validates COSE_Sign1 for TEEP messages and the SUIT authentication wrapper. The Rust implementation uses the `ciborium` crate for detailed CBOR operations and the `coset` crate for COSE structure processing. For cryptographic and signature operations required by `coset`, crates introduced by the RustCrypto project (<https://github.com/rustcrypto>) are the first choice, with an allowlist limited to algorithms supported by AttesTAM.

Evidence used for AttesTAM Remote Attestation is based on Generic EAT. TEEP_Agent controls the correspondence among the QueryRequest challenge, TEEP Agent public COSE_Key, and QueryResponse signing key, and creates `attestation-payload` as COSE_Sign1(EAT CBOR). COSE algorithms are separated by purpose. ESP256 is used for TEEP message COSE between TAM and TEEP_Agent and for SUIT-related signatures and signature validation. ES256 is used for Evidence creation by TEEP_Agent and Evidence validation by Veraison, matching the current Veraison Generic EAT verifier. Separate the Evidence signing key from the TEEP Agent signing key, and bind the TEEP Agent signing key through EAT `cnf.key`. AttesTAM is the Relying Party for Veraison and decides whether the Evidence makes this TEEP_Agent acceptable. TEEP_Agent does not receive or verify the Attestation Result; it observes AttesTAM acceptance only through a TAM-signed Update returned in the live Evidence challenge-response session. For mock Evidence in the plain Linux development version, the EAT Evidence itself is signed with an attester ES256 key from the companion `teep-wasm-demo` checkout, and EAT `cnf.key` contains the TEEP Agent public COSE_Key used to sign QueryResponse. SGX Quote, OP-TEE/TrustZone tokens, and hardware-specific evidence keys are not included in this repository's initial final verified conditions. TEEP_Broker on the REE is responsible only for HTTP/TLS and buffer transport and is not a trust basis for Evidence generation or validation. AttesTAM forwards received Evidence to the Veraison Verifier for validation. The design does not use direct runtime communication from the twep User state directory to Veraison. `docs/AttesTAM.md` is authoritative for the demo/test key-material mapping.

## Prohibited Logging

- private keys
- the complete raw binary of attestation evidence
- the complete body covered by a COSE signature
- complete image binaries, especially all JPEG input/output bytes
- all User environment variables
- access tokens, cookies, and authorization headers

## Additional Requirements for a Future TEE Implementation

- Keep the TEEP_Agent private key or agent key inside the TEE.
- Place the TAM trust anchor inside the TEE or in protected storage that the TEE can validate.
- Guarantee that Remote Attestation Evidence originates from the TEE.
- Treat twepd as the Broker/REE and design it so that it cannot tamper with TEEP messages.
- Preserve data/code separation between TEEP_Agent and general apps inside the TEE.
