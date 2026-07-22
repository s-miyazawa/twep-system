# Spec.md: Trusted Wasm Execution Platform (twep) Specification

## Purpose

twep enables a User to acquire, update, load, and execute Trusted Wasm Apps through `twep-cli`, with AttesTAM integration for TEEP-based provisioning.

The platform has two primary backends: plain Linux (Ubuntu 24.04) and TrustZone (OP-TEE). The Linux backend runs WAMR in the REE process for development, integration, and testing. The TrustZone backend preserves the same public `twep-wr` C ABI while running the TEEP Agent, Catalog resolution, and Trusted Wasm Apps in WAMR inside the TA. Both backends run the same platform-independent Wasm binaries. SGX and Keystone remain portability boundaries rather than implemented backends.

## Confirmed Key Policies

| Item | Policy |
| --- | --- |
| Resolver modes | Provide local mock, explicit AttesTAM insecure integration, and AttesTAM verified protocol modes |
| Verified provisioning | Require TEEP/COSE/SUIT verification against a real AttesTAM instance |
| Trusted Wasm App ABI | Adopt a custom CBOR input/CBOR output ABI. `docs/ABI.md` is authoritative for details |
| ABI evolution | Maintain schema versioning so that a later ABI revision can be defined using an Interface Definition Language |
| Wasm binary portability | The TEEP_Agent Wasm Application and general Trusted Wasm Applications must run as the same Wasm binary across different platform backends such as Linux, TrustZone, SGX, and Keystone. Platform differences are absorbed by hostcall implementations, protected storage, Evidence generation, and runtime policy; platform-specific Wasm artifacts are not created |
| TEEP_Agent hostcalls | Provide file/http/evidence/read-protected/random/time/log exclusively for the TEEP_Agent. COSE_Sign1 generation for TEEP messages is performed within the Rust TEEP_Agent |
| NegaPosi | Support JPEG only. Formats other than JPEG will be handled by a future `negaposi.wasm` update |
| twepd | Run as a user service in the REE for both primary backends |

## Terminology

| Term | Meaning |
| --- | --- |
| User | A person who runs `twep-cli` |
| twep-cli | User-facing CLI implemented in Go |
| twepd | Resident daemon implemented in Go |
| twep-wr | Public C ABI boundary. The Linux shared library hosts WAMR in the REE; the TrustZone shared library uses `libteec` to invoke TA-local WAMR |
| Trusted Wasm App | A Wasm app implemented in Rust, based on `no_std`+`alloc`, and using the `twep-app-v1` ABI |
| TEEP_Agent Trusted Wasm App | A special Wasm app that manages acquisition, update, installation, and loading of Trusted Wasm Apps. It can use file/http/evidence/read-protected/random/time/log hostcalls. It is bundled as a repository build artifact; the Linux backend verifies its demo code-signing identity, while the TrustZone backend additionally measures the exact Wasm bytes loaded inside the TA |
| AttesTAM | A TAM server that distributes Trusted Components over TEEP-over-HTTP |
| Catalog File | A mapping of command names, Wasm app names, versions, hashes, component IDs, and related data |
| WAMR | Wasm Micro Runtime. The runtime that loads and executes Wasm in the Linux REE backend or inside the TrustZone TA |
| TEEP | Trusted Execution Environment Provisioning |
| TAM | Trusted Application Manager |
| TC | Trusted Component |

## Use Cases

### HelloWorld

```sh
$ twep-cli helloworld
Hello, World!!
```

### CalcAdd

```sh
$ twep-cli calcadd 3 4 5
12
```

### NegaPosi

```sh
$ twep-cli negaposi -i image.jpg -o output.jpg
(Saving a Reversed Color Image)
```

## Component Responsibilities

### twep-cli

- Receives a command name and arguments from the User.
- Converts the arguments into a CBOR request.
- Sends the request to twepd through a Unix domain socket.
- Receives a CBOR response from twepd.
- Writes to stdout, displays file-save results, and sets the exit code according to the response type.
- twep-cli itself does not load Wasm.
- twep-cli itself does not communicate with AttesTAM.

### twepd

- Starts as a resident daemon and receives requests over a Unix domain socket.
- Decodes the request CBOR and validates the command name and arguments.
- Calls `twep-wr.so` through the C ABI.
- Delegates checking for, loading, executing, and requesting acquisition of Trusted Wasm Apps to `twep-wr.so`.
- Returns execution results to twep-cli as a CBOR response.
- Manages daemon logs, configuration, and the state directory.

### twep-wr.so

- Initializes the WAMR runtime.
- Handles the WAMR instance for the TEEP_Agent separately from WAMR instances for general Trusted Wasm Apps.
- Restricts TEEP_Agent hostcalls exclusively to the TEEP_Agent through the `twep_teep_env` namespace and capability-bearing exec_env user data; these hostcalls are not configured in the general Trusted Wasm App runtime.
- In `attestam-verified`, does not use development catalog/app seeds, the `TWEP_CATALOG_CBOR` override, mock installation, or unverified promotion. Linux remains a verified dry-run observation path; TrustZone may execute only the bounded M9.3 protected app flow described below.
- Loads the TEEP_Agent Wasm and has it acquire, update, install, and prepare to load the Catalog File and Wasm app binaries.
- Loads general Trusted Wasm Apps, passes them CBOR input, and executes them.
- Implements the export ABI and hostcall ABI for Rust/Wasm apps.
- Exposes only the C ABI to Go.
- Does not expose WAMR internal types, Wasm memory pointers, or native handles to Go.
- Separates platform-dependent processing into `lib/twep-wr/src/platform/<backend>/`. The implemented primary backends are `linux` and `trustzone`; the `sgx` and `keystone` identifiers are portability boundaries that return unsupported until implementations are provided. `platform/linux` is an REE-only development backend and is not used for final verified security claims. `platform/trustzone` adopts OP-TEE REE FS Secure Storage as the TrustZone Secure Storage policy and treats `CFG_REE_FS=y` and `CFG_RPMB_FS=n` as permanent settings. This repository does not include rollback attacks in its threat model, and `sealed-storage-rollback-protected=false` does not by itself block the documented verified protocol checks.

### TEEP_Agent Trusted Wasm App

- Communicates with AttesTAM using TEEP to acquire, update, and install the Catalog File and Trusted Wasm Apps.
- The TEEP_Agent itself is the root-side component that verifies the Catalog File and Trusted Wasm Apps. Initial final verified mode does not support self-update through AttesTAM; measurement or pinning is delegated to the platform root of trust.
- The Generic EAT format is authoritative for Evidence, and the implementation integrates with the Veraison Generic EAT verifier. Hardware-specific evidence/key binding, such as SGX DCAP quotes, OP-TEE hardware unique keys, and RPMB-derived freshness, is outside the repository's verified protocol profile.
- Reads and writes the Catalog File stored in a special directory on the Local File System.
- Resolves a Trusted Wasm App from a command name.
- Verifies a Wasm app's hash, version, and component ID as necessary.
- Does not perform file/network operations directly; it performs them through hostcalls provided by `twep-wr.so`.

### Trusted Wasm App

- Implemented in Rust.
- Based on `no_std`+`alloc`.
- Maintaining `no_std` is the highest priority for Wasm implementations. Before adding a new crate, confirm that it works with both `wasm32-unknown-unknown` and `no_std`. A crate that requires `std` must not be adopted without documenting the exception and a comparison of alternatives in the relevant authoritative specification.
- The TEEP_Agent Wasm Application and general Trusted Wasm Applications are not rebuilt or replaced for each platform backend. Running the same Wasm binary on Linux, TrustZone, SGX, Keystone, and other platforms is mandatory. Platform-specific functionality is not introduced into Wasm through compile-time branches; it is absorbed through `twep_teep_env` hostcalls, C ABI/TA commands, and platform abstractions.
- Receives CBOR input from the host and returns CBOR output.
- Does not directly access files or networks. Required file contents and paths are received in CBOR input and are subject to host-side policy.
- Uses `helloworld`, `calcadd`, and `negaposi` as the initial sample apps. `negaposi` supports JPEG only.

### AttesTAM

- Communicates with the TEEP_Agent over TEEP-over-HTTP as a TAM server.
- The `mock` resolver acquires Trusted Wasm Apps from local testdata for local development and tests.
- The `attestam-insecure` resolver provides explicitly insecure AttesTAM connectivity demonstrations.
- The `attestam-verified` resolver enforces the documented TEEP/COSE/SUIT protocol checks against a real AttesTAM instance. The bundled fixed credentials remain demo-only and do not establish a production security claim.

## Execution Flow

### When the Trusted Wasm App Exists Locally

1. The User runs `twep-cli <command> [args...]`.
2. twep-cli generates a CBOR request and sends it to twepd over UDS.
3. twepd decodes the request and passes it to `internal/twepwr`, which owns final normalization of the command, app input CBOR, and timeout before calling the C ABI equivalent of `twep_wr_execute`.
4. twep-wr.so uses the TEEP_Agent to consult the Catalog File.
5. If the Wasm app file corresponding to the command name exists and passes hash verification, it is loaded into a general WAMR instance.
6. The CBOR input is passed to the Trusted Wasm App's `twep_app_main`.
7. The Trusted Wasm App returns CBOR output.
8. twep-wr.so returns the result to twepd.
9. twepd returns a CBOR response to twep-cli.
10. twep-cli reflects the result in stdout and the exit code.

### When the Trusted Wasm App Does Not Exist Locally

The behavior depends on the resolver and milestone. The following two flows
must not be read as one currently implemented flow.

#### Current M9.3 academic verified-app behavior

1. The User request reaches the TA-local TEEP Agent through the public C ABI and TrustZone execute envelope.
2. The TEEP Agent performs the live TEEP/COSE/SUIT, freshness, credential/policy, identity, and AttesTAM-acceptance checks.
3. If no protected Catalog exists, it accepts the default `twep-catalog-v1` Catalog TC, validates its bounded canonical metadata, publishes it through the protected D047/D043 transaction, and returns `teep.verified_required` so the command can be retried.
4. On retry, it requests the command's `twep-app-v1` TC. AttesTAM may return that Update without another Evidence challenge after the agent was accepted in the preceding Catalog session; in that case the TEEP Agent requires the protected AttesTAM-acceptance generation to remain current and binds the Update to the retry session's own rolling tokens and immediately preceding QueryResponse. It then verifies the Update and exact payload digest and requires the active protected Catalog entry to authorize that command and digest.
5. It writes the one active app through a TA-owned two-slot protected transaction, publishes the corresponding D043 sequence only after readback, reloads the protected bytes, checks their stored digest against the TEEP Agent's resolver result, and executes the app in the general-app WAMR instance with no hostcalls.
6. Later processes can execute the protected Catalog/app pair without contacting AttesTAM. A different app may replace the single active app through the same verified flow; there is deliberately no multi-app protected store.
7. This fixed-development-credential PoC remains explicitly insecure and reports `final-verified=false`, including after successful app execution.

The `mock` resolver may still install local development fixtures, and
`attestam-insecure` remains a separately labelled connectivity demonstration.
Neither behavior is authority for the verified protected Catalog.

#### Production deployment work (outside this academic repository)

The reference flow above demonstrates retrieval, verification, protected
installation, Catalog authorization, and execution. It does not attempt
production credential issuance or enrollment, protected production private
keys, rotation/revocation/recovery services, hardware-rooted Evidence, rollback
protection, multi-app inventory, or `final-verified=true`. Those are deployment
concerns, not missing requirements for this small academic implementation.

## Persistence

### Runtime Directories

| Purpose | User service proposal | System service proposal |
| --- | --- | --- |
| socket | `$XDG_RUNTIME_DIR/twep/twepd.sock` | `/run/twep/twepd.sock` |
| config | `$XDG_CONFIG_HOME/twep/config.toml` | `/etc/twep/config.toml` |
| state | `$XDG_STATE_HOME/twep/` | `/var/lib/twep/` |
| catalog | `$STATE/catalog/catalog.cbor` | `/var/lib/twep/catalog/catalog.cbor` |
| wasm apps | `$STATE/apps/*.wasm` | `/var/lib/twep/apps/*.wasm` |
| logs | stdout/systemd journal | systemd journal |

The current Linux and TrustZone configurations run `twepd` as a user service in the REE and use the user-service paths above. The system-service paths define the corresponding deployment layout when a system service is configured.
If `XDG_RUNTIME_DIR` is unset, the client and daemon fall back to
`<os.TempDir()>/twep/twepd.sock`, normally `/tmp/twep/twepd.sock` on Linux, as
specified in `docs/Interface.md`.

### Catalog File

The primary format is CBOR. A JSON dump with equivalent content may be generated for development and debugging.

In final verified mode, the Catalog File is distributed as an independent SUIT Trusted Component. The authoritative SUIT Component Identifier is `[ bstr("twep-catalog-v1"), bstr(catalog-name) ]`, and the default catalog name is `default`. Debug JSON, data obtained from the AttesTAM management API, and personalization data within a TEEP Update are not trusted as grounds for updating the Catalog File unless they are verified as a Catalog TC.

Conceptual schema:

```cddl
twep-catalog = {
  "schema_version": uint,
  "generated_at" => tstr,
  "source" => tstr,
  "apps" => { * command-name => app-entry },
}

command-name = tstr
app-entry = {
  "display_name" => tstr,
  "component_id" => tstr,
  "version" => tstr,
  "abi" => "twep-app-v1",
  "wasm_file" => tstr,
  "sha256" => bytes,
  ? "args_schema" => any,
  ? "accepted_formats" => [* tstr],
  ? "resource_limits" => resource-limits,
  ? "description" => tstr,
}

resource-limits = {
  ? "stack_bytes" => uint,
  ? "heap_bytes" => uint,
  ? "timeout_ms" => uint,
  ? "max_output_bytes" => uint,
}
```

Initial example:

```json
{
  "schema_version": 1,
  "generated_at": "2026-04-25T00:00:00Z",
  "source": "local-dev",
  "apps": {
    "helloworld": {
      "display_name": "HelloWorld",
      "component_id": "twep.example.helloworld",
      "version": "0.1.0",
      "abi": "twep-app-v1",
      "wasm_file": "helloworld.wasm",
      "sha256": "<hex>"
    },
    "calcadd": {
      "display_name": "CalcAdd",
      "component_id": "twep.example.calcadd",
      "version": "0.1.0",
      "abi": "twep-app-v1",
      "wasm_file": "calcadd.wasm",
      "sha256": "<hex>"
    },
    "negaposi": {
      "display_name": "NegaPosi",
      "component_id": "twep.example.negaposi",
      "version": "0.1.0",
      "abi": "twep-app-v1",
      "wasm_file": "negaposi.wasm",
      "sha256": "<hex>",
      "accepted_formats": ["image/jpeg"],
      "resource_limits": {
        "heap_bytes": 16777216,
        "timeout_ms": 10000,
        "max_output_bytes": 16777216
      }
    }
  }
}
```

## CLI Arguments and CBOR Encoding

The platform provides both of the following:

1. Standard mode: Put the command line directly into CBOR as `argv`. The host also builds `inferred_params` as a parallel typed array for every argv token: signed decimal tokens become `{"type":"int"}`, unsigned decimal tokens that require unsigned range become `{"type":"uint"}`, and all other tokens become `{"type":"text"}`.
2. Explicit mode: The User directly specifies app input CBOR using `--cbor-file` or `--cbor-hex`.

Conceptual standard-mode request:

```cddl
twep-cli-request = {
  "schema_version": 1,
  "request_id": tstr,
  "command": tstr,
  "argv": [* tstr],
  "inferred_params": [* typed-value],
  ? "stdin": bytes,
  "cwd": tstr,
  "env_policy": "none" / "allowlisted",
}

typed-value =
  { "type": "int", "value": int } /
  { "type": "uint", "value": uint } /
  { "type": "text", "value": tstr } /
  { "type": "bytes", "value": bytes } /
  { "type": "bool", "value": bool }
```

Conceptual response:

```cddl
twep-cli-response = {
  "schema_version": 1,
  "request_id": tstr,
  "status": "ok" / "error",
  "exit_code": int,
  ? "stdout": bytes,
  ? "stderr": bytes,
  ? "result": any,
  ? "error": {
    "code": tstr,
    "message": tstr,
    ? "details": any,
  },
}
```

## Trusted Wasm App ABI

`docs/ABI.md` is authoritative. `docs/Interface.md` covers the connection specifications for IPC, the C ABI, and hostcalls. The following is a summary:

- The app exports `twep_app_abi_version`, `twep_app_alloc`, `twep_app_free`, and `twep_app_main`.
- The input is a CBOR byte sequence.
- The output is also a CBOR byte sequence.
- `negaposi` receives JPEG bytes as `files["input"]` within CBOR and returns JPEG bytes as `files["output"]`.
- Ownership of the output buffer transfers from the app to the host, but the host ultimately releases it using the app's `twep_app_free`.
- Error codes returned by the app follow the table in `docs/ABI.md`.

## Provisioning and Attestation Modes

### Local Mock Mode

- Installs the Catalog File and Wasm apps from local testdata.
- Does not implement TEEP messages.
- Acquires a missing app using the mock resolver.
- This mode is for local development and tests and is not used for security claims.

### AttesTAM Insecure Integration Mode

- Sends TEEP-over-HTTP messages to AttesTAM's `POST /tam`.
- Operates only when insecure demo mode is enabled through explicit configuration.
- COSE/SUIT/attestation verification may be limited, but unverified status is emitted in logs and responses.
- This mode is separated from verified protocol processing and makes no security claim.

### AttesTAM Verified Protocol Mode

- Processes QueryRequest, QueryResponse, immediate Update, Success, and Error for the supported protocol routes.
- Verifies the applicable CBOR, COSE, SUIT component, sequence, and payload-digest conditions.
- Commits an accepted `twep-catalog-v1` Catalog TC to protected TrustZone state through the dedicated Catalog transaction; unsupported component operations fail closed.
- Couples replay protection and freshness to the protected acceptance generation and component sequence.
- Uses a real AttesTAM and Veraison service in the live TrustZone smoke path. The bundled fixed development credentials keep repository demonstrations at `final-verified=false` and do not authorize production use.

### Remote Attestation Integration

- Generates Evidence for AttesTAM challenge-response.
- Treats AttesTAM as the Relying Party for Veraison. TEEP Agent does not receive or verify Veraison Attestation Results.
- Verifies the TAM trust anchor, TAM-signed Update, acceptance-generation freshness, and agent key binding.
- Uses development Evidence on plain Linux and TA-mediated Evidence handling on TrustZone.

## Acceptance Criteria

### Platform Acceptance Criteria

- `make build` can build `twep-cli`, `twepd`, `twep-wr.so`, and the sample Wasm apps.
- `make test` passes the Go/C/Rust unit tests.
- `make e2e` starts twepd and successfully runs the following:

```sh
twep-cli helloworld
twep-cli calcadd 3 4 5
twep-cli negaposi -i testdata/images/input.jpg -o /tmp/twep-output.jpg
```

- `helloworld` writes `Hello, World!!` to stdout.
- `calcadd 3 4 5` writes `12` to stdout.
- `negaposi` generates a JPEG output image and indicates successful saving through stdout or the result.
- On the normal `negaposi` CLI path, the CLI validates and reads the input JPEG with User permissions and saves the output JPEG by renaming a temporary file. twepd/twep-wr do not handle arbitrary file paths for general apps.
- If a Wasm app is not available locally, the configured resolver can use local testdata, the AttesTAM insecure integration mode, or the AttesTAM verified protocol mode according to its documented security policy.
- A Wasm app that fails Catalog File hash verification is not executed.
- The TrustZone build preserves public C ABI v3 through `libteec` and executes `helloworld`, `calcadd`, and `negaposi` in TA-local WAMR.
- TrustZone smoke tests cover TA-local TEEP Agent resolution, general-app hostcall rejection, resource limits, host-I/O continuation, protected state, and AttesTAM/Veraison integration.

### Security Acceptance Criteria

- The UDS cannot be read by other users.
- For a custom UDS path, the parent directory's owner/mode are verified, and group/world-writable directories are rejected.
- An app path containing `..` or an absolute path cannot escape the state directory.
- WAMR heap/stack limits are configured.
- A Wasm app cannot directly access the host FS/network.
- Insecure mode cannot be enabled without explicit configuration.

## Non-goals

The following are outside the current repository scope:

- Intel SGX and Keystone runtime backends
- Production credential issuance, enrollment, rotation, revocation-feed, and recovery services
- Production-specific hardware attestation beyond the documented Generic EAT and OP-TEE integration
- Multi-user system daemon operation
- An advanced policy language for each Wasm app
- Arbitrary file writes outside the sandbox

## Design changes

Durable architectural requirements are recorded in the authoritative public
specifications. A change to a public contract, security boundary, or trust
decision must update the relevant specification before publication.
