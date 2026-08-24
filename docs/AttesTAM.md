# AttesTAM integration guide

This guide describes the public development integration between `twep`,
[AttesTAM](https://github.com/kentakayama/AttesTAM), and a Veraison deployment.
It covers the reproducible insecure demo and the environment needed to exercise
the verified proof-of-concept path.

## Security warning

This repository publishes fixed private keys for disposable demos and automated
tests. They are intentionally insecure. Never use them in production, shared
validation environments, long-lived deployments, or with external services.
They do not represent a production credential lifecycle and cannot establish
`final-verified=true`.

Use newly generated, deployment-specific credentials and a suitable protected
key service for any real deployment. Do not expose the demo services to an
untrusted network.

## Integration model

- `twepd` owns IPC, HTTP transport, and state-file transport on the Linux side.
- The Rust TEEP Agent owns TEEP, COSE, SUIT, Catalog validation, and promotion
  decisions.
- AttesTAM is the TAM and relying party. It keeps the Veraison Attestation
  Result internal and communicates acceptance through the live TEEP session.
- Veraison verifies Generic EAT Evidence after the development CoRIM has been
  provisioned.
- `attestam-insecure` is a development compatibility path.
- `attestam-verified` is a proof-of-concept path and still reports
  `final-verified=false`. On TrustZone the default M9.3 academic path protects
  the default Catalog, authorizes one app by command and exact digest, protects
  it, and executes it inside the TA. This is a bounded reference flow, not a
  production trust claim or multi-app deployment system.

The public protocol references are:

- [AttesTAM repository](https://github.com/kentakayama/AttesTAM)
- [AttesTAM TEEP message handling](https://github.com/kentakayama/AttesTAM/blob/main/doc/TEEP_MESSAGE_HANDLE.md)
- [Veraison project](https://github.com/veraison)
- [twep ABI](ABI.md)
- [twep security model](Security.md)

## Demo key roles

The fixed demo material is intentionally kept in source so clean checkouts can
reproduce tests without a private key service.

| Purpose | Repository source |
| --- | --- |
| TAM TEEP-message signing and verification fixture | `internal/demokeys/keys.go` |
| TEEP Agent QueryResponse and Success signing fixture | `internal/demokeys/keys.go` and `wasm/teep-agent/src/cose.rs` |
| Alternate development TEEP Agent signer | `internal/teepbroker/teepbroker.go` and `wasm/teep-agent/src/cose.rs` |
| SUIT/TC signing fixture | `internal/demokeys/keys.go` |
| Generic EAT Evidence signing fixture | `wasm/teep-agent/src/cose.rs` |
| Wasm application and TEEP Agent code signing | `internal/demokeys/keys.go` |

The fixture generator writes only the required public verification keys into
the development protected credential store. TEEP-message and SUIT verification
use distinct entries and purposes. Generic EAT uses ES256; its fixed
development private key and signing operation are embedded in the Rust
TEEP_Agent Wasm and remain separate from the TEEP message ESP256 signer. The
key is publicly recoverable and forgeable, not a hardware-protected or
production credential, so successful verification still requires
`final-verified=false`. The development TEEP/SUIT messages use the algorithms
selected by their existing fixture profiles.

## Required software

- The prerequisites listed in the root `README.md`
- An AttesTAM checkout
- A Veraison deployment with the Generic EAT verification scheme enabled
- `curl` for provisioning
- GNU `base64` and `sha256sum` for materializing and checking the tracked
  Generic EAT CoRIM fixture
- For TrustZone-only validation: an OP-TEE/QEMU environment, its Buildroot
  toolchain file, and an `optee_postrun.py`-compatible runner

Keep each checkout in any directory you choose. The commands below use
environment variables and do not depend on a particular local layout.

## Environment variables

From the `twep-system` checkout, set:

```sh
export TWEP_ROOT="$(pwd)"
export ATTESTAM_ROOT=/path/to/AttesTAM
export VERAISON_DEPLOYMENT=/path/to/veraison-deployment
export WAMR_DIR=/path/to/wasm-micro-runtime

export ATTESTAM_URL=http://127.0.0.1:8080/tam
export ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest
export VERAISON_PROVISION_URL=https://127.0.0.1:9443/endorsement-provisioning/v1/submit
```

The Veraison challenge-response endpoint configured in AttesTAM is normally:

```text
https://127.0.0.1:8443/challenge-response/v1/newSession
```

Development deployments commonly use self-signed TLS certificates. Limit
insecure TLS exceptions to a local disposable environment.

## Build twep

```sh
cd "$TWEP_ROOT"
make WAMR_DIR="$WAMR_DIR" build
make WAMR_DIR="$WAMR_DIR" test
```

The build produces signed Wasm files using the published demo-only signing
keys. Generated files are written below ignored `bin/`, `build/`, and Cargo
`target/` directories.

## Start Veraison

Follow the selected Veraison deployment's installation instructions and ensure
that its VTS, provisioning, verification, and management services are running.
For a compatible native deployment helper, a typical command is:

```sh
"$VERAISON_DEPLOYMENT/bin/veraison" start-tmux twep-veraison
```

If the helper is unavailable, start the four services using the deployment's
own configuration. Confirm that the Generic EAT media type is registered:

```text
application/eat+cwt; eat_profile="urn:ietf:rfc:rfc9711"
```

The Evidence-bearing TEEP QueryResponse must carry this value in option 12.
AttesTAM must also create the Veraison challenge-response session with the
base64url-encoded nonce extracted from that Evidence, rather than a fixed demo
nonce. AttesTAM independently matches the verified nonce to its outstanding
TEEP QueryRequest challenge, so a fixed Veraison session nonce cannot
authenticate a normal live exchange with a freshly generated challenge.

Provision the repository's deliberately insecure Generic EAT CoRIM fixture:

```sh
cd "$TWEP_ROOT"
make VERAISON_PROVISION_URL="$VERAISON_PROVISION_URL" \
  provision-veraison-generic-eat-fixture
```

Use a fresh disposable Veraison store when repeating sequence-sensitive live
tests. An affirming result requires the fixture trust material to be present.

## Start AttesTAM

In a separate terminal:

```sh
cd "$ATTESTAM_ROOT"
go run ./cmd/attestam -insecure-demo-mode
```

The default development service listens on port 8080. Restrict it to the local
machine. Use a fresh disposable AttesTAM database for repeatable registration
and sequence tests.

## Register development Trusted Components

Register an application fixture:

```sh
cd "$TWEP_ROOT"
make WAMR_DIR="$WAMR_DIR" \
  ATTESTAM_REGISTER_URL="$ATTESTAM_REGISTER_URL" \
  register-attestam-helloworld-fixture
```

The component identifier is
`[ bstr("twep-app-v1"), bstr("helloworld") ]`. Register the default Catalog
fixture separately when testing the Catalog path:

```sh
make ATTESTAM_REGISTER_URL="$ATTESTAM_REGISTER_URL" \
  register-attestam-catalog-fixture
```

The only Catalog authority is
`[ bstr("twep-catalog-v1"), bstr("default") ]`. An application component,
debug JSON, or management API response cannot authorize a Catalog update.

## Validate the insecure integration

The deterministic fixture-server E2E test requires no external services:

```sh
cd "$TWEP_ROOT"
make WAMR_DIR="$WAMR_DIR" e2e-attestam-insecure
```

With the local AttesTAM service running, test its HTTP endpoint:

```sh
make WAMR_DIR="$WAMR_DIR" \
  ATTESTAM_URL="$ATTESTAM_URL" \
  smoke-attestam-insecure
```

For the live AttesTAM/Veraison application flow:

```sh
make WAMR_DIR="$WAMR_DIR" \
  ATTESTAM_URL="$ATTESTAM_URL" \
  ATTESTAM_REGISTER_URL="$ATTESTAM_REGISTER_URL" \
  VERAISON_PROVISION_URL="$VERAISON_PROVISION_URL" \
  e2e-attestam-live
```

The live test provisions the Generic EAT fixture, registers the development
manifest, completes challenge-response and Update/Success processing, and
executes `helloworld`. It is an insecure proof-of-concept because it uses the
published demo credentials.

## Validate the TrustZone proof of concept

TrustZone validation additionally needs:

```sh
export OPTEE_BUILDROOT_TOOLCHAIN=/path/to/optee/out-br/host/share/buildroot/toolchainfile.cmake
export OPTEE_POSTRUN="$PWD/scripts/optee_postrun.py"
```

The repository runner launches the official OP-TEE QEMU v8 environment,
exposes the project to the guest, executes the requested smoke command, and
returns a failure status when expected Normal World or Secure World evidence
is absent. `OPTEE_POSTRUN` already defaults to this path; the export is needed
only when invoking from a wrapper that replaces Makefile defaults.

Representative targets are:

```sh
make WAMR_DIR="$WAMR_DIR" \
  OPTEE_BUILDROOT_TOOLCHAIN="$OPTEE_BUILDROOT_TOOLCHAIN" \
  OPTEE_POSTRUN="$OPTEE_POSTRUN" \
  ATTESTAM_URL="$ATTESTAM_URL" \
  ATTESTAM_REGISTER_URL="$ATTESTAM_REGISTER_URL" \
  VERAISON_PROVISION_URL="$VERAISON_PROVISION_URL" \
  smoke-optee-trustzone-attestam-verified-acceptance

make WAMR_DIR="$WAMR_DIR" \
  OPTEE_BUILDROOT_TOOLCHAIN="$OPTEE_BUILDROOT_TOOLCHAIN" \
  OPTEE_POSTRUN="$OPTEE_POSTRUN" \
  ATTESTAM_URL="$ATTESTAM_URL" \
  ATTESTAM_REGISTER_URL="$ATTESTAM_REGISTER_URL" \
  VERAISON_PROVISION_URL="$VERAISON_PROVISION_URL" \
  smoke-optee-trustzone-attestam-verified-catalog

make WAMR_DIR="$WAMR_DIR" \
  OPTEE_BUILDROOT_TOOLCHAIN="$OPTEE_BUILDROOT_TOOLCHAIN" \
  OPTEE_POSTRUN="$OPTEE_POSTRUN" \
  ATTESTAM_URL="$ATTESTAM_URL" \
  ATTESTAM_REGISTER_URL="$ATTESTAM_REGISTER_URL" \
  VERAISON_PROVISION_URL="$VERAISON_PROVISION_URL" \
  smoke-optee-trustzone-attestam-verified-app
```

The acceptance target preserves the historical M9.1 stopping point. The Catalog
target checks the historical M9.2 inactive-slot and D043 publication boundary.
The app target checks the default M9.3 sequence: Catalog publication, a later
app Update authorized by the protected Catalog, TA-local execution, and an
offline restart execution from protected state. The current AttesTAM normally
returns that later app Update directly after the new session's component-list
QueryResponse; the TEEP Agent therefore requires the existing protected
acceptance generation to remain current and binds the Update to the new
session's rolling tokens and exact preceding QueryResponse. All retain
`final-verified=false` because they use fixed development credentials.

## Validate on riscv-optee v9

Place `twep-system` and `riscv-optee` beside one another and first complete the
baseline `make smoke-optee-riscv-v9`. Keep fresh disposable host AttesTAM and
Veraison services running. Each target provisions the Generic EAT CoRIM and
registers every fixture required by its selected phase before QEMU starts. The
QEMU guest reaches the host through `10.0.2.2` by default.

```sh
make smoke-optee-riscv-v9-attestam-live \
  ATTESTAM_URL=http://10.0.2.2:8080/tam \
  ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest

make smoke-optee-riscv-v9-attestam-verified-acceptance \
  ATTESTAM_URL=http://10.0.2.2:8080/tam \
  ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest

make smoke-optee-riscv-v9-attestam-verified-catalog \
  ATTESTAM_URL=http://10.0.2.2:8080/tam \
  ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest

make smoke-optee-riscv-v9-attestam-verified-app \
  ATTESTAM_URL=http://10.0.2.2:8080/tam \
  ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest
```

The Catalog target deliberately rebuilds the TA with D043 fault-injection
hooks and checks inactive-slot publication, restart/readback, equal-sequence
and replay rejection, pre-publication failure, D043-publication failure, and
preservation across a later non-Catalog acceptance. Rebuild without those hooks
before running or deploying the app target. The app target checks protected
Catalog installation, protected `helloworld` installation and TA-local
execution, then starts fresh host processes with an unreachable TAM and proves
offline execution after restart. Each runner performs a clean guest poweroff so
the v9 ext2 image is not left dirty by abrupt QEMU termination.

All four targets require `final-verified=false`: the published development
keys are forgeable and OP-TEE REE FS Secure Storage on this platform does not
claim rollback protection. A successful run validates integration and
persistence mechanics, not production attestation assurance.

## Validate live behavior on both OP-TEE profiles

For shared AttesTAM/Veraison behavior, run the ARM target for the selected
phase, stop and replace the disposable AttesTAM database and Veraison store,
then provision/register the fixture again and run the corresponding RISC-V
target shown above. Record both commands and results in the test report.

The two runs must not share service state. Both profiles use the same fixed
development Agent identity, while AttesTAM acceptance and component sequence
state persist across sessions. Reusing a database can therefore make the
second profile look previously accepted even though its protected OP-TEE state
was reset. This would test a cross-profile state collision rather than
equivalent fresh-device behavior. See `docs/Testing.md` for the
complete-coverage rule and for how to report a missing profile counterpart.

## Expected behavior and troubleshooting

- Connection failures return `teep.network`.
- Malformed, mismatched, unsigned, or unsupported messages return
  `teep.protocol` before staging or installation.
- `204 No Content` is not proof of attestation acceptance. Acceptance requires
  the signed live-session protocol result described above.
- Equal or lower component sequences are rejected. Start with fresh disposable
  service state, or register a sequence higher than the retained one.
- A non-affirming Veraison result normally means the Generic EAT scheme or the
  fixture CoRIM is missing, the nonce does not match, or the Evidence profile is
  unsupported.
- `twep-cli diagnose verified --state-dir <state>` reports the current boundary
  states. Treat every `final-verified=false` result as non-final regardless of
  which individual fixture checks pass.

After local validation, stop AttesTAM and the Veraison services and remove the
disposable service databases and twep state directory. Never promote their
demo credentials or state into another environment.
