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
  `final-verified=false`. On TrustZone it can accept and protect the metadata-only
  default Catalog; verified application installation and execution are not a
  completed final boundary.

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
| Generic EAT Evidence signing fixture | `internal/demokeys/keys.go` |
| Wasm application and TEEP Agent code signing | `internal/demokeys/keys.go` |

The fixture generator writes only the required public verification keys into
the development protected credential store. TEEP-message and SUIT verification
use distinct entries and purposes. Generic EAT uses ES256; the development
TEEP/SUIT messages use the algorithms selected by their existing fixture
profiles.

## Required software

- The prerequisites listed in the root `README.md`
- An AttesTAM checkout
- A Veraison deployment with the Generic EAT verification scheme enabled
- `curl` for provisioning
- `diag2cbor.rb` for converting the repository CoRIM fixture
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
export OPTEE_POSTRUN=/path/to/optee_postrun.py
```

The runner must launch the repository's OP-TEE QEMU environment, expose the
project to the guest, execute the requested smoke command, and return a failure
status when expected Normal World or Secure World evidence is absent.

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
```

The acceptance target checks that only a live TAM-signed Update bound to the
Evidence session can publish the one-time D043 acceptance generation. The
Catalog target checks inactive-slot staging, readback validation, atomic
activation, replay rejection, and failure preservation. Both retain
`final-verified=false`; neither proves completed verified application
installation and execution.

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
