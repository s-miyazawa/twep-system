# SGX HW Manual Demo

This guide describes a manual demo that starts a resident `twepd` on a prepared
SGX host and runs three Wasm applications from another terminal. It does not
cover installing the SGX SDK, AESM, DCAP/PCCS, WAMR, or AttesTAM. See
[Testing](../Testing.md#sgx-hw) for the required environment and automated
regression tests.

## What the Demo Shows

- The `attestam-verified` resolver path using SGX Evidence verified by Intel QVL
- Initial publication of the protected Catalog by a verified `twep-catalog-v1`
  Catalog TC
- Retrieval and execution of `helloworld`, `calcadd`, and `negaposi` inside SGX
- Storage of protected Catalog and application state in SGX sealed state rather
  than plaintext files in the REE

This is an academic PoC that uses the default `SGX_HW_DEBUG=ON` setting and a
fixed development credential. Even on success, `final-verified=false`; this
does not demonstrate production verification or a production credential
lifecycle.

## Prerequisites

- An SGX device, AESM, and DCAP/PCCS are available
- An AttesTAM service with Intel QVL enabled is already running at
  `127.0.0.1:8080` with fresh disposable DB/cache state. SGX smoke tests use
  only its public registration and `/tam` APIs; the service checkout and DB
  path are not test inputs.
- The WAMR source tree contains `product-mini/platforms/linux-sgx`
- Run the following commands from the root of the TWEP checkout


## Preparation

### 1. Build with the WAMR source tree

The only environment variable required in this terminal is `WAMR_DIR`.

```sh
cd /path/to/twep-system
export WAMR_DIR=/path/to/wasm-micro-runtime
make WAMR_DIR="$WAMR_DIR" build build-sgx-hw
```

### 2. Register the demo manifests with AttesTAM

```sh
./scripts/register_attestam_demo_apps.sh \
  http://127.0.0.1:8080/SUITManifestService/RegisterManifest
```

This registers the Catalog, `helloworld`, `calcadd`, and `negaposi` at sequence
1. Run it only once against a fresh AttesTAM DB. Registration is not
transactional. If it fails partway through, restart AttesTAM with another fresh
DB/cache and repeat the registration from the beginning.

### 3. Prepare fresh TWEP state

```sh
STATE_DIR="${TMPDIR:-/tmp}/twep-sgx-demo-state"
./scripts/prepare_sgx_demo_state.sh "$STATE_DIR"

# To reset the state if necessary.
./scripts/prepare_sgx_demo_state.sh --reset "$STATE_DIR"
```

The script returns an error if the directory already contains data; it neither
deletes nor reinitializes that directory. This fixture does not authorize the
Catalog. Only a verified `twep-catalog-v1` Catalog TC can authorize an update to
the protected Catalog.


### 4. Start the resident twepd

In the daemon terminal, start it with the prepared state explicitly specified.

```sh
LD_LIBRARY_PATH="$PWD/build/twep-wr-sgx-hw${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  ./bin/twepd \
  --socket "$STATE_DIR/twepd.sock" \
  --state-dir "$STATE_DIR" \
  --resolver-mode attestam-verified \
  --attestam-url http://127.0.0.1:8080/tam \
  --insecure-demo-agent-key alternate
```

In `LD_LIBRARY_PATH`, specify the directory containing the SGX HW version of
`libtwep_wr.so` produced in step 1. This command does not initialize state,
register manifests with AttesTAM, or run in the background. Use `Ctrl+C` to stop
it.

## Run the Demo

In another terminal, change to the checkout root and use the socket specified
when starting the daemon.

```sh
cd /path/to/twep-system
STATE_DIR="${TMPDIR:-/tmp}/twep-sgx-demo-state"

./bin/twep-cli --socket "$STATE_DIR/twepd.sock" helloworld
# Expected result: teep.verified_required

./bin/twep-cli --socket "$STATE_DIR/twepd.sock" helloworld
# Expected result: Hello, World!!

./bin/twep-cli --socket "$STATE_DIR/twepd.sock" calcadd 3 4 5
# Expected result: 12

./bin/twep-cli --socket "$STATE_DIR/twepd.sock" negaposi \
  -i testdata/images/input.jpg -o "$STATE_DIR/negaposi.jpg"
# Expected result: Saving a Reversed Color Image
```

With fresh state, the first `helloworld` invocation publishes the Catalog using
the verified Catalog TC and then exits with `teep.verified_required` as
intended. Running the same command again retrieves and executes the application.
The `negaposi` output is `$STATE_DIR/negaposi.jpg`.
