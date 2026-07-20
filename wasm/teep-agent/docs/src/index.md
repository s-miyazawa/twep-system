# Overview

`wasm/teep-agent` is the special TEEP Agent among twep's Trusted Wasm Apps. It
shares the same `twep-app-v1` exported ABI as a normal user app, but it is a
management-oriented Wasm that handles Catalog File resolution, AttesTAM
development sessions, TEEP / COSE / SUIT parsing, Trusted Component payload
verification, Wasm app promotion into the cache, and verified-mode
observation.

This document explains the structure and behavior of `wasm/teep-agent` as an
implementation, especially the flow for installing or updating Wasm apps into a
local environment through the TEEP protocol.

## Role

The main responsibilities of the TEEP Agent are:

- Build a `twep-app-v1` SUIT Component Identifier from `target_command`.
- Read `catalog/catalog.cbor` from the state directory and resolve the catalog
  entry for the target command.
- Read `apps/<wasm_file>` and verify that it matches the catalog entry's
  SHA-256.
- In `attestam-insecure` mode, run a TEEP session against an AttesTAM endpoint.
- Extract the manifest, component id, sequence number, payload URI, payload
  digest, and integrated payload from the Update SUIT envelope.
- Verify the payload SHA-256, write it to staging, and then return Success.
- When Success completes with NoContent, install the payload into `apps/` or
  `catalog/`.
- Generate a development catalog and promote an app only for `twep-app-v1` app
  TCs.
- In `attestam-verified` mode, remain limited to observation and diagnostic
  artifact generation until the final verification conditions are met.

## Canonical Specifications

The behavior of this crate is not defined in isolation. The following root
documents are the source of truth for boundaries and schemas:

- `docs/ABI.md`: `twep-app-v1` export ABI, TEEP Agent command schema, hostcall
  policy.
- `docs/Architecture.md`: responsibility split across twep.
- `docs/AttesTAM.md`: AttesTAM integration and development flows.

This mdBook is a detailed code-reading aid, not a document that changes the ABI
or the trust model.
