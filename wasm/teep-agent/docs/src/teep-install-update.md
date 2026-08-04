# Install and Update via TEEP

This chapter explains how `attestam-insecure` installs or updates a Wasm app
into the local state directory. In final verified mode, even if the same
artifacts are observed, the flow does not proceed to app promotion or Catalog
updates until the verification conditions are satisfied.

## Entry Point

`session::run_resolve_app` first prepares to write a `target_command=<command>\n`
probe and then calls the random/time hostcalls. If `attestam_url` is not empty,
it calls `run_attestam_session`.

The return value from the AttesTAM session has the following meaning:

| Return value | Meaning | Next action |
| --- | --- | --- |
| `Ok(Some(true))` | Processed a TC that can be installed as an app or Catalog | Continue to Catalog resolution |
| `Ok(Some(false))` | The TEEP session progressed, but it was not a general Wasm app | Return a `teep.protocol` error |
| `Ok(None)` | Session did not establish, for example because there was no HTTP response | Fall back to existing Catalog resolution |
| `Err(code)` | Protocol / network / host-I/O error | Return that code |

## Receiving QueryRequest

`run_attestam_session` posts an empty body to `attestam_url`. The hostcall
status is handled as follows:

| status | handling |
| --- | --- |
| `0` | Success. Process the body as COSE_Sign1 |
| `2` | Response too large. Treat as session not established and allow fallback |
| `5` | Network error. Return `teep.network` |
| other | Internal error `127` |

The successful body is processed through
`cose::outer_teep_cose_sign1_payload_unverified`. The insecure flow does not
perform a final verification of the outer COSE signature, so the function name
reflects the unverified path. If the payload is not a TEEP QueryRequest, stop
with a `teep.protocol` error.

Observed artifacts:

- `teep-agent/last-teep-response.cose`
- `teep-agent/last-teep-payload.cbor`
- `teep-agent/last-teep-message-type.txt`

## QueryResponse Generation

`sign_query_response` builds the QueryResponse payload with
`build_query_response_payload` and signs it with
`cose::sign_demo_agent_esp256_cose_sign1`.

If the QueryRequest has no attestation challenge:

1. `teep::query_response_payload` reads token option `19`.
2. The requested component id is added to the requested TC list.
3. The token is returned in the QueryResponse.
4. The payload is signed with the development agent key.

If the QueryRequest has an attestation challenge:

1. `evidence::query_request_challenge` reads the challenge.
2. `session::demo_agent_public_key` chooses the agent public COSE_Key.
3. `evidence::create_eat_evidence` constructs the Generic EAT and signs it with
   the fixed development ES256 Evidence key inside the Rust TEEP_Agent.
4. `teep::query_response_payload_with_attestation` builds the payload with evidence.
5. The payload is signed with the development agent key.

If `teep-agent/dev-agent-public-key.cbor` exists, the alternate development
signer is used. This is a development feature for observing real AttesTAM
challenges and is not a final verified trust anchor.

## Update Processing

If the response to the QueryResponse POST is an Update,
`process_update_payload` is called.

```text
process_update_payload
  |
  +-- observe_update_manifest_summary
  +-- suit::teep_update_candidate(update, requested_component_id)
  |     +-- extract manifest-list
  |     +-- parse SUIT envelope / manifest
  |     +-- confirm requested component id match
  |     +-- verify integrated payload SHA-256
  |     +-- obtain update token
  |
  +-- write_update_candidate_observation_or_127
  +-- stage_update_or_127
  +-- post_success
```

`suit::teep_update_candidate` extracts the first manifest from Update message
option `9`'s manifest-list. The following are read from the SUIT envelope:

| Information | Source |
| --- | --- |
| `component_id` | SUIT common components |
| `sequence_number` | SUIT manifest key `2` |
| `payload_digest` | Digest parameter in the shared sequence |
| `payload_uri` | payload-fetch sequence |
| integrated payload | Text keys such as `#payload` in the SUIT envelope |
| update token | TEEP Update option `19` |

The payload digest is treated as a SUIT digest structure `[ -16, sha256 ]` and
must match the actual SHA-256 of the integrated payload, otherwise the flow
stops with `PayloadHashMismatch`.

## Component-id Classification

`suit::component_kind_and_name` recognizes only the following SUIT Component
Identifier forms:

| prefix | kind | install destination |
| --- | --- | --- |
| `twep-app-v1` | App | `apps/<command>.wasm` |
| `twep-catalog-v1` | Catalog | `catalog/catalog.cbor` |
| others | Unsupported | Reject before staging or installation |

App commands and catalog names are ASCII letters and digits plus `-`, `_`,
with a maximum of 32 bytes. Do not promote payload names containing `../` or
slashes into Wasm app paths.

## Staging

If the Update candidate is valid, write staging artifacts first.

| path | content |
| --- | --- |
| `tmp/update-payload-0.bin` | integrated payload |
| `tmp/update-staging-metadata.cbor` | component id, sequence, payload URI, payload path, SHA-256 |
| `tmp/update-staging-status.txt` | `staging=ready` |

At the same time, write diagnostic `teep-agent/update-*` artifacts. These are
observation data used by E2E and manual diagnostics to understand how far the
TEEP session progressed.

## Success Send and Freshness

`post_success` builds a TEEP Success payload containing a SUIT report with
`suit::success_response_payload`, signs it with the development agent key, and
POSTs it to AttesTAM. Before the Success POST, `session::dev_sequence_is_fresh`
checks sequence freshness.

Freshness checking happens in this order:

1. If the protected object `protected-sequence-freshness.cbor` is readable, use it.
2. Otherwise use the development file `teep-agent/dev-sequence-freshness.cbor`.
3. Treat the sequence as fresh only if it is larger than the existing value.

If the Success POST finishes with NoContent, update the development freshness
map and continue to installation.

## Install and Promotion

`install_payload` decides the final storage location by component kind using
`suit::installed_payload_path`.

| kind | payload destination | additional action |
| --- | --- | --- |
| App | `apps/<command>.wasm` | Generate an insecure development Catalog |
| Catalog | `catalog/catalog.cbor` | Save as Catalog payload |
| Unsupported | none | Rejected before this function is reached |

For successful App and Catalog installations, write
`components/install-metadata.cbor` and `components/install-status.txt`. For
apps in insecure mode, `promoted_app_catalog` builds the minimal development
Catalog. Final verified mode instead requires a separately verified Catalog TC.

The generated app Catalog looks like this:

```text
{
  "schema_version": 1,
  "source": "attestam-insecure",
  "apps": {
    "<command>": {
      "component_id": "twep-app-v1:<command>",
      "version": "0.1.0",
      "abi": "twep-app-v1",
      "wasm_file": "<command>.wasm",
      "sha256": <payload_sha256>
    }
  }
}
```

This Catalog promotion is development behavior for `attestam-insecure`. In
final verified mode, the Catalog File update basis must be a `twep-catalog-v1`
Catalog TC, and debug JSON or app TCs must not be trusted as the Catalog basis.

## Final Resolution

After installation finishes, `run_resolve_app` reads `catalog/catalog.cbor`
again and resolves the target command with `catalog::resolve_from_catalog`.
Only after `apps/<command>.wasm` matches the Catalog entry hash does the host
receive `wasm_file` and the hash.

In other words, receiving a TEEP Update alone does not make it runnable. Only
after storage, metadata, freshness, Success completion, Catalog resolution, and
app-hash verification are all in place does the flow proceed to local
execution.
