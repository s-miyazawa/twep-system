# References.md: Reference Materials

## KISS / DRY

Manage reference materials with KISS and DRY. When the same external specification or local repository path needs to be referenced from multiple documents, use this document as the index and write only the necessary references in each specification document. Put implementation decisions in the relevant authoritative specification, not in the reference material itself.

## TEEP / Attestation

- RFC 9397: Trusted Execution Environment Provisioning (TEEP) Architecture
  - https://datatracker.ietf.org/doc/html/rfc9397
- draft-ietf-teep-protocol-26: Trusted Execution Environment Provisioning (TEEP) Protocol
  - https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-26
  - latest draft entry: https://datatracker.ietf.org/doc/draft-ietf-teep-protocol/
- HTTP Transport for TEEP: Agent Initiated Communication
  - https://datatracker.ietf.org/doc/html/draft-ietf-teep-otrp-over-http-15
  - latest draft entry: https://datatracker.ietf.org/doc/draft-ietf-teep-otrp-over-http/
- draft-ietf-suit-manifest-34: A Concise Binary Object Representation (CBOR)-based Serialization Format for the Software Updates for Internet of Things (SUIT) Manifest
  - https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/
  - Use this as the basis for SUIT Envelope, Authentication Block, Manifest, Common, Command Sequences, Integrated Payloads, Manifest Processor Behavior, and Required Checks.

## Implementation References

- AttesTAM
  - https://github.com/kentakayama/AttesTAM
  - local checkout under the user's home directory
  - local runbook: `docs/AttesTAM.md`
- Veraison
  - https://github.com/veraison/veraison
  - local checkout under the user's home directory
  - local native deployment under the user's home directory
  - Use this as the Verifier for AttesTAM challenge-response. For Generic EAT schemes and trust-anchor / endorsement provisioning, refer to the corresponding files in the local Veraison checkout.
- TAWS
  - https://github.com/yuma-nishi/taws
  - local checkout under the user's home directory
- wasm-micro-runtime (WAMR)
  - https://github.com/bytecodealliance/wasm-micro-runtime
  - local checkout under the user's home directory
- coset
  - https://crates.io/crates/coset
  - https://github.com/google/coset
  - The first-choice crate for implementing COSE generation and verification in the future TEE-resident Rust TEEP_Agent.

## Design Notes

- Reference AttesTAM as a TAM server implementation that aims to conform to the TEEP Protocol draft and the TEEP-over-HTTP draft. If its communication payloads or payload handling diverge from twep, make the twep side match AttesTAM.
- Reference Veraison as the verifier for EAT Evidence forwarded by AttesTAM. For mock EAT Evidence in twep to become affirming through AttesTAM, the Veraison side needs trust-anchor / endorsement provisioning that matches the Generic EAT scheme.
- Reference TAWS as an example implementation of a Wasm-oriented TEEP Agent and SGX simulation mode.
- Reference WAMR as the Wasm runtime embedded in `twep-wr.so`.
- Use the IETF TEEP protocol as the basis for the message model of CBOR/COSE, QueryRequest, QueryResponse, Update, Success, and Error.
- Use the IETF SUIT manifest draft as the basis for SUIT Envelope, Authentication Block, manifest processing, sequence number, payload digest, integrated payload, and manifest processor behavior.
- For CBOR handling in the TEE-resident Rust TEEP_Agent, use the `ciborium` crate. For COSE handling, use the `coset` crate. For cryptographic and signature primitives needed by `coset`, refer first to crates described by the RustCrypto project (<https://github.com/rustcrypto>) and only implement the algorithms supported by AttesTAM.
- RFC 9397 is the basis for the terms and architecture of TAM, TEEP Agent, Broker, Trusted Component, and TEE.

## Internal Specs

- `docs/ABI.md`: Trusted Wasm App ABI, TEEP_Agent ABI, hostcall policy, and the IDL transition policy
