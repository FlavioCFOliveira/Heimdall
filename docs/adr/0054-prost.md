---
title: "ADR-0054: prost for Protocol Buffers encoding"
status: accepted
date: 2026-04-27
deciders: [FlavioCFOliveira]
---

# ADR-0054: prost for Protocol Buffers encoding

## Context

tonic (ADR-0053) requires prost for protobuf encoding and decoding. prost v0.13
is the canonical companion to tonic v0.12; the two are co-maintained by the Tokio
project and their version numbers are aligned intentionally.

Sprint 33 does not yet add prost as a dependency because the admin-RPC is
implemented as JSON-over-UDS (ADR-0053 interim). prost will be introduced in the
same sprint that performs the gRPC migration.

## Decision

Use `prost = "0.13"` as the protobuf encoder/decoder for the admin-RPC service
when the gRPC migration sprint lands.

## Consequences

- Added alongside tonic in the gRPC migration sprint.
- `prost-build` or `tonic-build` will generate Rust structs from `.proto` files
  at compile time via `build.rs`.
- The current Sprint 33 JSON protocol will be replaced entirely; no compatibility
  layer is planned.
- Supply-chain impact: prost has a minimal set of dependencies and is widely used
  in the Rust ecosystem.
