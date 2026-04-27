---
title: "ADR-0053: tonic for gRPC admin-RPC"
status: accepted
date: 2026-04-27
deciders: [FlavioCFOliveira]
---

# ADR-0053: tonic for gRPC admin-RPC

## Context

OPS-033 mandates gRPC over Protocol Buffers for the admin-RPC surface. tonic v0.12
is the de-facto standard gRPC library for Rust, backed by the Tokio project.

Sprint 33 implements the admin-RPC surface as a **length-prefix-framed JSON
protocol over Unix Domain Socket** as an accepted interim: the `build.rs`
complexity of proto compilation is deferred so that the rest of Sprint 33 can
ship on schedule.

## Decision

Use `tonic = "0.12"` for the admin-RPC gRPC server (OPS-033) in a future sprint.
The JSON-over-UDS implementation in Sprint 33 is explicitly marked as interim and
**must be replaced** once proto compilation is wired in.

## Consequences

- `prost = "0.13"` is required as a companion (ADR-0054).
- `build.rs` + `tonic-build` will be added for `.proto` compilation in the
  migration sprint.
- Current JSON-over-UDS admin-RPC is a Sprint 33 interim; it **must** be replaced
  before a stable release.
- The UDS socket and wire-protocol shape will change; existing clients using the
  JSON framing must be updated when the gRPC migration lands.
