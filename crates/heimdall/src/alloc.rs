// SPDX-License-Identifier: MIT

//! Global allocator selection (BIN-039, BIN-040, ADR-0062).
//!
//! Exactly one allocator is active per binary build.  Selection is controlled by
//! Cargo feature flags:
//!
//! | Feature      | Allocator                 | Recommended use               |
//! |-------------|--------------------------|-------------------------------|
//! | `mimalloc`  | Microsoft mimalloc        | Default — production release  |
//! | `jemalloc`  | jemalloc (tikv)           | Alternative for Linux tuning  |
//! | *(neither)* | OS default (glibc/macOS)  | Minimal dependency surface    |
//!
//! Enabling both `mimalloc` and `jemalloc` simultaneously is a compile error.

#[cfg(all(feature = "mimalloc", feature = "jemalloc"))]
compile_error!(
    "features `mimalloc` and `jemalloc` are mutually exclusive; \
     enable at most one allocator feature"
);

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "jemalloc", not(feature = "mimalloc")))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
