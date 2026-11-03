//! # abyss-common
//!
//! The shared memory contract between Abyss kernel modules (Ring 0)
//! and user-space components (daemon, CLI).
//!
//! Every type in this crate must:
//! - Compile under `#![no_std]` (no heap, no `String`, no `Vec`)
//! - Use `#[repr(C)]` for deterministic C-compatible memory layout
//! - Derive `Clone, Copy` (required for eBPF map values)
//!
//! The crate is organized into domain-specific modules:
//! - [`telemetry`] — Packet counters and per-packet event structs
//! - [`rate_limit`] — Map keys/values for the token-bucket rate limiter (abyss-tide)
//! - [`dpi`] — Signature pattern structs for deep packet inspection (abyss-gaze)
//! - [`dispatcher`] — Module slot indices and PROG_ARRAY constants (abyss-core)

#![no_std]

pub mod dispatcher;
pub mod dpi;
pub mod ip;
pub mod rate_limit;
pub mod telemetry;

// Re-export the most commonly used types at crate root for ergonomic imports.
pub use dispatcher::{ModuleSlot, ModuleStatus};
pub use dpi::{DpiAction, DpiSignature, MAX_SIGNATURES, MAX_SIGNATURE_LEN};
pub use ip::{parse_ipv4_addr, u32_to_octets};
pub use rate_limit::{RateLimitConfig, RateLimitKey, RateLimitValue};
pub use telemetry::{PacketCounters, PacketEvent, XdpVerdict};
