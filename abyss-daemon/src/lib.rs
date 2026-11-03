//! # abyss-daemon library
//!
//! Exposes configuration, bytecode loading, attachment, module linking,
//! and telemetry polling modules.

pub mod attach;
pub mod config;
pub mod loader;
pub mod modules;
pub mod pinning;
pub mod telemetry;
