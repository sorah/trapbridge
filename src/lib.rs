//! trapbridge: receive SNMP traps, decode them with MIB data dumped to JSON,
//! and forward each one to Amazon EventBridge.

pub mod cmd;
pub mod config;
pub mod error;
pub mod http;
pub mod metrics;
pub mod mib;
#[cfg(feature = "mibs")]
pub mod mib_dump;
pub mod publisher;
pub mod receiver;
pub mod telemetry;
pub mod trap;
pub mod usm;

pub use crate::error::{Error, Result};
