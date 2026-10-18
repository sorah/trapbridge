//! Crate-wide error type. Library code returns [`crate::Error`]; `anyhow` is
//! reserved for the CLI boundary (`main.rs`, `src/cmd/*`).

/// Errors produced by trapbridge's library code.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Invalid or inconsistent configuration.
    #[error("configuration error: {0}")]
    Config(String),
    /// Malformed or unacceptable SNMP message.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Error reported by the snmp2 crate.
    #[error(transparent)]
    Snmp(#[from] snmp2::Error),
    /// MIB loading or MIB data error.
    #[error("MIB error: {0}")]
    Mib(String),
    /// I/O error (sockets, files).
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON encoding or decoding error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Anything else.
    #[error("{0}")]
    Other(String),
    /// Exit the process with the given code without printing anything more.
    #[error("silently exit")]
    SilentlyExitWithCode(std::process::ExitCode),
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;
