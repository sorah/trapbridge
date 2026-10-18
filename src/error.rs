//! Crate-wide error type. Library code returns [`crate::Error`]; `anyhow` is
//! reserved for the CLI boundary (`main.rs`, `src/cmd/*`).

/// Errors produced by trapbridge's library code.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Invalid or inconsistent configuration.
    #[error("configuration error: {0}")]
    Config(String),
    /// Malformed SNMP message.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// v1/v2c message with a community that is not accepted.
    #[error("community not accepted")]
    CommunityRejected,
    /// SNMPv3 message that no configured user can authenticate.
    #[error("USM error: {0}")]
    Usm(String),
    /// Well-formed SNMP message that trapbridge does not handle.
    #[error("unsupported: {0}")]
    Unsupported(String),
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
    /// Event over the EventBridge entry size limit.
    #[error("event is {size} bytes, over the {limit} byte EventBridge limit")]
    EventTooLarge { size: usize, limit: usize },
    /// Anything else.
    #[error("{0}")]
    Other(String),
    /// Exit the process with the given code without printing anything more.
    #[error("silently exit")]
    SilentlyExitWithCode(std::process::ExitCode),
}

impl Error {
    /// Why a received message was dropped, for `trapbridge_dropped_total`.
    pub fn drop_reason(&self) -> crate::metrics::DropReason {
        match self {
            Error::CommunityRejected | Error::Snmp(snmp2::Error::CommunityMismatch) => {
                crate::metrics::DropReason::Community
            }
            Error::Usm(_)
            | Error::Snmp(
                snmp2::Error::AuthFailure(_) | snmp2::Error::Crypto(_) | snmp2::Error::AuthUpdated,
            ) => crate::metrics::DropReason::Usm,
            Error::Unsupported(_) | Error::Snmp(snmp2::Error::UnsupportedVersion) => {
                crate::metrics::DropReason::Unsupported
            }
            _ => crate::metrics::DropReason::Parse,
        }
    }
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;
