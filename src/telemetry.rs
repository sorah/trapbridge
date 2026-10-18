//! tracing-subscriber setup: env-filtered fmt output for humans, JSON for
//! production.

/// Initialize the global tracing subscriber. The filter comes from
/// `TRAPBRIDGE_LOG`, then `RUST_LOG`, then defaults to `info`. Logs go to
/// stderr so stdout stays free for `--dry-run` events and `mib-dump` output.
pub fn init(json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("TRAPBRIDGE_LOG")
        .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}
