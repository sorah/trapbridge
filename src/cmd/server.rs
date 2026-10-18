//! `trapbridge server`: listen for traps and forward them until terminated.

/// Arguments for `trapbridge server`.
#[derive(Debug, clap::Args)]
pub struct ServerArgs {
    /// UDP addresses to listen on.
    #[arg(
        long,
        env = "TRAPBRIDGE_LISTEN",
        value_delimiter = ',',
        default_value = "0.0.0.0:162"
    )]
    pub listen: Vec<std::net::SocketAddr>,
    /// JSON configuration file (communities, SNMPv3 users).
    #[arg(long, env = "TRAPBRIDGE_CONFIG")]
    pub config: Option<std::path::PathBuf>,
    /// MIB JSON files produced by `trapbridge mib-dump`.
    #[arg(long = "mib-json", env = "TRAPBRIDGE_MIB_JSON", value_delimiter = ',')]
    pub mib_json: Vec<std::path::PathBuf>,
    /// Accepted SNMPv1/v2c community. Any community is accepted when none is
    /// given here or in the configuration file.
    #[arg(
        long = "community",
        env = "TRAPBRIDGE_COMMUNITIES",
        value_delimiter = ','
    )]
    pub communities: Vec<String>,
    /// EventBridge event bus name or ARN.
    #[arg(
        long,
        env = "TRAPBRIDGE_EVENT_BUS",
        required_unless_present = "dry_run"
    )]
    pub event_bus: Option<String>,
    /// Event `source`.
    #[arg(
        long,
        env = "TRAPBRIDGE_EVENT_SOURCE",
        default_value = "trapbridge.0w0.co"
    )]
    pub event_source: String,
    /// Event `detail-type`.
    #[arg(long, env = "TRAPBRIDGE_DETAIL_TYPE", default_value = "SNMP Trap")]
    pub detail_type: String,
    /// Add the reverse DNS name of the sender to `detail.source.hostname`.
    #[arg(
        long,
        env = "TRAPBRIDGE_RESOLVE_SOURCE",
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_value_t = true,
        default_missing_value = "true"
    )]
    pub resolve_source: bool,
    /// Timeout of one reverse DNS lookup, in seconds.
    #[arg(long, env = "TRAPBRIDGE_RESOLVE_SOURCE_TIMEOUT", default_value_t = 2)]
    pub resolve_source_timeout: u64,
    /// Upper bound of how long a reverse DNS answer is cached, in seconds. Shorter record TTLs win.
    #[arg(long, env = "TRAPBRIDGE_RESOLVE_SOURCE_MAX_TTL", default_value_t = 300)]
    pub resolve_source_max_ttl: u64,
    /// Print events to stdout as JSON lines instead of sending them.
    #[arg(long, env = "TRAPBRIDGE_DRY_RUN")]
    pub dry_run: bool,
    /// TCP address for the HTTP listener serving /healthz and /metrics.
    #[arg(long, env = "TRAPBRIDGE_HTTP_LISTEN")]
    pub http_listen: Option<std::net::SocketAddr>,
}

#[tokio::main]
pub async fn run(args: &ServerArgs) -> Result<(), anyhow::Error> {
    let config = match &args.config {
        Some(path) => crate::config::Config::load(path)?,
        None => crate::config::Config::default(),
    };
    let mib = std::sync::Arc::new(crate::mib::MibDatabase::load(&args.mib_json)?);
    let usm = crate::usm::SecurityStore::new(&config.v3_users)?;
    let communities = config
        .communities
        .iter()
        .chain(&args.communities)
        .cloned()
        .collect::<Vec<_>>();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        mib_nodes = mib.len(),
        communities = communities.len(),
        v3_users = config.v3_users.len(),
        dry_run = args.dry_run,
        "starting trapbridge"
    );
    let decoder = std::sync::Arc::new(crate::receiver::Decoder::new(communities, usm, mib));
    let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());

    let publisher = if args.dry_run {
        crate::publisher::Publisher::Stdout(metrics.clone())
    } else {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        crate::publisher::Publisher::EventBridge(crate::publisher::EventBridgePublisher::new(
            aws_sdk_eventbridge::Client::new(&sdk_config),
            args.event_bus.clone().expect("required by clap"),
            args.event_source.clone(),
            args.detail_type.clone(),
            metrics.clone(),
        ))
    };

    let reverse_dns = if args.resolve_source {
        Some(std::sync::Arc::new(crate::reverse_dns::ReverseDns::new(
            std::time::Duration::from_secs(args.resolve_source_timeout),
            std::time::Duration::from_secs(args.resolve_source_max_ttl),
        )?))
    } else {
        None
    };

    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    let mut listeners = tokio::task::JoinSet::new();
    for addr in &args.listen {
        let socket = crate::receiver::bind(*addr).await?;
        listeners.spawn(crate::receiver::run(
            socket,
            decoder.clone(),
            tx.clone(),
            metrics.clone(),
            reverse_dns.clone(),
        ));
    }
    if let Some(addr) = args.http_listen {
        let listener = crate::http::bind(addr).await?;
        listeners.spawn(crate::http::serve(listener, metrics.clone()));
    }
    drop(tx);
    let publisher_task = tokio::spawn(async move { publisher.run(rx).await });

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = tokio::select! {
        r = tokio::signal::ctrl_c() => {
            r?;
            tracing::info!(signal = "SIGINT", "shutting down");
            Ok(())
        }
        _ = sigterm.recv() => {
            tracing::info!(signal = "SIGTERM", "shutting down");
            Ok(())
        }
        joined = listeners.join_next() => Err(listener_exit_error(joined)),
    };
    // Dropping the listeners closes the channel, so the publisher flushes and exits.
    listeners.shutdown().await;
    publisher_task.await?;
    result.map_err(Into::into)
}

/// Listeners loop forever, so any exit is fatal.
fn listener_exit_error(
    joined: Option<Result<crate::Result<()>, tokio::task::JoinError>>,
) -> crate::Error {
    match joined {
        Some(Ok(Err(e))) => e,
        Some(Ok(Ok(()))) => crate::Error::Other("listener exited unexpectedly".to_owned()),
        Some(Err(e)) => crate::Error::Other(format!("listener task failed: {e}")),
        None => crate::Error::Other("no listeners configured".to_owned()),
    }
}
