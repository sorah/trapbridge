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
    /// Print events to stdout as JSON lines instead of sending them.
    #[arg(long, env = "TRAPBRIDGE_DRY_RUN")]
    pub dry_run: bool,
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

    let publisher = if args.dry_run {
        crate::publisher::Publisher::Stdout
    } else {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        crate::publisher::Publisher::EventBridge(crate::publisher::EventBridgePublisher::new(
            aws_sdk_eventbridge::Client::new(&sdk_config),
            args.event_bus.clone().expect("required by clap"),
            args.event_source.clone(),
            args.detail_type.clone(),
        ))
    };

    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    let mut listeners = tokio::task::JoinSet::new();
    for addr in &args.listen {
        let socket = crate::receiver::bind(*addr).await?;
        listeners.spawn(crate::receiver::run(socket, decoder.clone(), tx.clone()));
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
