//! `trapbridge mib-dump`: export installed MIBs to JSON for `server --mib-json`.

/// Arguments for `trapbridge mib-dump`.
#[derive(Debug, clap::Args)]
pub struct MibDumpArgs {
    /// Dump configuration file. Without one, every notification is exported.
    #[arg(long)]
    pub config: Option<std::path::PathBuf>,
    /// MIB search directory; overrides `mib_dirs` in the configuration.
    #[arg(long = "mib-dir", env = "MIBDIRS", value_delimiter = ':')]
    pub mib_dirs: Vec<String>,
    /// Output file; stdout when omitted.
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,
    /// Fail when net-snmp reports MIB parse errors.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub fail_on_parse_errors: bool,
}

pub fn run(args: &MibDumpArgs) -> Result<(), anyhow::Error> {
    use std::io::Write as _;
    let config = match &args.config {
        Some(path) => crate::mib_dump::MibDumpConfig::load(path)?,
        None => crate::mib_dump::MibDumpConfig::default(),
    };
    let mib_dirs = if args.mib_dirs.is_empty() {
        &config.mib_dirs
    } else {
        &args.mib_dirs
    };
    let tree = crate::mib_dump::MibTree::load(mib_dirs, &config.modules)?;
    for line in &tree.parse_errors {
        tracing::warn!(message = line, "MIB parse error");
    }
    if args.fail_on_parse_errors && !tree.parse_errors.is_empty() {
        tracing::error!(
            count = tree.parse_errors.len(),
            "MIB parse errors found; pass --fail-on-parse-errors=false to ignore"
        );
        return Err(crate::Error::SilentlyExitWithCode(std::process::ExitCode::FAILURE).into());
    }

    let out = tree.export(&config)?;
    tracing::info!(
        loaded = tree.nodes.len(),
        exported = out.nodes.len(),
        "dumped MIB"
    );
    let mut writer: Box<dyn std::io::Write> = match &args.output {
        Some(path) => Box::new(std::io::BufWriter::new(std::fs::File::create(path)?)),
        None => Box::new(std::io::stdout().lock()),
    };
    serde_json::to_writer_pretty(&mut writer, &out)?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}
