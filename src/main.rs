//! Thin CLI entrypoint: parse arguments, initialize telemetry, dispatch into
//! `trapbridge::cmd`, and translate `SilentlyExitWithCode` into a process exit
//! code.

/// trapbridge: SNMP traps to Amazon EventBridge.
#[derive(clap::Parser)]
#[command(name = "trapbridge", version)]
struct Cli {
    /// Emit logs as JSON.
    #[arg(long, global = true, env = "TRAPBRIDGE_LOG_JSON")]
    log_json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Receive SNMP traps and forward them to EventBridge.
    Server(trapbridge::cmd::server::ServerArgs),
    /// Dump installed MIBs to JSON for `server --mib-json`.
    #[cfg(feature = "mibs")]
    MibDump(trapbridge::cmd::mib_dump::MibDumpArgs),
}

fn main() -> Result<std::process::ExitCode, anyhow::Error> {
    let cli = <Cli as clap::Parser>::parse();
    trapbridge::telemetry::init(cli.log_json);
    let retval = match &cli.command {
        Command::Server(args) => trapbridge::cmd::server::run(args),
        #[cfg(feature = "mibs")]
        Command::MibDump(args) => trapbridge::cmd::mib_dump::run(args),
    };
    match retval {
        Ok(()) => Ok(std::process::ExitCode::SUCCESS),
        Err(e) => match e.downcast_ref::<trapbridge::Error>() {
            Some(trapbridge::Error::SilentlyExitWithCode(c)) => Ok(*c),
            _ => Err(e),
        },
    }
}
