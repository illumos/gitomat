pub(crate) mod prelude {
    pub use slog::{info, error, warn, debug, o};
    pub use std::io::Read;
    pub use serde::Deserialize;
    pub use anyhow::{bail, anyhow, Result};
    pub use std::result::Result as SResult;
    pub use tokio::sync::mpsc;
    pub use std::sync::Arc;
}
use prelude::*;

mod irc_client;
mod server;

#[derive(Deserialize, Clone)]
pub(crate) struct ConfigGithub {
    secret: String,
}

#[derive(Deserialize, Clone)]
pub(crate) struct ConfigIrc {
    channel: String,
    user: String,
    password: String,
    server: String,
    user_info: String,
    notify: Option<String>,
}

#[derive(Deserialize, Clone)]
pub(crate) struct ConfigToml {
    irc: ConfigIrc,
    github: ConfigGithub,
}

#[derive(Debug)]
pub(crate) enum Action {
    Message(String),
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.reqopt("f", "", "configuration file", "CONFIG_FILE");
    opts.optflag("d", "", "debug log");

    let opts = opts.parse(std::env::args().skip(1))?;
    if !opts.free.is_empty() {
        bail!("unexpected arguments: {:?}", opts.free);
    }

    let config: ConfigToml = {
        let mut f = std::fs::File::open(opts.opt_str("f").unwrap())?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        toml::from_slice(&buf)?
    };

    let log = dropshot::ConfigLogging::StderrTerminal {
        level: if opts.opt_present("d") {
            dropshot::ConfigLoggingLevel::Debug
        } else {
            dropshot::ConfigLoggingLevel::Info
        },
    }
    .to_logger("gitomat")?;

    let (tx, mut rx) = mpsc::channel::<Action>(16);

    let log0 = log.new(o!("component" => "irc"));
    let config0 = config.clone();
    let task_irc = tokio::spawn(async move {
        let log = log0;
        info!(log, "IRC task started");
        loop {
            info!(log, "connecting to IRC");
            if let Err(e) = irc_client::irc(&log, &mut rx, &config0.irc).await {
                error!(log, "IRC error: {:?}", e);
            } else {
                error!(log, "IRC connection terminated unexpectedly");
            }

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });

    let log0 = log.new(o!("component" => "server"));
    let task_server = server::start_server(log0, tx, &config.github).await?;

    loop {
        tokio::select! {
            _ = task_irc => {
                bail!("task IRC should not end");
            }
            _ = task_server => {
                bail!("task server should not end");
            }
        }
    }
}
