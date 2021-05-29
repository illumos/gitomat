use anyhow::{bail, Result};
use serde::Deserialize;
use std::io::Read;

mod irc_client;

#[derive(Deserialize)]
pub(crate) struct ConfigIrc {
    channel: String,
    user: String,
    password: String,
    server: String,
    user_info: String,
}

#[derive(Deserialize)]
pub(crate) struct ConfigToml {
    irc: ConfigIrc,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.reqopt("f", "", "configuration file", "CONFIG_FILE");

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

    let task_irc = tokio::spawn(async move {
        loop {
            println!();
            println!("STARTING IRC TASK...");
            println!();
            if let Err(e) = irc_client::irc(&config.irc).await {
                println!("ERROR: irc: {:?}", e);
            } else {
                println!("ERROR: irc() terminated unexpectedly");
            }

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });

    loop {
        tokio::select! {
            _ = task_irc => {
                bail!("task IRC should not end");
            }
        }
    }
}
