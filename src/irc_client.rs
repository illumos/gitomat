use anyhow::{bail, Result};
use futures::prelude::*;
use std::time::Duration;

use super::ConfigIrc;

fn s(s: &str) -> Option<String> {
    Some(s.to_string())
}

/**
 * Append n underscores to the end of a string, for use in alternate nickname
 * construction.
 */
fn us(s: &str, n: usize) -> String {
    let mut s = s.to_string();
    for _ in 0..n {
        s.push('_');
    }
    s
}

enum State {
    Start,
    WaitSaslCap,
    WaitSaslPlus,
    WaitSaslResult,
    WaitRegister,
    WaitGhost,
    WaitNick,
    WaitJoin,
    Online,
}

async fn irc_msg(
    toml: &ConfigIrc,
    client: &irc::client::Client,
    s: State,
    m: &irc::proto::Message,
) -> Result<State> {
    println!("{:?}", m);

    match s {
        State::Start => {
            use irc::proto::Capability;

            /*
             * Before we begin the usual identification sequence, we must
             * complete SASL authentication.  This is a hard requirement
             * enforced by the network for connections that come from cloud
             * providers for spam reduction purposes.
             */
            client.send_cap_req(&[Capability::Sasl])?;
            return Ok(State::WaitSaslCap);
        }
        State::WaitSaslCap => {
            use irc::proto::Command::CAP;
            use irc::proto::CapSubCommand::ACK;

            if let CAP(Some(star), cmd, Some(cap), _) = &m.command {
                if cap.as_str() == "sasl" {
                    if star.as_str() != "*" {
                        bail!("expected *? {:?}", m);
                    }

                    match cmd {
                        ACK => {
                            println!("--- OK, SASL!");
                            /*
                             * Negotiate the use of the SASL PLAIN
                             * mechanism.
                             */
                            client.send_sasl_plain()?;
                            return Ok(State::WaitSaslPlus);
                        }
                        _ => {
                            bail!("OH DEAR, NO SASL? {:?}", m);
                        }
                    }
                }
            }
        }
        State::WaitSaslPlus => {
            use irc::proto::Command::AUTHENTICATE;

            if let AUTHENTICATE(d) = &m.command {
                if d.as_str() == "+" {
                    let sasl_plain = base64::encode(format!(
                        "{}\0{}\0{}",
                        toml.user, toml.user, toml.password,
                    ));

                    println!("--- SASL PLAIN AUTH...");
                    client.send_sasl(&sasl_plain)?;
                    return Ok(State::WaitSaslResult);
                } else {
                    bail!("SASL PLAIN not supported?");
                }
            }
        }
        State::WaitSaslResult => {
            use irc::proto::Command::Response;
            use irc::proto::Response::{RPL_SASLSUCCESS, ERR_SASLFAIL};

            match &m.command {
                Response(RPL_SASLSUCCESS, _) => {
                    println!("--- SASL OK!");
                    client.identify()?;
                    return Ok(State::WaitRegister);
                }
                Response(ERR_SASLFAIL, _) => {
                    bail!("SASL authentication failure: {:?}", m);
                }
                _ => {}
            }
        }
        State::WaitRegister => {
            use irc::proto::Command::Response;
            use irc::proto::Response::RPL_ENDOFMOTD;

            if let Response(RPL_ENDOFMOTD, args) = &m.command {
                println!("---- END OF MOTD DETECTED!");
                if let Some(nick) = args.iter().next() {
                    if nick.as_str() == &toml.user {
                        println!("--- JOINING");
                        client.send_join(&toml.channel)?;
                        return Ok(State::WaitJoin);
                    } else {
                        println!("---- WRONG NICK ({})! GHOST...", nick);
                        client.send_privmsg(
                            "NickServ",
                            format!("GHOST {}", toml.user),
                        )?;
                        return Ok(State::WaitGhost);
                    }
                } else {
                    bail!("no nick in end of motd? {:?}", m);
                }
            }
        }
        State::WaitGhost => {
            use irc::proto::Command::NOTICE;
            use irc::proto::Prefix::Nickname;

            if let Some(Nickname(n, _, _)) = &m.prefix {
                if n == "NickServ" {
                    match &m.command {
                        NOTICE(_, msg) => {
                            if msg.contains("has been ghosted") {
                                use irc::proto::Command::NICK;
                                println!("---- CHANGING NICK");
                                client.send(NICK(toml.user.to_string()))?;
                                return Ok(State::WaitNick);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        State::WaitNick => {
            use irc::proto::Command::NICK;

            match &m.command {
                NICK(newnick) => {
                    if newnick.as_str() == &toml.user {
                        /*
                         * XXX we should check the old nick I guess?
                         */
                        println!("---- NICK OK NOW");

                        println!("--- JOINING");
                        client.send_join(&toml.channel)?;
                        return Ok(State::WaitJoin);
                    } else {
                        bail!("unexpected new nick? {:?}", m);
                    }
                }
                /*
                 * XXX should handle nickname errors here
                 */
                _ => {}
            }
        }
        State::WaitJoin => {
            use irc::proto::Command::JOIN;

            if let JOIN(chan, _, _) = &m.command {
                if chan != &toml.channel {
                    bail!("unexpected channel? {:?}", m);
                }

                println!("----- JOIN detected!");
                client.send_privmsg(&toml.channel, "test")?;

                println!("----- ONLINE");
                return Ok(State::Online);
            }
        }
        State::Online => {}
    }

    Ok(s)
}

pub(crate) async fn irc(toml: &ConfigIrc) -> Result<()> {
    let cfg = irc::client::data::Config {
        nickname: s(&toml.user),
        alt_nicks: vec![us(&toml.user, 1), us(&toml.user, 2)],
        username: s(&toml.user),
        realname: s(&toml.user),
        server: s(&toml.server),
        port: Some(6697),
        use_tls: Some(true),
        user_info: s(&toml.user_info),
        version: s("gitomat 2.0"),
        ..Default::default()
    };

    let mut client = irc::client::Client::from_config(cfg).await?;

    let mut stream = client.stream()?;
    let mut s = State::Start;

    /*
     * Wait at most a minute for identification to complete.  If we don't get
     * there, either the server is unreasonably slow or we have made a
     * programming error.
     */
    let online_timer = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(online_timer);

    loop {
        tokio::select! {
            _ = &mut online_timer, if !matches!(s, State::Online) => {
                bail!("Did not reach Online state in time.");
            }
            m = stream.next() => {
                match m {
                    Some(Ok(m)) => {
                        s = irc_msg(&toml, &client, s, &m).await?;
                    }
                    Some(Err(e)) => {
                        bail!("IRC error: {:?}", e);
                    }
                    None => {
                        bail!("IRC stream ended unexpectedly");
                    }
                }
            }
        }
    }
}
