use schemars::JsonSchema;
use dropshot::endpoint;

use super::{prelude::*, Action, ConfigGithub};

fn sign(body: &[u8], secret: &str) -> String {
    let hmac = hmac_sha256::HMAC::mac(body, secret.as_bytes());
    let mut out = "sha256=".to_string();
    for b in hmac.iter() {
        out.push_str(&format!("{:<02x}", b));
    }
    out
}

fn interr<T>(log: &slog::Logger, msg: &str) -> SResult<T, dropshot::HttpError> {
    error!(log, "internal error: {}", msg);
    Err(dropshot::HttpError::for_internal_error(msg.to_string()))
}

#[derive(Deserialize, JsonSchema)]
struct SayBody {
    m: String,
}

#[endpoint {
    method = POST,
    path = "/gitomat/say",
}]
async fn say(
    ctx: Arc<dropshot::RequestContext<Central>>,
    body: dropshot::TypedBody<SayBody>,
) -> SResult<dropshot::HttpResponseOk<()>, dropshot::HttpError> {
    let c = ctx.context();
    let body = body.into_inner();
    c.tx.send(Action::Message(body.m)).await.map_err(|_| {
        dropshot::HttpError::for_internal_error("queue failure".to_string())
    })?;
    Ok(dropshot::HttpResponseOk(()))
}

#[derive(Deserialize, JsonSchema, Debug)]
struct GithubRepository {
    name: String,
}

#[derive(Deserialize, JsonSchema, Debug)]
struct GithubCommit {
    message: String,
    author: GithubAuthor,
}

#[derive(Deserialize, JsonSchema, Debug)]
struct GithubAuthor {
    name: String,
    email: String,
}

#[derive(Deserialize, JsonSchema, Debug)]
struct GithubBody {
    #[serde(rename = "ref")]
    ref_: String,
    repository: GithubRepository,
    commits: Vec<GithubCommit>,
}

#[endpoint {
    method = POST,
    path = "/gitomat/github",
}]
async fn github(
    ctx: Arc<dropshot::RequestContext<Central>>,
    body: dropshot::UntypedBody,
) -> SResult<dropshot::HttpResponseOk<()>, dropshot::HttpError> {
    let c = ctx.context();
    let req = ctx.request.lock().await;

    /*
     * Locate the HMAC-256 signature of the body from Github.
     */
    let sig = {
        if let Some(h) = req.headers().get("x-hub-signature-256") {
            if let Ok(s) = h.to_str() {
                s.to_string()
            } else {
                return interr(&ctx.log, "invalid signature header");
            }
        } else {
            return interr(&ctx.log, "no signature header");
        }
    };

    /*
     * Fetch the body as raw bytes so that we can calculate the signature before
     * parsing it as JSON.
     */
    let buf = body.as_bytes();
    let oursig = sign(buf, &c.secret);

    if sig != oursig {
        error!(ctx.log, "signatures"; "theirs" => sig, "ours" => oursig);
        return interr(&ctx.log, "signature mismatch");
    }

    let v: serde_json::Value = if let Ok(ok) = serde_json::from_slice(buf) {
        ok
    } else {
        return interr(&ctx.log, "invalid JSON");
    };

    debug!(ctx.log, "from GitHub: {:#?}", v);

    let body: GithubBody = match serde_json::from_value(v) {
        Ok(ok) => ok,
        Err(e) => return interr(&ctx.log, &format!("json: {:?}", e)),
    };

    if &body.ref_ != "refs/heads/master" {
        return interr(&ctx.log, "wrong ref (not master)");
    }

    for commit in body.commits.iter() {
        if let Some(msg) = commit.message.lines().next() {
            info!(ctx.log, "Github push notification: {:?}", commit);
            c.tx.send(Action::Message(format!(
                "[{}] {} -- {} <{}>",
                body.repository.name,
                msg,
                commit.author.name,
                commit.author.email,
            )))
            .await
            .unwrap();
        }
    }

    Ok(dropshot::HttpResponseOk(()))
}

pub(crate) struct Central {
    tx: mpsc::Sender<Action>,
    secret: String,
}

pub(crate) async fn start_server(
    log: slog::Logger,
    tx: mpsc::Sender<Action>,
    toml: &ConfigGithub,
) -> Result<dropshot::HttpServer<Central>> {
    let cds = dropshot::ConfigDropshot {
        bind_address: "127.0.0.1:6093".parse().unwrap(),
        request_body_max_bytes: 1024 * 1024,
        ..Default::default()
    };

    let c = Central {
        tx,
        secret: toml.secret.to_string(),
    };

    let mut api = dropshot::ApiDescription::new();
    if toml.allow_say {
        api.register(say)
            .map_err(|e| anyhow!("API registration: {}", e))?;
    }
    api.register(github)
        .map_err(|e| anyhow!("API registration: {}", e))?;

    info!(log, "server listening on {}", cds.bind_address);
    let server = dropshot::HttpServerStarter::new(&cds, api, c, &log)?;
    Ok(server.start())
}
