use clap::{Parser, Subcommand};
use signin_bridge::{keys, App, Config, Method, SiweConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(version, about = "An OpenID Connect provider for vlpds in front of Sign-In with Ethereum")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the provider.
    Serve(Box<Serve>),
    /// Print a new ES256 signing key (PKCS#8 PEM) for --signing-key-file.
    GenerateKey,
}

#[derive(clap::Args)]
struct Serve {
    #[arg(long, env = "SIGNIN_BRIDGE_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    /// The URL the reverse proxy sends here, path included and not stripped
    /// (https://example.com/signin-bridge). Each method's issuer is under
    /// it: {public_url}/siwe.
    #[arg(long, env = "SIGNIN_BRIDGE_PUBLIC_URL")]
    public_url: url::Url,
    /// PKCS#8 PEM P-256 key that signs id_tokens (see generate-key).
    #[arg(long, env = "SIGNIN_BRIDGE_SIGNING_KEY_FILE")]
    signing_key_file: PathBuf,
    /// Earlier signing keys, still published in the key set but never used.
    #[arg(long = "retired-key-file", env = "SIGNIN_BRIDGE_RETIRED_KEY_FILES", value_delimiter = ',')]
    retired_key_files: Vec<PathBuf>,
    /// The client id vlpds uses (its provider's clientId).
    #[arg(long, env = "SIGNIN_BRIDGE_CLIENT_ID")]
    client_id: String,
    /// The client secret, at least 32 characters. Prefer the environment
    /// variable: a flag shows in the process list.
    #[arg(long, env = "SIGNIN_BRIDGE_CLIENT_SECRET", hide_env_values = true)]
    client_secret: String,
    /// Exact redirect URIs the client may use: vlpds's
    /// {public_url}/oauth/federated/callback/{provider id}.
    #[arg(long = "redirect-uri", env = "SIGNIN_BRIDGE_REDIRECT_URIS", value_delimiter = ',', required = true)]
    redirect_uris: Vec<String>,
    /// The statement line of the message wallets sign.
    #[arg(long, env = "SIGNIN_BRIDGE_SIWE_STATEMENT", default_value = "Sign in with your Ethereum account.")]
    siwe_statement: String,
    /// Chain IDs a SIWE message may name; the first is the one the page
    /// asks for. Each chain is part of the subject (eip155:{chain}:0x…).
    #[arg(long = "siwe-chain", env = "SIGNIN_BRIDGE_SIWE_CHAINS", value_delimiter = ',', default_value = "1")]
    siwe_chains: Vec<u64>,
    /// CHAIN=URL: a JSON-RPC endpoint for checking contract wallet
    /// signatures on that chain. Without one, only plain-key wallets work.
    #[arg(long = "eth-rpc", env = "SIGNIN_BRIDGE_ETH_RPC", value_delimiter = ',', value_parser = parse_rpc)]
    eth_rpc: Vec<(u64, url::Url)>,
}

fn parse_rpc(s: &str) -> Result<(u64, url::Url), String> {
    let (chain, u) = s.split_once('=').ok_or("expected CHAIN=URL")?;
    let chain = chain.parse().map_err(|_| format!("{chain:?} isn't a chain ID"))?;
    let u = url::Url::parse(u).map_err(|e| format!("{u:?}: {e}"))?;
    if !matches!(u.scheme(), "https" | "http") {
        return Err(format!("{u}: not an http(s) URL"));
    }
    Ok((chain, u))
}

fn read_key(path: &PathBuf) -> Result<p256::ecdsa::SigningKey, String> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    keys::parse_pem(&pem).map_err(|e| format!("{}: {e}", path.display()))
}

fn config(s: Serve) -> Result<Config, String> {
    Ok(Config {
        public_url: s.public_url,
        client_id: s.client_id,
        client_secret: s.client_secret,
        redirect_uris: s.redirect_uris,
        signing_key: read_key(&s.signing_key_file)?,
        retired_keys: s
            .retired_key_files
            .iter()
            .map(|p| read_key(p).map(|k| *k.verifying_key()))
            .collect::<Result<_, _>>()?,
        siwe: SiweConfig { statement: s.siwe_statement, chains: s.siwe_chains, rpc: s.eth_rpc.into_iter().collect() },
    })
}

async fn shutdown() {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
    }
}

async fn serve(s: Serve) -> Result<(), String> {
    let listen = s.listen;
    let app = App::new(config(s)?)?;
    let gc = app.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            t.tick().await;
            gc.gc();
        }
    });
    let listener = tokio::net::TcpListener::bind(listen).await.map_err(|e| format!("{listen}: {e}"))?;
    tracing::info!(%listen, issuer = %app.issuer(Method::Siwe), "serving");
    axum::serve(listener, signin_bridge::router(app))
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let s = match cli.cmd {
        Cmd::GenerateKey => {
            print!("{}", keys::generate_pem());
            return ExitCode::SUCCESS;
        }
        Cmd::Serve(s) => *s,
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let rt = tokio::runtime::Runtime::new().expect("a tokio runtime");
    match rt.block_on(serve(s)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("signin-bridge: {e}");
            ExitCode::from(2)
        }
    }
}
