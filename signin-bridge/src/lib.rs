//! An OpenID Connect provider for sign-in methods vlpds doesn't speak itself.
//! vlpds adds each method as an ordinary sign-in provider and sees only an
//! issuer and a subject (docs/operations/sign-in-providers.md, "Methods that
//! aren't OpenID Connect").
//!
//! Each method is its own issuer, `{public_url}/{method}`: vlpds links at most
//! one identity per issuer to an account, so methods sharing an issuer would
//! shut each other out. Every method ends the same way. The browser that hit
//! `/authorize` holds a pending request bound to its cookie; the method
//! completes it with a subject (the wallet's signature, for SIWE); that
//! browser then calls `/finish`, which mints the code and returns it to the
//! client. A method that completes from another device (a phone scanning a QR
//! code) only needs its own completion route.
//!
//! State is in memory: run one replica. A restart drops sign-ins in flight
//! (each lives 10 minutes) and nothing else.

pub mod eth;
pub mod keys;
mod oidc;
mod page;
pub mod siwe;
mod store;

use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use std::collections::HashMap;
use std::sync::Arc;

/// A sign-in method, served as its own issuer at `{public_url}/{path}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Siwe,
}

impl Method {
    pub fn path(self) -> &'static str {
        match self {
            Method::Siwe => "siwe",
        }
    }
}

pub struct Config {
    /// Where the reverse proxy sends this service's requests, path included
    /// and not stripped: `https://example.com/signin-bridge`.
    pub public_url: url::Url,
    pub client_id: String,
    pub client_secret: String,
    /// Exact redirect URIs the client may use.
    pub redirect_uris: Vec<String>,
    pub signing_key: p256::ecdsa::SigningKey,
    /// Published in the key set so tokens they signed still verify; never
    /// used to sign.
    pub retired_keys: Vec<p256::ecdsa::VerifyingKey>,
    pub siwe: SiweConfig,
}

pub struct SiweConfig {
    /// The message's statement line.
    pub statement: String,
    /// Chain IDs a message may name. The first is the one this service's
    /// page asks wallets to sign for.
    pub chains: Vec<u64>,
    /// JSON-RPC endpoints by chain ID, for contract wallets (ERC-1271 and
    /// ERC-6492). A chain without one accepts plain-key (EOA) signatures only.
    pub rpc: HashMap<u64, url::Url>,
}

impl Config {
    /// Problems with the configuration, before anything is served.
    pub fn check(&self) -> Result<(), String> {
        let u = &self.public_url;
        let loopback = matches!(u.host(), Some(url::Host::Ipv4(a)) if a.is_loopback())
            || matches!(u.host(), Some(url::Host::Ipv6(a)) if a.is_loopback())
            || u.host_str() == Some("localhost");
        if u.scheme() != "https" && !(u.scheme() == "http" && loopback) {
            return Err("--public-url must be https (http only on loopback)".into());
        }
        if u.query().is_some() || u.fragment().is_some() || u.host_str().is_none() {
            return Err("--public-url must be a plain URL with no query or fragment".into());
        }
        if self.client_id.is_empty() {
            return Err("--client-id is empty".into());
        }
        if self.client_secret.len() < 32 {
            return Err("the client secret must be at least 32 characters".into());
        }
        if self.redirect_uris.is_empty() {
            return Err("at least one --redirect-uri is needed".into());
        }
        for r in &self.redirect_uris {
            let p = url::Url::parse(r).map_err(|e| format!("redirect URI {r:?}: {e}"))?;
            if p.fragment().is_some() || !matches!(p.scheme(), "https" | "http") {
                return Err(format!("redirect URI {r:?} must be http(s) with no fragment"));
            }
        }
        let s = &self.siwe;
        if s.statement.is_empty() || s.statement.contains(['\n', '\r']) {
            return Err("the SIWE statement must be one non-empty line".into());
        }
        if s.chains.is_empty() {
            return Err("at least one SIWE chain ID is needed".into());
        }
        if let Some(c) = s.rpc.keys().find(|c| !s.chains.contains(c)) {
            return Err(format!("an RPC endpoint is set for chain {c}, which isn't an allowed chain"));
        }
        Ok(())
    }
}

pub struct App {
    cfg: Config,
    /// `public_url` without a trailing slash.
    base: String,
    /// Its path: `""` or `/signin-bridge`.
    prefix: String,
    keys: keys::Keys,
    store: store::Store,
    rpc: eth::Rpc,
    secure_cookies: bool,
}

impl App {
    pub fn new(cfg: Config) -> Result<Arc<App>, String> {
        cfg.check()?;
        let base = cfg.public_url.as_str().trim_end_matches('/').to_string();
        let prefix = cfg.public_url.path().trim_end_matches('/').to_string();
        let keys = keys::Keys::new(&cfg.signing_key, &cfg.retired_keys);
        let rpc = eth::Rpc::new(cfg.siwe.rpc.clone());
        let secure_cookies = cfg.public_url.scheme() == "https";
        Ok(Arc::new(App { cfg, base, prefix, keys, store: store::Store::default(), rpc, secure_cookies }))
    }

    pub fn issuer(&self, m: Method) -> String {
        format!("{}/{}", self.base, m.path())
    }

    /// The issuer's path on this host, for links in pages.
    fn issuer_path(&self, m: Method) -> String {
        format!("{}/{}", self.prefix, m.path())
    }

    /// Drops expired requests and codes; run it every minute or so.
    pub fn gc(&self) {
        self.store.gc();
    }
}

pub fn router(app: Arc<App>) -> axum::Router {
    let p = app.prefix.clone();
    let siwe = oidc::routes(Method::Siwe).merge(siwe::routes());
    axum::Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(&format!("{p}/static/bridge.js"), get(page::script))
        .route(&format!("{p}/static/style.css"), get(page::style))
        .nest(&format!("{p}/{}", Method::Siwe.path()), siwe)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(app)
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 32 random bytes, base64url.
pub(crate) fn random_id() -> String {
    b64u(rand::random::<[u8; 32]>())
}

pub(crate) fn b64u(b: impl AsRef<[u8]>) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
