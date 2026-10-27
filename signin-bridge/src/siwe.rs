//! Sign-In with Ethereum (EIP-4361). The page asks `/challenge` for the
//! message to sign for the wallet's address, the wallet signs it with
//! `personal_sign` (EIP-191), and `/verify` checks it and completes the
//! request. `/verify` takes any well-formed EIP-4361 message that names this
//! service, so a frontend that builds its own (viem, AppKit) works too.
//!
//! The subject is `eip155:{chain}:{address}`, the address lowercase: one
//! casing, so it never changes for the same wallet. A plain-key wallet (EOA)
//! is checked by recovering its key; a contract wallet (Safe, a smart
//! account, an undeployed one under ERC-6492) through `eth_call` on its chain
//! when an RPC endpoint is configured for it.

use crate::eth::Check;
use crate::oidc::{browser_cookie, complete, finish_url, EXPIRED};
use crate::store::{Gone, Subject, MAX_ATTEMPTS, REQUEST_TTL};
use crate::{App, Method};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const M: Method = Method::Siwe;
const HEADER_SUFFIX: &str = " wants you to sign in with your Ethereum account:";
const MAX_MESSAGE: usize = 4096;
/// Hex characters; an ERC-6492 signature carries a factory call.
const MAX_SIGNATURE: usize = 16 * 1024;
const SKEW: i64 = 60;

pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new().route("/challenge", post(challenge)).route("/verify", post(verify))
}

pub fn keccak(b: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    sha3::Keccak256::digest(b).into()
}

/// The EIP-191 `personal_sign` hash of `msg`.
pub fn eip191(msg: &str) -> [u8; 32] {
    keccak(format!("\x19Ethereum Signed Message:\n{}{msg}", msg.len()).as_bytes())
}

/// The 20 bytes of a `0x` address in any casing.
pub fn parse_address(s: &str) -> Option<[u8; 20]> {
    let h = s.strip_prefix("0x")?;
    if h.len() != 40 {
        return None;
    }
    hex::decode(h).ok()?.try_into().ok()
}

/// EIP-55 mixed-case checksum form.
pub fn checksum(a: &[u8; 20]) -> String {
    let lower = hex::encode(a);
    let h = keccak(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (h[i / 2] >> if i % 2 == 0 { 4 } else { 0 }) & 0xf;
        out.push(if nibble >= 8 { c.to_ascii_uppercase() } else { c });
    }
    out
}

/// The address whose key made a 65-byte `personal_sign` signature (r, s, v
/// with v 27/28 or 0/1) over `hash`.
pub fn recover(hash: &[u8; 32], sig: &[u8]) -> Option<[u8; 20]> {
    if sig.len() != 65 {
        return None;
    }
    let v = match sig[64] {
        27 | 28 => sig[64] - 27,
        0 | 1 => sig[64],
        _ => return None,
    };
    let rec = k256::ecdsa::RecoveryId::from_byte(v)?;
    let s = k256::ecdsa::Signature::from_slice(&sig[..64]).ok()?;
    let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(hash, &s, rec).ok()?;
    let pt = vk.to_sec1_point(false);
    keccak(&pt.as_bytes()[1..])[12..].try_into().ok()
}

/// An EIP-4361 message, parsed by its ABNF.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub scheme: Option<String>,
    pub domain: String,
    pub address: String,
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at: OffsetDateTime,
    pub expiration_time: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
    pub request_id: Option<String>,
    pub resources: Vec<String>,
}

fn rfc3339(s: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(s, &Rfc3339).map_err(|_| format!("{s:?} isn't an RFC 3339 time"))
}

impl Message {
    pub fn parse(text: &str) -> Result<Message, String> {
        if text.contains('\r') {
            return Err("line endings must be LF".into());
        }
        let mut lines = text.split('\n').peekable();
        let mut next = || lines.next().ok_or_else(|| "the message ends early".to_string());
        let header = next()?;
        let origin = header.strip_suffix(HEADER_SUFFIX).ok_or("the first line isn't a SIWE header")?;
        let (scheme, domain) = match origin.split_once("://") {
            Some((s, d)) => (Some(s.to_string()), d.to_string()),
            None => (None, origin.to_string()),
        };
        if domain.is_empty() || domain.contains(char::is_whitespace) {
            return Err("bad domain".into());
        }
        let address = next()?.to_string();
        if !next()?.is_empty() {
            return Err("no blank line after the address".into());
        }
        let statement = match next()? {
            "" => None,
            s => {
                if !next()?.is_empty() {
                    return Err("no blank line after the statement".into());
                }
                Some(s.to_string())
            }
        };
        let mut field = |name: &str| -> Result<String, String> {
            let l = next()?;
            l.strip_prefix(name).map(String::from).ok_or_else(|| format!("expected {name:?}"))
        };
        let uri = field("URI: ")?;
        let version = field("Version: ")?;
        let chain = field("Chain ID: ")?;
        let nonce = field("Nonce: ")?;
        let issued_at = rfc3339(&field("Issued At: ")?)?;
        if !chain.bytes().all(|b| b.is_ascii_digit()) || chain.starts_with('0') {
            return Err("bad chain ID".into());
        }
        let chain_id = chain.parse().map_err(|_| "bad chain ID")?;
        if nonce.len() < 8 || !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err("bad nonce".into());
        }
        let mut m = Message {
            scheme,
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: Vec::new(),
        };
        // the optional fields, each at most once and in this order
        let mut l = lines.next();
        if let Some(v) = l.and_then(|s| s.strip_prefix("Expiration Time: ")) {
            m.expiration_time = Some(rfc3339(v)?);
            l = lines.next();
        }
        if let Some(v) = l.and_then(|s| s.strip_prefix("Not Before: ")) {
            m.not_before = Some(rfc3339(v)?);
            l = lines.next();
        }
        if let Some(v) = l.and_then(|s| s.strip_prefix("Request ID: ")) {
            m.request_id = Some(v.to_string());
            l = lines.next();
        }
        if l == Some("Resources:") {
            l = lines.next();
            while let Some(r) = l.and_then(|s| s.strip_prefix("- ")) {
                m.resources.push(r.to_string());
                l = lines.next();
            }
        }
        match l {
            None => Ok(m),
            Some(extra) => Err(format!("unexpected line {:?}", extra.chars().take(40).collect::<String>())),
        }
    }
}

/// What a message must say to sign in here, from the config and the request.
struct Expect<'a> {
    scheme: &'a str,
    domain: String,
    uri: String,
    chains: &'a [u64],
    nonce: &'a str,
    created: i64,
    now: i64,
}

impl Expect<'_> {
    fn check(&self, m: &Message) -> Result<(), String> {
        // EIP-4361: a message without a scheme means https
        if m.scheme.as_deref().unwrap_or("https") != self.scheme || m.domain != self.domain {
            return Err(format!("the message is for {:?}, not this site", m.domain));
        }
        let Some(a) = parse_address(&m.address) else { return Err("bad address".into()) };
        if checksum(&a) != m.address {
            return Err("the address isn't in EIP-55 checksum form".into());
        }
        if m.uri != self.uri {
            return Err("the message's URI isn't this sign-in service".into());
        }
        if m.version != "1" {
            return Err("unsupported SIWE version".into());
        }
        if !self.chains.contains(&m.chain_id) {
            return Err(format!("chain {} isn't accepted here", m.chain_id));
        }
        if !crate::ct_eq(&m.nonce, self.nonce) {
            return Err("the message's nonce isn't this sign-in's".into());
        }
        let ts = |t: OffsetDateTime| t.unix_timestamp();
        let issued = ts(m.issued_at);
        if issued < self.created - SKEW || issued > self.now + SKEW {
            return Err("the message's Issued At isn't now".into());
        }
        if m.expiration_time.is_some_and(|t| ts(t) <= self.now) {
            return Err("the message has expired".into());
        }
        if m.not_before.is_some_and(|t| ts(t) > self.now + SKEW) {
            return Err("the message isn't valid yet".into());
        }
        Ok(())
    }
}

fn authority(u: &url::Url) -> String {
    match u.port() {
        Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
        None => u.host_str().unwrap_or("").to_string(),
    }
}

fn rfc3339_secs(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0).unwrap_or(t).format(&Rfc3339).unwrap_or_default()
}

/// The message this service's page has the wallet sign.
fn build(app: &App, address: &str, chain: u64, nonce: &str, issued: OffsetDateTime, expires: OffsetDateTime) -> String {
    let u = &app.cfg.public_url;
    let scheme = if u.scheme() == "https" { String::new() } else { format!("{}://", u.scheme()) };
    format!(
        "{scheme}{}{HEADER_SUFFIX}\n{address}\n\n{}\n\nURI: {}\nVersion: 1\nChain ID: {chain}\nNonce: {nonce}\nIssued At: {}\nExpiration Time: {}",
        authority(u),
        app.cfg.siwe.statement,
        app.issuer(M),
        rfc3339_secs(issued),
        rfc3339_secs(expires),
    )
}

fn refuse(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeReq {
    request: String,
    address: String,
    #[serde(default)]
    chain_id: Option<u64>,
}

async fn challenge(State(app): State<Arc<App>>, h: axum::http::HeaderMap, Json(r): Json<ChallengeReq>) -> Response {
    let Some(browser) = browser_cookie(&h) else { return refuse(StatusCode::BAD_REQUEST, EXPIRED) };
    let Some(a) = parse_address(&r.address) else { return refuse(StatusCode::BAD_REQUEST, "That isn't an address.") };
    let chains = &app.cfg.siwe.chains;
    let chain = r.chain_id.unwrap_or(chains[0]);
    if !chains.contains(&chain) {
        return refuse(StatusCode::BAD_REQUEST, &format!("Chain {chain} isn't accepted here."));
    }
    let Ok((nonce, created)) = app.store.with_pending(&r.request, M, &browser, |p| (p.siwe_nonce.clone(), p.created))
    else {
        return refuse(StatusCode::BAD_REQUEST, EXPIRED);
    };
    let created = OffsetDateTime::from_unix_timestamp(created).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let now = OffsetDateTime::now_utc();
    let message = build(&app, &checksum(&a), chain, &nonce, now, created + REQUEST_TTL);
    Json(json!({ "message": message })).into_response()
}

#[derive(Deserialize)]
struct VerifyReq {
    request: String,
    message: String,
    signature: String,
}

async fn verify(State(app): State<Arc<App>>, h: axum::http::HeaderMap, Json(r): Json<VerifyReq>) -> Response {
    let Some(browser) = browser_cookie(&h) else { return refuse(StatusCode::BAD_REQUEST, EXPIRED) };
    // an attempt counts before the (possibly remote) check, so concurrent
    // tries can't exceed the limit
    let reserved = app.store.with_pending(&r.request, M, &browser, |p| {
        if p.done.is_some() || p.attempts >= MAX_ATTEMPTS {
            return None;
        }
        p.attempts += 1;
        Some((p.siwe_nonce.clone(), p.created))
    });
    let (nonce, created) = match reserved {
        Ok(Some(x)) => x,
        Ok(None) | Err(Gone) => return refuse(StatusCode::BAD_REQUEST, EXPIRED),
    };
    match check(&app, &r, &nonce, created).await {
        Ok(subject) => match complete(&app, M, &r.request, &browser, subject) {
            Ok(true) => Json(json!({ "next": finish_url(&app, M, &r.request) })).into_response(),
            _ => refuse(StatusCode::BAD_REQUEST, EXPIRED),
        },
        Err((status, msg)) => {
            tracing::info!(status = status.as_u16(), "SIWE refused: {msg}");
            let left = app.store.with_pending(&r.request, M, &browser, |p| MAX_ATTEMPTS - p.attempts).unwrap_or(0);
            if left == 0 {
                app.store.remove_pending(&r.request);
                return refuse(status, &format!("{msg} That was the last try: go back to the app and start again."));
            }
            refuse(status, &msg)
        }
    }
}

async fn check(app: &App, r: &VerifyReq, nonce: &str, created: i64) -> Result<Subject, (StatusCode, String)> {
    let bad = |m: String| (StatusCode::BAD_REQUEST, m);
    if r.message.len() > MAX_MESSAGE || r.signature.len() > MAX_SIGNATURE {
        return Err(bad("The message or signature is too long.".into()));
    }
    let m = Message::parse(&r.message).map_err(|e| bad(format!("That isn't a Sign-In with Ethereum message: {e}.")))?;
    let u = &app.cfg.public_url;
    let expect = Expect {
        scheme: u.scheme(),
        domain: authority(u),
        uri: app.issuer(M),
        chains: &app.cfg.siwe.chains,
        nonce,
        created,
        now: crate::now_secs(),
    };
    expect.check(&m).map_err(|e| bad(format!("The signed message doesn't fit this sign-in: {e}.")))?;
    let addr = parse_address(&m.address).expect("checked");
    let sig = hex::decode(r.signature.trim_start_matches("0x")).map_err(|_| bad("The signature isn't hex.".into()))?;
    let hash = eip191(&r.message);
    if recover(&hash, &sig) != Some(addr) {
        // not this address's key: a contract wallet, or a wrong signature
        match app.rpc.check(m.chain_id, &addr, &hash, &sig).await {
            Check::Valid => {}
            Check::Invalid => return Err(bad("The signature isn't from this address.".into())),
            Check::NoRpc => {
                return Err(bad(
                    "The signature isn't from this address's key. Smart-contract wallets can't sign in here yet."
                        .into(),
                ))
            }
            Check::Unavailable(e) => {
                tracing::warn!(chain = m.chain_id, "contract wallet check failed: {e}");
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Your wallet's signature couldn't be checked right now. Try again shortly.".into(),
                ));
            }
        }
    }
    Ok(Subject {
        sub: format!("eip155:{}:0x{}", m.chain_id, hex::encode(addr)),
        display: Some(m.address),
        auth_time: crate::now_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(statement: bool, tail: &str) -> String {
        let s = if statement { "Sign in.\n" } else { "" };
        format!(
            "example.com wants you to sign in with your Ethereum account:\n0x2c7536E3605D9C16a7a3D7b1898e529396a65c23\n\n{s}\nURI: https://example.com/b/siwe\nVersion: 1\nChain ID: 1\nNonce: abcdef1234\nIssued At: 2026-10-26T12:00:00Z{tail}"
        )
    }

    #[test]
    fn parses_with_and_without_statement_and_optional_fields() {
        let m = Message::parse(&msg(true, "")).unwrap();
        assert_eq!(m.statement.as_deref(), Some("Sign in."));
        assert_eq!(m.chain_id, 1);
        let m = Message::parse(&msg(false, "\nNot Before: 2026-10-26T12:00:00Z\nResources:\n- https://a\n- ipfs://b"))
            .unwrap();
        assert_eq!(m.statement, None);
        assert_eq!(m.expiration_time, None);
        assert!(m.not_before.is_some());
        assert_eq!(m.resources, vec!["https://a", "ipfs://b"]);
    }

    #[test]
    fn rejects_out_of_order_unknown_or_trailing_lines() {
        // Not Before before Expiration Time
        let bad = msg(true, "\nNot Before: 2026-10-26T12:00:00Z\nExpiration Time: 2026-10-26T13:00:00Z");
        assert!(Message::parse(&bad).is_err());
        assert!(Message::parse(&msg(true, "\nSomething: else")).is_err());
        assert!(Message::parse(&msg(true, "\n")).is_err());
        assert!(Message::parse(&msg(true, "").replace('\n', "\r\n")).is_err());
        assert!(Message::parse(&msg(true, "").replace("Chain ID: 1", "Chain ID: 01")).is_err());
        assert!(Message::parse(&msg(true, "").replace("abcdef1234", "short")).is_err());
    }

    /// web3.js's documented `web3.eth.accounts.sign('Some data', …)` vector,
    /// and its v as 0/1.
    #[test]
    fn recovers_web3_vector() {
        let mut sig = hex::decode("b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c").unwrap();
        let want = parse_address("0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
        assert_eq!(recover(&eip191("Some data"), &sig), want);
        sig[64] -= 27;
        assert_eq!(recover(&eip191("Some data"), &sig), want);
        assert!(recover(&eip191("Other data"), &sig).is_some_and(|a| Some(a) != want));
    }

    /// EIP-55's own examples.
    #[test]
    fn checksums_eip55_examples() {
        for a in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            assert_eq!(checksum(&parse_address(a).unwrap()), a);
        }
    }

    #[test]
    fn expect_checks_each_field() {
        let m = Message::parse(&msg(true, "\nExpiration Time: 2026-10-26T12:10:00Z")).unwrap();
        let t = |s: &str| OffsetDateTime::parse(s, &Rfc3339).unwrap().unix_timestamp();
        let ok = Expect {
            scheme: "https",
            domain: "example.com".into(),
            uri: "https://example.com/b/siwe".into(),
            chains: &[1],
            nonce: "abcdef1234",
            created: t("2026-10-26T11:59:30Z"),
            now: t("2026-10-26T12:00:10Z"),
        };
        assert_eq!(ok.check(&m), Ok(()));
        let with = |f: &dyn Fn(&mut Expect)| {
            let mut e = Expect { domain: ok.domain.clone(), uri: ok.uri.clone(), ..ok };
            f(&mut e);
            e.check(&m)
        };
        assert!(with(&|e| e.domain = "evil.com".into()).is_err());
        assert!(with(&|e| e.scheme = "http").is_err());
        assert!(with(&|e| e.uri = "https://example.com/b/other".into()).is_err());
        assert!(with(&|e| e.chains = &[8453]).is_err());
        assert!(with(&|e| e.nonce = "abcdef1235").is_err());
        // signed before the request existed, or expired
        assert!(with(&|e| e.created = t("2026-10-26T12:05:00Z")).is_err());
        assert!(with(&|e| e.now = t("2026-10-26T12:10:00Z")).is_err());
        let lower = Message { address: m.address.to_ascii_lowercase(), ..Message::parse(&msg(true, "")).unwrap() };
        assert!(ok.check(&lower).is_err());
    }
}
