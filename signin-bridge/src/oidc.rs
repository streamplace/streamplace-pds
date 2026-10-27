//! The OpenID Connect side, the same for every method: discovery, the key
//! set, `/authorize` (which starts a pending request and shows the method's
//! page), `/finish` and `/cancel` (which return to the client), `/token`.
//!
//! Only the authorization code flow, with PKCE (S256) and a nonce required,
//! for the one configured client. The response carries `iss` (RFC 9207).

use crate::store::{Code, Full, Gone, Pending, Subject, CODE_TTL, REQUEST_TTL};
use crate::{page, App, Method};
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

type Params = HashMap<String, String>;

/// The browser binding: set by `/authorize`, sent with every later step.
const COOKIE: &str = "signin_bridge";
const ID_TOKEN_TTL: i64 = 300;
const MAX_NONCE: usize = 512;
const MAX_STATE: usize = 2048;

pub(crate) const EXPIRED: &str =
    "This sign-in expired or was started in another browser. Go back to the app and start again.";

pub(crate) fn routes(m: Method) -> Router<Arc<App>> {
    Router::new()
        .route("/.well-known/openid-configuration", get(move |State(app): State<Arc<App>>| discovery(app, m)))
        .route("/jwks", get(|State(app): State<Arc<App>>| async move { cached_json(app.keys.jwks().clone()) }))
        .route(
            "/authorize",
            get(move |State(app): State<Arc<App>>, h: HeaderMap, Query(q): Query<Params>| authorize(app, m, h, q)),
        )
        .route(
            "/finish",
            get(move |State(app): State<Arc<App>>, h: HeaderMap, Query(q): Query<Params>| finish(app, m, h, q)),
        )
        .route(
            "/cancel",
            post(move |State(app): State<Arc<App>>, h: HeaderMap, Form(f): Form<Params>| cancel(app, m, h, f)),
        )
        .route(
            "/token",
            post(move |State(app): State<Arc<App>>, h: HeaderMap, Form(f): Form<Params>| token(app, m, h, f)),
        )
}

fn cached_json(v: serde_json::Value) -> Response {
    ([(header::CACHE_CONTROL, "public, max-age=300")], axum::Json(v)).into_response()
}

async fn discovery(app: Arc<App>, m: Method) -> Response {
    let iss = app.issuer(m);
    cached_json(json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/authorize"),
        "token_endpoint": format!("{iss}/token"),
        "jwks_uri": format!("{iss}/jwks"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "form_post"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["openid", "profile"],
        "claims_supported": ["iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "preferred_username"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
    }))
}

/// This browser's binding cookie, if it sent one.
pub(crate) fn browser_cookie(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, v)| *k == COOKIE && v.len() == 43)
        .map(|(_, v)| v.to_string())
}

fn see_other(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, v), (header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        )
            .into_response(),
        Err(_) => page::error(StatusCode::INTERNAL_SERVER_ERROR, "The return address isn't usable."),
    }
}

/// The result to the client's redirect URI, with `iss`: a redirect, or an
/// auto-submitted form for `form_post`.
pub(crate) fn deliver(
    app: &App,
    m: Method,
    redirect_uri: &str,
    form_post: bool,
    mut params: Vec<(&'static str, String)>,
) -> Response {
    params.push(("iss", app.issuer(m)));
    if form_post {
        return page::form_post(app, redirect_uri, &params);
    }
    let Ok(mut u) = url::Url::parse(redirect_uri) else {
        return page::error(StatusCode::INTERNAL_SERVER_ERROR, "The return address isn't usable.");
    };
    u.query_pairs_mut().extend_pairs(params.iter().map(|(k, v)| (*k, v.as_str())));
    see_other(u.as_str())
}

fn with_state(mut params: Vec<(&'static str, String)>, state: &Option<String>) -> Vec<(&'static str, String)> {
    if let Some(s) = state {
        params.push(("state", s.clone()));
    }
    params
}

fn oauth_error(error: &str, description: &str, state: &Option<String>) -> Vec<(&'static str, String)> {
    with_state(vec![("error", error.into()), ("error_description", description.into())], state)
}

fn is_b64u(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

async fn authorize(app: Arc<App>, m: Method, h: HeaderMap, q: Params) -> Response {
    let get = |k: &str| q.get(k).map(String::as_str).filter(|v| !v.is_empty());
    // until the client and its redirect URI check out, errors stay here
    if get("client_id") != Some(app.cfg.client_id.as_str()) {
        return page::error(StatusCode::BAD_REQUEST, "This sign-in link is for an app this service doesn't know.");
    }
    let Some(redirect_uri) = get("redirect_uri").filter(|r| app.cfg.redirect_uris.iter().any(|x| x == r)) else {
        return page::error(
            StatusCode::BAD_REQUEST,
            "This sign-in link names a return address this service doesn't know.",
        );
    };
    let state = get("state").map(String::from);
    let (form_post, mode_ok) = match get("response_mode") {
        None | Some("query") => (false, true),
        Some("form_post") => (true, true),
        Some(_) => (false, false),
    };
    let fail = |error: &str, description: &str| {
        deliver(&app, m, redirect_uri, form_post, oauth_error(error, description, &state))
    };
    if !mode_ok {
        return fail("invalid_request", "response_mode must be query or form_post");
    }
    if get("response_type") != Some("code") {
        return fail("unsupported_response_type", "only the code flow is supported");
    }
    let scopes: Vec<&str> = get("scope").unwrap_or("").split_ascii_whitespace().collect();
    if !scopes.contains(&"openid") {
        return fail("invalid_scope", "the openid scope is required");
    }
    if state.as_ref().is_some_and(|s| s.len() > MAX_STATE) {
        return fail("invalid_request", "state is too long");
    }
    let Some(nonce) = get("nonce").filter(|n| n.len() <= MAX_NONCE) else {
        return fail("invalid_request", "a nonce of at most 512 characters is required");
    };
    let challenge = get("code_challenge").filter(|c| c.len() == 43 && is_b64u(c));
    let Some(challenge) = challenge.filter(|_| get("code_challenge_method") == Some("S256")) else {
        return fail("invalid_request", "PKCE with S256 is required");
    };
    if get("prompt").is_some_and(|p| p.split_ascii_whitespace().any(|v| v == "none")) {
        return fail("login_required", "every sign-in here needs the user");
    }
    let existing = browser_cookie(&h);
    let browser = existing.clone().unwrap_or_else(crate::random_id);
    let id = crate::random_id();
    let pending = Pending {
        method: m,
        browser: browser.clone(),
        redirect_uri: redirect_uri.to_string(),
        state: state.clone(),
        nonce: nonce.to_string(),
        code_challenge: challenge.to_string(),
        form_post,
        profile: scopes.contains(&"profile"),
        created: crate::now_secs(),
        expires: Instant::now() + REQUEST_TTL,
        siwe_nonce: hex::encode(rand::random::<[u8; 16]>()),
        attempts: 0,
        done: None,
    };
    if let Err(Full) = app.store.insert_pending(id.clone(), pending) {
        tracing::warn!("too many sign-ins in flight; refusing a new one");
        return fail("temporarily_unavailable", "too many sign-ins in progress; try again shortly");
    }
    let client = url::Url::parse(redirect_uri).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
    let mut r = page::sign_in(&app, m, &id, &client);
    if existing.is_none() {
        let secure = if app.secure_cookies { "; Secure" } else { "" };
        let path = if app.prefix.is_empty() { "/" } else { app.prefix.as_str() };
        let c = format!("{COOKIE}={browser}; Path={path}; HttpOnly; SameSite=Lax{secure}");
        if let Ok(v) = HeaderValue::from_str(&c) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

/// Completes a pending request with `subject`, if `browser` started it and
/// nothing completed it yet. Methods call this.
pub(crate) fn complete(app: &App, m: Method, id: &str, browser: &str, subject: Subject) -> Result<bool, Gone> {
    app.store.with_pending(id, m, browser, |p| match p.done {
        Some(_) => false,
        None => {
            p.done = Some(subject);
            true
        }
    })
}

/// Where a completed request's browser goes next.
pub(crate) fn finish_url(app: &App, m: Method, id: &str) -> String {
    format!("{}/finish?request={id}", app.issuer_path(m))
}

async fn finish(app: Arc<App>, m: Method, h: HeaderMap, q: Params) -> Response {
    let (Some(browser), Some(id)) = (browser_cookie(&h), q.get("request")) else {
        return page::error(StatusCode::BAD_REQUEST, EXPIRED);
    };
    let p = match app.store.take_pending(id, m, &browser, |p| p.done.is_some()) {
        Err(Gone) => return page::error(StatusCode::BAD_REQUEST, EXPIRED),
        Ok(None) => {
            return page::error(StatusCode::CONFLICT, "This sign-in isn't finished yet. Go back and finish it.")
        }
        Ok(Some(p)) => p,
    };
    let subject = p.done.expect("taken only when done");
    let code = crate::random_id();
    tracing::info!(method = m.path(), sub = %subject.sub, "signed in");
    let c = Code {
        method: m,
        redirect_uri: p.redirect_uri.clone(),
        code_challenge: p.code_challenge,
        nonce: p.nonce,
        profile: p.profile,
        subject,
        expires: Instant::now() + CODE_TTL,
    };
    let params = match app.store.insert_code(code.clone(), c) {
        Ok(()) => with_state(vec![("code", code)], &p.state),
        Err(Full) => {
            oauth_error("temporarily_unavailable", "too many sign-ins in progress; try again shortly", &p.state)
        }
    };
    deliver(&app, m, &p.redirect_uri, p.form_post, params)
}

async fn cancel(app: Arc<App>, m: Method, h: HeaderMap, f: Params) -> Response {
    let (Some(browser), Some(id)) = (browser_cookie(&h), f.get("request")) else {
        return page::error(StatusCode::BAD_REQUEST, EXPIRED);
    };
    match app.store.take_pending(id, m, &browser, |_| true) {
        Ok(Some(p)) => {
            deliver(&app, m, &p.redirect_uri, p.form_post, oauth_error("access_denied", "the user cancelled", &p.state))
        }
        _ => page::error(StatusCode::BAD_REQUEST, EXPIRED),
    }
}

fn token_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut r = (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({"error": error, "error_description": description})),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"token\""));
    }
    r
}

/// application/x-www-form-urlencoded decoding of one component, as RFC 6749
/// §2.3.1 has clients encode the parts of HTTP Basic credentials.
fn form_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// The client's id and secret, from HTTP Basic or the form. Both at once is
/// an error (RFC 6749 §2.3).
fn client_credentials(h: &HeaderMap, f: &Params) -> Result<(String, String), &'static str> {
    use base64::Engine as _;
    let basic = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Basic "));
    match (basic, f.get("client_secret")) {
        (Some(_), Some(_)) => Err("more than one client authentication"),
        (Some(b), None) => {
            let raw = base64::engine::general_purpose::STANDARD.decode(b.trim()).map_err(|_| "malformed Basic")?;
            let raw = String::from_utf8(raw).map_err(|_| "malformed Basic")?;
            let (id, secret) = raw.split_once(':').ok_or("malformed Basic")?;
            Ok((form_decode(id).ok_or("malformed Basic")?, form_decode(secret).ok_or("malformed Basic")?))
        }
        (None, Some(s)) => Ok((f.get("client_id").cloned().unwrap_or_default(), s.clone())),
        (None, None) => Err("no client authentication"),
    }
}

async fn token(app: Arc<App>, m: Method, h: HeaderMap, f: Params) -> Response {
    let (id, secret) = match client_credentials(&h, &f) {
        Ok(c) => c,
        Err(e) => return token_error(StatusCode::UNAUTHORIZED, "invalid_client", e),
    };
    if f.get("client_id").is_some_and(|c| *c != id)
        || !(crate::ct_eq(&id, &app.cfg.client_id) & crate::ct_eq(&secret, &app.cfg.client_secret))
    {
        tracing::warn!(method = m.path(), "token request with the wrong client credentials");
        return token_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client or wrong secret");
    }
    if f.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return token_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", "only authorization_code");
    }
    let invalid = |d: &str| token_error(StatusCode::BAD_REQUEST, "invalid_grant", d);
    let Some(c) = f.get("code").and_then(|code| app.store.take_code(code)) else {
        return invalid("unknown, used or expired code");
    };
    if c.method != m || f.get("redirect_uri") != Some(&c.redirect_uri) {
        return invalid("the code was issued for another issuer or redirect URI");
    }
    let verifier = f.get("code_verifier").map(String::as_str).unwrap_or("");
    let verifier_ok = (43..=128).contains(&verifier.len())
        && verifier.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    let computed = crate::b64u(<sha2::Sha256 as sha2::Digest>::digest(verifier.as_bytes()));
    if !verifier_ok || !crate::ct_eq(&computed, &c.code_challenge) {
        return invalid("the code_verifier doesn't match the code_challenge");
    }
    let now = crate::now_secs();
    let mut claims = json!({
        "iss": app.issuer(m),
        "sub": c.subject.sub,
        "aud": app.cfg.client_id,
        "iat": now,
        "exp": now + ID_TOKEN_TTL,
        "auth_time": c.subject.auth_time,
        "nonce": c.nonce,
    });
    if let (true, Some(d)) = (c.profile, &c.subject.display) {
        claims["preferred_username"] = json!(d);
    }
    let id_token = app.keys.sign(&claims);
    // OAuth needs an access token in the response. This one opens nothing:
    // there is no userinfo endpoint or any other protected resource.
    (
        [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")],
        axum::Json(json!({
            "access_token": crate::random_id(),
            "token_type": "Bearer",
            "expires_in": ID_TOKEN_TTL,
            "id_token": id_token,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_decode_handles_rfc6749_encoding() {
        assert_eq!(form_decode("a%3Ab+c%2B").as_deref(), Some("a:b c+"));
        assert_eq!(form_decode("plain").as_deref(), Some("plain"));
        assert_eq!(form_decode("bad%2"), None);
        assert_eq!(form_decode("bad%zz"), None);
    }
}
