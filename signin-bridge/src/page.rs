//! Server-rendered pages: the method's sign-in page, errors, and the
//! `form_post` return. Script and style are static files, so the pages run
//! under a CSP with no inline code.

use crate::{App, Method};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const SCRIPT: &str = include_str!("../static/bridge.js");
const STYLE: &str = include_str!("../static/style.css");

pub(crate) fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn origin(u: &str) -> Option<String> {
    url::Url::parse(u).ok().map(|u| u.origin().ascii_serialization()).filter(|o| o != "null")
}

/// `form-action` must name every place a form here can end up, redirects
/// included: this service and the client's redirect URIs.
fn form_action(app: &App) -> String {
    let mut v = vec!["'self'".to_string()];
    for o in app.cfg.redirect_uris.iter().filter_map(|r| origin(r)) {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v.join(" ")
}

fn html(status: StatusCode, form_action: &str, body: String) -> Response {
    let csp = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; connect-src 'self'; \
         form-action {form_action}; base-uri 'none'; frame-ancestors 'none'"
    );
    let mut r = (status, body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    r
}

fn doc(app: &App, title: &str, body_attrs: &str, main: &str) -> String {
    let p = &app.prefix;
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="{p}/static/style.css">
<script src="{p}/static/bridge.js" defer></script>
</head>
<body{body_attrs}>
<main>
{main}
</main>
</body>
</html>
"#,
        title = esc(title),
    )
}

pub(crate) fn error(status: StatusCode, message: &str) -> Response {
    // no app here: an error page has no script, so no paths to resolve
    let body = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sign-in problem</title></head>\n\
         <body><main><h1>Sign-in problem</h1><p>{}</p></main></body></html>\n",
        esc(message)
    );
    html(status, "'none'", body)
}

pub(crate) fn sign_in(app: &App, m: Method, request: &str, client: &str) -> Response {
    let ip = esc(&app.issuer_path(m));
    let main = match m {
        Method::Siwe => format!(
            r#"<h1>Sign in with Ethereum</h1>
<p>Sign a message with your wallet to continue to <strong>{client}</strong>. Signing costs nothing and sends no transaction.</p>
<div id="wallets" class="wallets"></div>
<p id="status" class="status" role="status" aria-live="polite"></p>
<form method="post" action="{ip}/cancel">
<input type="hidden" name="request" value="{request}">
<button type="submit" class="secondary">Cancel</button>
</form>"#,
            client = esc(client),
            request = esc(request),
        ),
    };
    let attrs = format!(r#" data-method="{}" data-issuer-path="{ip}" data-request="{}""#, m.path(), esc(request));
    html(StatusCode::OK, &form_action(app), doc(app, "Sign in with Ethereum", &attrs, &main))
}

pub(crate) fn form_post(app: &App, redirect_uri: &str, params: &[(&str, String)]) -> Response {
    let inputs: String = params
        .iter()
        .map(|(k, v)| format!(r#"<input type="hidden" name="{}" value="{}">"#, esc(k), esc(v)))
        .collect::<Vec<_>>()
        .join("\n");
    let main = format!(
        r#"<form method="post" action="{}">
{inputs}
<p>Returning to the app…</p>
<noscript><button type="submit">Continue</button></noscript>
</form>"#,
        esc(redirect_uri)
    );
    html(StatusCode::OK, &form_action(app), doc(app, "Returning to the app", r#" data-autopost="1""#, &main))
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "public, max-age=300")], body).into_response()
}

pub(crate) async fn script() -> Response {
    asset("text/javascript; charset=utf-8", SCRIPT)
}

pub(crate) async fn style() -> Response {
    asset("text/css; charset=utf-8", STYLE)
}
