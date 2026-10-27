//! The bridge over HTTP, with this test as vlpds (the client) and a wallet.

use p256::ecdsa::signature::Verifier as _;
use serde_json::{json, Value as J};
use signin_bridge::siwe::{checksum, eip191, keccak};
use signin_bridge::{App, Config, SiweConfig};
use std::collections::HashMap;

const CLIENT_ID: &str = "vlpds";
const SECRET: &str = "a-client-secret-of-at-least-32-chars";
const REDIRECT: &str = "https://pds.example.com/oauth/federated/callback/wallet";

struct Bridge {
    base: String,
    issuer: String,
    http: reqwest::Client,
}

async fn start(rpc: HashMap<u64, url::Url>) -> Bridge {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}/bridge", listener.local_addr().unwrap().port());
    let key = signin_bridge::keys::parse_pem(&signin_bridge::keys::generate_pem()).unwrap();
    let app = App::new(Config {
        public_url: url::Url::parse(&base).unwrap(),
        client_id: CLIENT_ID.into(),
        client_secret: SECRET.into(),
        redirect_uris: vec![REDIRECT.into()],
        signing_key: key,
        retired_keys: vec![],
        siwe: SiweConfig { statement: "Sign in to the PDS.".into(), chains: vec![1, 8453], rpc },
    })
    .unwrap();
    tokio::spawn(async move { axum::serve(listener, signin_bridge::router(app)).await.unwrap() });
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    Bridge { issuer: format!("{base}/siwe"), base, http }
}

struct Wallet(k256::ecdsa::SigningKey);

impl Wallet {
    fn new() -> Wallet {
        Wallet(k256::ecdsa::SigningKey::from_slice(&rand::random::<[u8; 32]>()).unwrap())
    }

    fn address(&self) -> [u8; 20] {
        let pt = self.0.verifying_key().to_sec1_point(false);
        keccak(&pt.as_bytes()[1..])[12..].try_into().unwrap()
    }

    fn sign(&self, msg: &str) -> String {
        let (sig, rec) = self.0.sign_prehash_recoverable(&eip191(msg));
        format!("0x{}{:02x}", hex::encode(sig.to_bytes()), 27 + rec.to_byte())
    }
}

/// What vlpds keeps for one sign-in.
struct Flow {
    verifier: String,
    nonce: String,
    state: String,
}

impl Flow {
    fn new() -> Flow {
        Flow {
            verifier: format!("v{}", hex::encode(rand::random::<[u8; 24]>())),
            nonce: hex::encode(rand::random::<[u8; 8]>()),
            state: hex::encode(rand::random::<[u8; 8]>()),
        }
    }

    fn params(&self) -> Vec<(&'static str, String)> {
        use sha2::Digest as _;
        let challenge = base64_url(&sha2::Sha256::digest(self.verifier.as_bytes()));
        vec![
            ("response_type", "code".into()),
            ("client_id", CLIENT_ID.into()),
            ("redirect_uri", REDIRECT.into()),
            ("scope", "openid profile".into()),
            ("state", self.state.clone()),
            ("nonce", self.nonce.clone()),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256".into()),
        ]
    }
}

fn base64_url(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A browser on the sign-in page: its cookie and the request id.
struct Page {
    cookie: String,
    request: String,
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> &'a str {
    let i = s.find(start).unwrap() + start.len();
    &s[i..i + s[i..].find(end).unwrap()]
}

fn location(r: &reqwest::Response) -> url::Url {
    url::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap()
}

fn query(u: &url::Url) -> HashMap<String, String> {
    u.query_pairs().into_owned().collect()
}

impl Bridge {
    async fn authorize(&self, params: &[(&str, String)]) -> reqwest::Response {
        self.http.get(format!("{}/authorize", self.issuer)).query(params).send().await.unwrap()
    }

    async fn open(&self, f: &Flow) -> Page {
        let r = self.authorize(&f.params()).await;
        assert_eq!(r.status(), 200);
        let cookie = r.headers()["set-cookie"].to_str().unwrap();
        assert!(cookie.contains("Path=/bridge") && cookie.contains("HttpOnly"), "{cookie}");
        let cookie = cookie.split(';').next().unwrap().to_string();
        let html = r.text().await.unwrap();
        Page { cookie, request: between(&html, "data-request=\"", "\"").to_string() }
    }

    async fn post(&self, cookie: &str, path: &str, body: J) -> (u16, J) {
        let r = self.http.post(format!("{}/{path}", self.issuer)).header("cookie", cookie).json(&body).send().await;
        let r = r.unwrap();
        (r.status().as_u16(), r.json().await.unwrap())
    }

    async fn message(&self, p: &Page, address: &[u8; 20]) -> String {
        let (st, j) =
            self.post(&p.cookie, "challenge", json!({"request": p.request, "address": checksum(address)})).await;
        assert_eq!(st, 200, "{j}");
        j["message"].as_str().unwrap().to_string()
    }

    async fn verify(&self, p: &Page, message: &str, signature: &str) -> (u16, J) {
        self.post(&p.cookie, "verify", json!({"request": p.request, "message": message, "signature": signature})).await
    }

    async fn get(&self, cookie: &str, url: &str) -> reqwest::Response {
        let url = if url.starts_with('/') {
            format!("http://{}{url}", between(&self.base, "http://", "/"))
        } else {
            url.into()
        };
        self.http.get(url).header("cookie", cookie).send().await.unwrap()
    }

    /// A wallet signs in on `p`; the redirect back to vlpds.
    async fn sign_in(&self, p: &Page, w: &Wallet) -> url::Url {
        let msg = self.message(p, &w.address()).await;
        let (st, j) = self.verify(p, &msg, &w.sign(&msg)).await;
        assert_eq!(st, 200, "{j}");
        let r = self.get(&p.cookie, j["next"].as_str().unwrap()).await;
        assert_eq!(r.status(), 303);
        location(&r)
    }

    async fn token(&self, form: &[(&str, &str)], basic: Option<(&str, &str)>) -> (u16, J) {
        let mut rb = self.http.post(format!("{}/token", self.issuer)).form(form);
        if let Some((id, secret)) = basic {
            rb = rb.basic_auth(id, Some(secret));
        }
        let r = rb.send().await.unwrap();
        (r.status().as_u16(), r.json().await.unwrap())
    }

    async fn exchange(&self, code: &str, f: &Flow) -> (u16, J) {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", f.verifier.as_str()),
        ];
        self.token(&form, Some((CLIENT_ID, SECRET))).await
    }

    /// The id_token's claims, after checking its signature against the
    /// published key set as vlpds does.
    async fn claims(&self, id_token: &str) -> J {
        let disc: J = self
            .http
            .get(format!("{}/.well-known/openid-configuration", self.issuer))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(disc["issuer"], json!(self.issuer));
        assert_eq!(disc["authorization_response_iss_parameter_supported"], json!(true));
        let jwks: J = self.http.get(disc["jwks_uri"].as_str().unwrap()).send().await.unwrap().json().await.unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        let dec = |s: &str| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
        };
        let header: J = serde_json::from_slice(&dec(parts[0])).unwrap();
        assert_eq!(header["alg"], "ES256");
        let k = jwks["keys"].as_array().unwrap().iter().find(|k| k["kid"] == header["kid"]).expect("kid in jwks");
        let pt = [&[4u8][..], &dec(k["x"].as_str().unwrap()), &dec(k["y"].as_str().unwrap())].concat();
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pt).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&dec(parts[2])).unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).expect("id_token signature");
        serde_json::from_slice(&dec(parts[1])).unwrap()
    }
}

#[tokio::test]
async fn a_wallet_signs_in_and_the_client_gets_its_identity() {
    let b = start(HashMap::new()).await;
    let f = Flow::new();
    let p = b.open(&f).await;
    let w = Wallet::new();
    let back = b.sign_in(&p, &w).await;
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    let q = query(&back);
    assert_eq!(q["state"], f.state);
    assert_eq!(q["iss"], b.issuer);

    let (st, t) = b.exchange(&q["code"], &f).await;
    assert_eq!(st, 200, "{t}");
    let c = b.claims(t["id_token"].as_str().unwrap()).await;
    assert_eq!(c["iss"], json!(b.issuer));
    assert_eq!(c["aud"], json!(CLIENT_ID));
    assert_eq!(c["nonce"], json!(f.nonce));
    assert_eq!(c["sub"], json!(format!("eip155:1:0x{}", hex::encode(w.address()))));
    assert_eq!(c["preferred_username"], json!(checksum(&w.address())));

    // a code works once
    let (st, t) = b.exchange(&q["code"], &f).await;
    assert_eq!((st, &t["error"]), (400, &json!("invalid_grant")));

    // the same wallet again gets the same subject
    let f2 = Flow::new();
    let p2 = b.open(&f2).await;
    let q2 = query(&b.sign_in(&p2, &w).await);
    let (_, t2) = b.exchange(&q2["code"], &f2).await;
    assert_eq!(b.claims(t2["id_token"].as_str().unwrap()).await["sub"], c["sub"]);
}

#[tokio::test]
async fn token_requests_need_the_client_and_the_verifier() {
    let b = start(HashMap::new()).await;
    let f = Flow::new();
    let p = b.open(&f).await;
    let code = query(&b.sign_in(&p, &Wallet::new()).await)["code"].clone();

    let wrong_secret = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", "x"),
    ];
    let (st, j) = b.token(&wrong_secret, Some((CLIENT_ID, "not-the-secret-not-the-secret-not-the"))).await;
    assert_eq!((st, &j["error"]), (401, &json!("invalid_client")));

    // client_secret_post works the same, and a wrong verifier burns the code
    let bad_verifier = "a".repeat(43);
    let post = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", bad_verifier.as_str()),
        ("client_id", CLIENT_ID),
        ("client_secret", SECRET),
    ];
    let (st, j) = b.token(&post, None).await;
    assert_eq!((st, &j["error"]), (400, &json!("invalid_grant")));
    let (st, _) = b.exchange(&code, &f).await;
    assert_eq!(st, 400);
}

#[tokio::test]
async fn only_the_browser_that_started_can_continue() {
    let b = start(HashMap::new()).await;
    let p = b.open(&Flow::new()).await;
    let other = b.open(&Flow::new()).await;
    let w = Wallet::new();
    let stolen = Page { cookie: other.cookie.clone(), request: p.request.clone() };
    let (st, _) =
        b.post(&stolen.cookie, "challenge", json!({"request": p.request, "address": checksum(&w.address())})).await;
    assert_eq!(st, 400);

    let msg = b.message(&p, &w.address()).await;
    let (st, _) = b.verify(&stolen, &msg, &w.sign(&msg)).await;
    assert_eq!(st, 400);
    let (st, j) = b.verify(&p, &msg, &w.sign(&msg)).await;
    assert_eq!(st, 200);
    let next = j["next"].as_str().unwrap();
    assert_eq!(b.get(&other.cookie, next).await.status(), 400);
    assert_eq!(b.get(&p.cookie, next).await.status(), 303);
    // and once
    assert_eq!(b.get(&p.cookie, next).await.status(), 400);
}

#[tokio::test]
async fn a_signature_by_another_key_is_refused_and_tries_run_out() {
    let b = start(HashMap::new()).await;
    let p = b.open(&Flow::new()).await;
    let (victim, thief) = (Wallet::new(), Wallet::new());
    let msg = b.message(&p, &victim.address()).await;
    for i in 1..=5 {
        let (st, j) = b.verify(&p, &msg, &thief.sign(&msg)).await;
        assert_eq!(st, 400, "{j}");
        assert_eq!(j["error"].as_str().unwrap().contains("last try"), i == 5, "{j}");
    }
    let (st, _) = b.verify(&p, &msg, &victim.sign(&msg)).await;
    assert_eq!(st, 400, "the request is gone after five failures");
}

#[tokio::test]
async fn a_message_built_elsewhere_must_name_this_service_and_request() {
    let b = start(HashMap::new()).await;
    let f = Flow::new();
    let p = b.open(&f).await;
    let w = Wallet::new();
    let good = b.message(&p, &w.address()).await;
    for (from, to) in [
        ("127.0.0.1:", "evil.example:"),
        ("URI: http://", "URI: https://"),
        ("Chain ID: 1", "Chain ID: 10"),
        ("Nonce: ", "Nonce: 0"),
    ] {
        let bad = good.replacen(from, to, 1);
        let (st, j) = b.verify(&p, &bad, &w.sign(&bad)).await;
        assert_eq!(st, 400, "{from} -> {to}: {j}");
    }
    // another allowed chain, as a frontend that builds its own message might:
    // the chain is part of the subject
    let base = good.replace("Chain ID: 1", "Chain ID: 8453");
    let (st, j) = b.verify(&p, &base, &w.sign(&base)).await;
    assert_eq!(st, 200, "{j}");
    let r = b.get(&p.cookie, j["next"].as_str().unwrap()).await;
    let (_, t) = b.exchange(&query(&location(&r))["code"], &f).await;
    let sub = b.claims(t["id_token"].as_str().unwrap()).await["sub"].clone();
    assert_eq!(sub, json!(format!("eip155:8453:0x{}", hex::encode(w.address()))));
}

#[tokio::test]
async fn bad_authorize_requests() {
    let b = start(HashMap::new()).await;
    let f = Flow::new();
    let with = |k: &'static str, v: Option<&str>| {
        let mut p: Vec<(&str, String)> = f.params().into_iter().filter(|(n, _)| *n != k).collect();
        if let Some(v) = v {
            p.push((k, v.into()));
        }
        p
    };
    // an unknown redirect URI or client never redirects
    let r = b.authorize(&with("redirect_uri", Some("https://evil.example/cb"))).await;
    assert_eq!(r.status(), 400);
    assert!(r.headers().get("location").is_none());
    assert_eq!(b.authorize(&with("client_id", Some("other"))).await.status(), 400);

    for (params, error) in [
        (with("code_challenge", None), "invalid_request"),
        (with("code_challenge_method", Some("plain")), "invalid_request"),
        (with("nonce", None), "invalid_request"),
        (with("scope", Some("profile")), "invalid_scope"),
        (with("response_type", Some("token")), "unsupported_response_type"),
        (with("prompt", Some("none")), "login_required"),
    ] {
        let r = b.authorize(&params).await;
        assert_eq!(r.status(), 303);
        let q = query(&location(&r));
        assert_eq!(q["error"], error);
        assert_eq!(q["state"], f.state);
        assert_eq!(q["iss"], b.issuer);
    }
}

#[tokio::test]
async fn cancel_and_form_post_return_to_the_client() {
    let b = start(HashMap::new()).await;
    let f = Flow::new();
    let p = b.open(&f).await;
    let r = b
        .http
        .post(format!("{}/cancel", b.issuer))
        .header("cookie", &p.cookie)
        .form(&[("request", p.request.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let q = query(&location(&r));
    assert_eq!((q["error"].as_str(), q["state"].as_str()), ("access_denied", f.state.as_str()));

    let mut params = f.params();
    params.push(("response_mode", "form_post".into()));
    let r = b.authorize(&params).await;
    let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let p = Page { cookie, request: between(&r.text().await.unwrap(), "data-request=\"", "\"").to_string() };
    let w = Wallet::new();
    let msg = b.message(&p, &w.address()).await;
    let (_, j) = b.verify(&p, &msg, &w.sign(&msg)).await;
    let r = b.get(&p.cookie, j["next"].as_str().unwrap()).await;
    assert_eq!(r.status(), 200);
    let csp = r.headers()["content-security-policy"].to_str().unwrap().to_string();
    assert!(csp.contains("form-action 'self' https://pds.example.com"), "{csp}");
    let html = r.text().await.unwrap();
    assert!(html.contains(&format!(r#"<form method="post" action="{REDIRECT}">"#)), "{html}");
    let code = between(&html, r#"name="code" value=""#, "\"");
    assert!(html.contains(&format!(r#"name="state" value="{}""#, f.state)));
    let (st, t) = b.exchange(code, &f).await;
    assert_eq!(st, 200, "{t}");
}

/// A JSON-RPC endpoint standing in for a chain: the validator call is
/// valid only for `valid`'s address.
async fn fake_chain(valid: [u8; 20]) -> url::Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let handler = move |axum::Json(req): axum::Json<J>| async move {
        let data = req["params"][0]["data"].as_str().unwrap().to_string();
        assert_eq!(req["method"], "eth_call");
        assert!(data.starts_with("0x608060405234801561001057600080fd5b50"), "the ERC-6492 validator's creation code");
        if data.contains(&format!("000000000000000000000000{}", hex::encode(valid))) {
            axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": "0x01"}))
        } else {
            axum::Json(json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}))
        }
    };
    tokio::spawn(async move {
        axum::serve(listener, axum::Router::new().route("/", axum::routing::post(handler))).await.unwrap()
    });
    url
}

#[tokio::test]
async fn contract_wallets_are_checked_on_their_chain() {
    // a Safe's address: its owner's key signs, which recovers to another address
    let safe = [0x5a; 20];
    let owner = Wallet::new();
    let rpc = HashMap::from([(1, fake_chain(safe).await)]);
    let b = start(rpc).await;
    let f = Flow::new();
    let p = b.open(&f).await;
    let msg = b.message(&p, &safe).await;
    let (st, j) = b.verify(&p, &msg, &owner.sign(&msg)).await;
    assert_eq!(st, 200, "{j}");
    let r = b.get(&p.cookie, j["next"].as_str().unwrap()).await;
    let (_, t) = b.exchange(&query(&location(&r))["code"], &f).await;
    assert_eq!(
        b.claims(t["id_token"].as_str().unwrap()).await["sub"],
        json!(format!("eip155:1:0x{}", hex::encode(safe)))
    );

    // the chain says no
    let p = b.open(&Flow::new()).await;
    let msg = b.message(&p, &[0x77; 20]).await;
    let (st, _) = b.verify(&p, &msg, &owner.sign(&msg)).await;
    assert_eq!(st, 400);

    // no RPC for chain 8453: a contract wallet there can't sign in
    let p = b.open(&Flow::new()).await;
    let (st, j) = b
        .post(&p.cookie, "challenge", json!({"request": p.request, "address": checksum(&safe), "chainId": 8453}))
        .await;
    assert_eq!(st, 200);
    let msg = j["message"].as_str().unwrap();
    let (st, j) = b.verify(&p, msg, &owner.sign(msg)).await;
    assert_eq!(st, 400);
    assert!(j["error"].as_str().unwrap().contains("Smart-contract wallets"), "{j}");
}
