//! The id_token signing key (ES256, P-256) and the published key set. A key's
//! `kid` is its RFC 7638 thumbprint, so it needs no configuration.

use p256::ecdsa::{SigningKey, VerifyingKey};
use serde_json::{json, Value as J};

pub fn parse_pem(pem: &str) -> Result<SigningKey, String> {
    use p256::pkcs8::DecodePrivateKey as _;
    let sk = p256::SecretKey::from_pkcs8_pem(pem.trim()).map_err(|e| format!("not a PKCS#8 P-256 key: {e}"))?;
    Ok(SigningKey::from(&sk))
}

/// A new key as PKCS#8 PEM.
pub fn generate_pem() -> String {
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
    let sk = p256::SecretKey::generate();
    sk.to_pkcs8_pem(LineEnding::LF).expect("encoding a fresh key").to_string()
}

pub(crate) struct Keys {
    signing: SigningKey,
    kid: String,
    jwks: J,
}

fn jwk(vk: &VerifyingKey) -> (String, J) {
    let pt = vk.to_sec1_point(false);
    let (x, y) = (crate::b64u(&pt.as_bytes()[1..33]), crate::b64u(&pt.as_bytes()[33..65]));
    // RFC 7638: the required members, lexicographic, no whitespace
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let kid = crate::b64u(<sha2::Sha256 as sha2::Digest>::digest(canonical.as_bytes()));
    let k = json!({"kty": "EC", "crv": "P-256", "x": x, "y": y, "use": "sig", "alg": "ES256", "kid": kid});
    (kid, k)
}

impl Keys {
    pub fn new(signing: &SigningKey, retired: &[VerifyingKey]) -> Keys {
        let (kid, current) = jwk(signing.verifying_key());
        let mut keys = vec![current];
        keys.extend(retired.iter().map(|vk| jwk(vk).1).filter(|k| k["kid"] != kid));
        Keys { signing: signing.clone(), kid, jwks: json!({ "keys": keys }) }
    }

    pub fn jwks(&self) -> &J {
        &self.jwks
    }

    /// A compact JWS over `claims`.
    pub fn sign(&self, claims: &J) -> String {
        use p256::ecdsa::signature::Signer as _;
        let header = json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"});
        let input = format!(
            "{}.{}",
            crate::b64u(serde_json::to_vec(&header).unwrap()),
            crate::b64u(serde_json::to_vec(claims).unwrap())
        );
        let sig: p256::ecdsa::Signature = self.signing.sign(input.as_bytes());
        format!("{input}.{}", crate::b64u(sig.to_bytes()))
    }
}
