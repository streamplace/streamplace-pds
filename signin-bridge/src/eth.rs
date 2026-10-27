//! Contract wallet signatures, checked on chain. One `eth_call` runs the
//! ERC-6492 universal validator without deploying it: it answers for a
//! deployed ERC-1271 wallet (`isValidSignature`) and for an undeployed one
//! whose signature carries its factory call (ERC-6492), as viem's
//! `verifyHash` does. It reverts for a plain key's signature, so callers
//! recover those first.

use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

/// The validator's creation code: viem 2.47.2,
/// `erc6492SignatureValidatorByteCode` in `src/constants/contracts.ts`.
const VALIDATOR: &str = include_str!("erc6492_validator.hex");
const CALL_DEADLINE: Duration = Duration::from_secs(10);
/// Concurrent calls to the RPC endpoints, so a burst of bad signatures
/// can't run up the operator's RPC bill faster than this.
const MAX_IN_FLIGHT: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    Valid,
    Invalid,
    /// No RPC endpoint for the chain.
    NoRpc,
    /// The endpoint failed; the signature may be fine.
    Unavailable(String),
}

pub struct Rpc {
    client: reqwest::Client,
    urls: HashMap<u64, url::Url>,
    slots: tokio::sync::Semaphore,
}

/// The validator's constructor arguments, ABI-encoded: `(address, bytes32,
/// bytes)`.
fn encode_args(addr: &[u8; 20], hash: &[u8; 32], sig: &[u8]) -> Vec<u8> {
    let word = |n: usize| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(n as u64).to_be_bytes());
        w
    };
    let mut out = Vec::with_capacity(32 * 5 + sig.len());
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(addr);
    out.extend_from_slice(hash);
    out.extend_from_slice(&word(0x60));
    out.extend_from_slice(&word(sig.len()));
    out.extend_from_slice(sig);
    out.resize(out.len().div_ceil(32) * 32, 0);
    out
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<String>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

impl Rpc {
    pub fn new(urls: HashMap<u64, url::Url>) -> Rpc {
        let client = reqwest::Client::builder().timeout(CALL_DEADLINE).build().expect("an HTTP client");
        Rpc { client, urls, slots: tokio::sync::Semaphore::new(MAX_IN_FLIGHT) }
    }

    /// Whether `sig` is `addr`'s signature over `hash` on `chain`.
    pub async fn check(&self, chain: u64, addr: &[u8; 20], hash: &[u8; 32], sig: &[u8]) -> Check {
        let Some(url) = self.urls.get(&chain) else { return Check::NoRpc };
        let Ok(_slot) = self.slots.acquire().await else { return Check::Unavailable("shutting down".into()) };
        let data = format!("0x{}{}", VALIDATOR.trim(), hex::encode(encode_args(addr, hash, sig)));
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"data": data}, "latest"]});
        let resp = match self.client.post(url.clone()).json(&body).send().await {
            Ok(r) => r,
            Err(e) => return Check::Unavailable(e.without_url().to_string()),
        };
        let status = resp.status();
        let r: RpcResponse = match resp.json().await {
            Ok(r) => r,
            Err(_) => return Check::Unavailable(format!("HTTP {}: not a JSON-RPC response", status.as_u16())),
        };
        match (r.result, r.error) {
            (Some(hex_result), None) => match hex::decode(hex_result.trim_start_matches("0x")) {
                // the validator returns one byte, 0x01 for a valid signature
                Ok(b) if b.last() == Some(&1) && b[..b.len() - 1].iter().all(|x| *x == 0) => Check::Valid,
                Ok(_) => Check::Invalid,
                Err(_) => Check::Unavailable("the result isn't hex".into()),
            },
            // the validator reverts on a malformed or wrong signature
            (_, Some(e)) if e.code == 3 || e.message.to_ascii_lowercase().contains("revert") => Check::Invalid,
            (_, Some(e)) => {
                Check::Unavailable(format!("RPC error {}: {}", e.code, e.message.chars().take(200).collect::<String>()))
            }
            (None, None) => Check::Unavailable("an empty JSON-RPC response".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_dynamic_bytes_after_the_head() {
        let e = encode_args(&[0xaa; 20], &[0xbb; 32], &[0xcc; 33]);
        assert_eq!(e.len(), 32 * 4 + 64);
        assert_eq!(&e[..12], &[0; 12]);
        assert_eq!(&e[12..32], &[0xaa; 20]);
        assert_eq!(e[95], 0x60);
        assert_eq!(e[127], 33);
        assert_eq!(&e[128..161], &[0xcc; 33]);
        assert!(e[161..].iter().all(|b| *b == 0));
    }
}
