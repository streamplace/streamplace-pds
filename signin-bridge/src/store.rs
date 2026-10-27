//! Pending sign-ins and issued codes, in memory.

use crate::Method;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a sign-in may take, from `/authorize` to `/finish`.
pub const REQUEST_TTL: Duration = Duration::from_secs(600);
pub const CODE_TTL: Duration = Duration::from_secs(60);
/// Pending sign-ins held at once; `/authorize` answers 503 past it.
const MAX_PENDING: usize = 100_000;
const MAX_CODES: usize = 100_000;
/// Failed completions (a bad signature) before the request is dropped.
pub const MAX_ATTEMPTS: u32 = 5;

/// Who signed in.
#[derive(Clone, Debug)]
pub struct Subject {
    pub sub: String,
    /// A display name (`preferred_username`), sent with the `profile` scope.
    pub display: Option<String>,
    pub auth_time: i64,
}

/// An authorization request waiting for its method to complete it.
pub struct Pending {
    pub method: Method,
    /// The cookie of the browser that started it: only that browser can
    /// complete it or collect the code.
    pub browser: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: String,
    pub code_challenge: String,
    pub form_post: bool,
    pub profile: bool,
    pub created: i64,
    pub expires: Instant,
    /// The SIWE message's nonce.
    pub siwe_nonce: String,
    pub attempts: u32,
    pub done: Option<Subject>,
}

pub struct Code {
    pub method: Method,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub nonce: String,
    pub profile: bool,
    pub subject: Subject,
    pub expires: Instant,
}

#[derive(Default)]
pub struct Store {
    pending: Mutex<HashMap<String, Pending>>,
    codes: Mutex<HashMap<String, Code>>,
}

#[derive(Debug)]
pub struct Full;

/// The request is unknown, expired, or another browser's.
#[derive(Debug, PartialEq, Eq)]
pub struct Gone;

impl Store {
    pub fn insert_pending(&self, id: String, p: Pending) -> Result<(), Full> {
        let mut m = self.pending.lock();
        if m.len() >= MAX_PENDING {
            let now = Instant::now();
            m.retain(|_, p| p.expires > now);
            if m.len() >= MAX_PENDING {
                return Err(Full);
            }
        }
        m.insert(id, p);
        Ok(())
    }

    /// Runs `f` on the request `id` if `browser` started it, `method` serves
    /// it and it hasn't expired.
    pub fn with_pending<T>(
        &self,
        id: &str,
        method: Method,
        browser: &str,
        f: impl FnOnce(&mut Pending) -> T,
    ) -> Result<T, Gone> {
        let mut m = self.pending.lock();
        match m.get_mut(id) {
            Some(p) if p.method == method && crate::ct_eq(&p.browser, browser) && p.expires > Instant::now() => {
                Ok(f(p))
            }
            _ => Err(Gone),
        }
    }

    /// Removes the request `id` if `browser` started it, `method` serves it,
    /// it hasn't expired and `take` says so.
    pub fn take_pending(
        &self,
        id: &str,
        method: Method,
        browser: &str,
        take: impl FnOnce(&Pending) -> bool,
    ) -> Result<Option<Pending>, Gone> {
        let mut m = self.pending.lock();
        match m.get(id) {
            Some(p) if p.method == method && crate::ct_eq(&p.browser, browser) && p.expires > Instant::now() => {
                Ok(take(p).then(|| m.remove(id)).flatten())
            }
            _ => Err(Gone),
        }
    }

    pub fn remove_pending(&self, id: &str) {
        self.pending.lock().remove(id);
    }

    pub fn insert_code(&self, code: String, c: Code) -> Result<(), Full> {
        let mut m = self.codes.lock();
        if m.len() >= MAX_CODES {
            let now = Instant::now();
            m.retain(|_, c| c.expires > now);
            if m.len() >= MAX_CODES {
                return Err(Full);
            }
        }
        m.insert(code, c);
        Ok(())
    }

    /// The code, once: a second exchange finds nothing.
    pub fn take_code(&self, code: &str) -> Option<Code> {
        self.codes.lock().remove(code).filter(|c| c.expires > Instant::now())
    }

    pub fn gc(&self) {
        let now = Instant::now();
        self.pending.lock().retain(|_, p| p.expires > now);
        self.codes.lock().retain(|_, c| c.expires > now);
    }
}
