use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{collections::HashSet, sync::Arc};

#[derive(Debug)]
pub struct DefaultOrExactResolver {
    pub exact: HashSet<String>, // allowed exact hostnames (lowercase). leave empty to allow all.
    pub default_ck: Arc<CertifiedKey>,
}

impl ResolvesServerCert for DefaultOrExactResolver {
    fn resolve(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = ch.server_name().map(|n: &str| n.to_ascii_lowercase());
        match sni {
            // If you only want to *allow* some names, check here; otherwise always return default
            Some(name) if !self.exact.is_empty() && !self.exact.contains(&name) => {
                // Return default anyway so the handshake succeeds quietly.
                Some(self.default_ck.clone())
            }
            _ => Some(self.default_ck.clone()), // no-SNI or allowed ⇒ use default
        }
    }
}
