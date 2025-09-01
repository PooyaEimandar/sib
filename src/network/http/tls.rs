// use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// pub struct Tls<'a> {
//     pub cert: &'a [u8],            // leaf certificate (PEM or DER)
//     pub chain: Option<&'a [u8]>,   // intermediates (PEM or DER, optional)
//     pub key: &'a [u8],             // private key (PEM or DER)
// }

// pub(crate) fn make_tls_acceptor(ssl: &Tls, enable_h2: bool) -> std::io::Result<futures_rustls::TlsAcceptor> {
//     use rustls::crypto::aws_lc_rs;

//     // Ensure a provider is installed
//     let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());

//     // Parse certificates (leaf + chain)
//     let mut certs = parse_certs(ssl.cert)?;
//     if let Some(chain) = ssl.chain {
//         certs.extend(parse_certs(chain)?);
//     }
//     if certs.is_empty() {
//         return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no X.509 certificates found"));
//     }

//     // Parse private key
//     let key = parse_private_key(ssl.key)?
//         .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no private key found"))?;

//     // Build config (explicit provider + safe protos)
//     let builder = rustls::ServerConfig::builder_with_provider(aws_lc_rs::default_provider().into())
//         .with_safe_default_protocol_versions()
//         .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

//     let mut cfg = builder
//         .with_no_client_auth()
//         .with_single_cert(certs, key)
//         .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

//     // ALPN: prefer h2, fall back to http/1.1
//     cfg.alpn_protocols = if enable_h2 {
//         vec![b"h2".to_vec(), b"http/1.1".to_vec()]
//     } else {
//         vec![b"http/1.1".to_vec()]
//     };

//     Ok(futures_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg)))
// }


// fn parse_certs(input: &[u8]) -> std::io::Result<Vec<CertificateDer<'static>>> {
//     let mut cur = std::io::Cursor::new(input);
//     let mut out = Vec::new();
//     for item in rustls_pemfile::read_all(&mut cur) {
//         let item = item.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
//         if let rustls_pemfile::Item::X509Certificate(der) = item {
//             out.push(CertificateDer::from(der));
//         }
//     }
//     Ok(out)
// }

// fn parse_private_key(input: &[u8]) -> std::io::Result<Option<PrivateKeyDer<'static>>> {
//     use rustls::pki_types::{PrivatePkcs8KeyDer, PrivatePkcs1KeyDer, PrivateSec1KeyDer};
    
//     let mut cur = std::io::Cursor::new(input);
//     let items: Result<Vec<rustls_pemfile::Item>, std::io::Error> = rustls_pemfile::read_all(&mut cur).collect();
//     for item in items.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))? {
//         match item {
//             rustls_pemfile::Item::Pkcs8Key(der) =>
//                 return Ok(Some(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(der)))),
//             rustls_pemfile::Item::Pkcs1Key(der) =>
//                 return Ok(Some(PrivateKeyDer::from(PrivatePkcs1KeyDer::from(der)))),
//             rustls_pemfile::Item::Sec1Key(der) =>
//                 return Ok(Some(PrivateKeyDer::from(PrivateSec1KeyDer::from(der)))),
//             _ => {}
//         }
//     }
//     Ok(None)
// }