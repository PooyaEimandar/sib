#![allow(dead_code)]
// Runtime code must not panic on unwrap, expect or assert (see [lints.clippy]
// in Cargo.toml); unit tests may. The non-test build still checks everything else.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_macros)
)]

#[cfg(feature = "db-fdb")]
pub mod database;
pub mod network;

#[cfg(feature = "render")]
pub mod render;

#[cfg(any(
    feature = "stm-udp-receiver",
    feature = "stm-udp-sender",
    feature = "stm-webrtc-sender"
))]
pub mod stream;

#[cfg(any(feature = "rt-may", feature = "net-h1-server"))]
pub fn init_global_poller(num_of_workers: usize, stack_size: usize) {
    may::config()
        .set_workers(num_of_workers)
        .set_stack_size(stack_size);

    #[cfg(feature = "net-h1-server")]
    crate::network::http::date::start_date_ticker();
}

#[cfg(feature = "mtls")]
static INIT: std::sync::Once = std::sync::Once::new();

#[cfg(feature = "mtls")]
#[derive(Debug, Clone)]
pub struct MtlsIdentity {
    /// Root CA cert (PEM). Clients should trust this to validate the server cert.
    pub ca_cert_pem: String,

    /// Server cert/key (PEM). Use these in your server rustls config.
    pub server_cert_pem: String,
    pub server_key_pem: String,

    /// Optional client cert/key (PEM). Use these for mTLS client auth.
    pub client_cert_pem: Option<String>,
    pub client_key_pem: Option<String>,
}

#[cfg(feature = "mtls")]
/// Create a local CA, then issue a server cert, and optionally a client cert.
///
/// - `extra_dns_sans`: e.g. ["domain.local", "dev.myapp"] (in addition to "localhost")
/// - `extra_ip_sans`: e.g. ["10.0.0.5", "192.168.1.20"] (in addition to 127.0.0.1 and ::1)
/// - `issue_client_cert`: if true, also generates a client cert (ClientAuth EKU)
///
/// Fails if a SAN is invalid or a key or certificate cannot be generated.
impl MtlsIdentity {
    pub fn generate(
        extra_dns_sans: &[&str],
        extra_ip_sans: &[&str],
        issue_client_cert: bool,
    ) -> std::io::Result<Self> {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
        };
        use std::{
            io::{Error, ErrorKind},
            net::{IpAddr, Ipv4Addr, Ipv6Addr},
        };

        INIT.call_once(|| {
            // Fails only if the application already installed a provider; keep it.
            let _ = rustls::crypto::CryptoProvider::install_default(
                rustls::crypto::aws_lc_rs::default_provider(),
            );
        });
        let invalid_san = |e: rcgen::Error| Error::new(ErrorKind::InvalidInput, e);

        // Create a local Root CA
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CountryName, "AE");
        ca_dn.push(DnType::OrganizationName, "Sib");
        ca_dn.push(DnType::CommonName, "Sib Local Root CA");

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(Error::other)?;
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let ca_key = KeyPair::generate().map_err(Error::other)?;
        let ca_cert = ca_params.self_signed(&ca_key).map_err(Error::other)?;
        let ca_cert_pem = ca_cert.pem();

        // Create an issuer so we can sign leaf certs.
        let ca_issuer = Issuer::new(ca_params, ca_key);

        // Issue a Server cert
        let mut server_dn = DistinguishedName::new();
        server_dn.push(DnType::CountryName, "AE");
        server_dn.push(DnType::OrganizationName, "Sib");
        server_dn.push(DnType::CommonName, "sib-server");

        let mut server_params =
            CertificateParams::new(Vec::<String>::new()).map_err(Error::other)?;
        server_params.distinguished_name = server_dn;

        // Subject Alternative Names (SAN)
        let mut sans: Vec<SanType> = Vec::new();

        // Always include localhost + loopback IPs
        sans.push(SanType::DnsName(
            "localhost".try_into().map_err(invalid_san)?,
        ));
        sans.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        sans.push(SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // Add extra DNS SANs
        for d in extra_dns_sans {
            if !d.is_empty() {
                sans.push(SanType::DnsName((*d).try_into().map_err(invalid_san)?));
            }
        }

        // Add extra IP SANs
        for ip in extra_ip_sans {
            if !ip.is_empty() {
                let ip = ip
                    .parse()
                    .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
                sans.push(SanType::IpAddress(ip));
            }
        }

        server_params.subject_alt_names = sans;

        // EKU + KeyUsage for TLS server
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            // KeyEncipherment for RSA key exchange scenarios; harmless for ECDSA too
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.is_ca = IsCa::NoCa;

        let server_key = KeyPair::generate().map_err(Error::other)?;
        let server_cert = server_params
            .signed_by(&server_key, &ca_issuer)
            .map_err(Error::other)?;

        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key.serialize_pem();

        // Optionally issue Client cert
        let (client_cert_pem, client_key_pem) = if issue_client_cert {
            let mut client_dn = DistinguishedName::new();
            client_dn.push(DnType::CountryName, "AE");
            client_dn.push(DnType::OrganizationName, "Sib");
            client_dn.push(DnType::CommonName, "sib-client");

            let mut client_params =
                CertificateParams::new(Vec::<String>::new()).map_err(Error::other)?;
            client_params.distinguished_name = client_dn;

            // Optional SAN for client; not strictly required, but harmless.
            client_params.subject_alt_names = vec![SanType::DnsName(
                "sib-client".try_into().map_err(invalid_san)?,
            )];

            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            client_params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            client_params.is_ca = IsCa::NoCa;

            let client_key = KeyPair::generate().map_err(Error::other)?;
            let client_cert = client_params
                .signed_by(&client_key, &ca_issuer)
                .map_err(Error::other)?;

            (Some(client_cert.pem()), Some(client_key.serialize_pem()))
        } else {
            (None, None)
        };

        Ok(Self {
            ca_cert_pem,
            server_cert_pem,
            server_key_pem,
            client_cert_pem,
            client_key_pem,
        })
    }
}

#[cfg(all(test, feature = "mtls"))]
#[path = "../tests/unit/mtls_tests.rs"]
mod mtls_tests;
