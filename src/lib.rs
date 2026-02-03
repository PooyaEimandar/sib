#![allow(dead_code)]

#[cfg(feature = "db-fdb")]
pub mod database;
pub mod network;

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
}

#[cfg(any(feature = "mtls"))]
static INIT: std::sync::Once = std::sync::Once::new();

#[cfg(any(feature = "mtls"))]
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

#[cfg(any(feature = "mtls"))]
/// Create a local CA, then issue a server cert, and optionally a client cert.
///
/// - `extra_dns_sans`: e.g. ["domain.local", "dev.myapp"] (in addition to "localhost")
/// - `extra_ip_sans`: e.g. ["10.0.0.5", "192.168.1.20"] (in addition to 127.0.0.1 and ::1)
/// - `issue_client_cert`: if true, also generates a client cert (ClientAuth EKU)
impl MtlsIdentity {
    pub fn generate(
        extra_dns_sans: &[&str],
        extra_ip_sans: &[&str],
        issue_client_cert: bool,
    ) -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
        };

        INIT.call_once(|| {
            rustls::crypto::CryptoProvider::install_default(
                rustls::crypto::aws_lc_rs::default_provider(),
            )
            .expect("install aws-lc-rs");
        });

        // --------------------------
        // 1) Create a local Root CA
        // --------------------------
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CountryName, "AE");
        ca_dn.push(DnType::OrganizationName, "Sib");
        ca_dn.push(DnType::CommonName, "Sib Local Root CA");

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("create CA params");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let ca_key = KeyPair::generate().expect("generate CA keypair");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
        let ca_cert_pem = ca_cert.pem();

        // Create an issuer so we can sign leaf certs.
        let ca_issuer = Issuer::new(ca_params, ca_key);

        // --------------------------
        // 2) Issue a Server cert
        // --------------------------
        let mut server_dn = DistinguishedName::new();
        server_dn.push(DnType::CountryName, "AE");
        server_dn.push(DnType::OrganizationName, "Sib");
        server_dn.push(DnType::CommonName, "sib-server");

        let mut server_params =
            CertificateParams::new(Vec::<String>::new()).expect("create server params");
        server_params.distinguished_name = server_dn;

        // Subject Alternative Names (SAN)
        let mut sans: Vec<SanType> = Vec::new();

        // Always include localhost + loopback IPs
        sans.push(SanType::DnsName("localhost".try_into().unwrap()));
        sans.push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        sans.push(SanType::IpAddress("::1".parse().unwrap()));

        // Add extra DNS SANs
        for d in extra_dns_sans {
            if !d.is_empty() {
                sans.push(SanType::DnsName((*d).try_into().unwrap()));
            }
        }

        // Add extra IP SANs
        for ip in extra_ip_sans {
            if !ip.is_empty() {
                sans.push(SanType::IpAddress(ip.parse().expect("invalid IP SAN")));
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

        let server_key = KeyPair::generate().expect("generate server keypair");
        let server_cert = server_params
            .signed_by(&server_key, &ca_issuer)
            .expect("sign server cert");

        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key.serialize_pem();

        // --------------------------
        // 3) Optionally issue Client cert
        // --------------------------
        let (client_cert_pem, client_key_pem) = if issue_client_cert {
            let mut client_dn = DistinguishedName::new();
            client_dn.push(DnType::CountryName, "AE");
            client_dn.push(DnType::OrganizationName, "Sib");
            client_dn.push(DnType::CommonName, "sib-client");

            let mut client_params =
                CertificateParams::new(Vec::<String>::new()).expect("create client params");
            client_params.distinguished_name = client_dn;

            // Optional SAN for client; not strictly required, but harmless.
            client_params.subject_alt_names =
                vec![SanType::DnsName("sib-client".try_into().unwrap())];

            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            client_params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            client_params.is_ca = IsCa::NoCa;

            let client_key = KeyPair::generate().expect("generate client keypair");
            let client_cert = client_params
                .signed_by(&client_key, &ca_issuer)
                .expect("sign client cert");

            (Some(client_cert.pem()), Some(client_key.serialize_pem()))
        } else {
            (None, None)
        };

        Self {
            ca_cert_pem,
            server_cert_pem,
            server_key_pem,
            client_cert_pem,
            client_key_pem,
        }
    }
}
