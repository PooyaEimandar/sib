use super::MtlsIdentity;

#[test]
fn invalid_sans_are_errors_not_panics() {
    let dns = MtlsIdentity::generate(&["bücher.example"], &[], false);
    assert_eq!(
        dns.map(|_| ()).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::InvalidInput)
    );

    let ip = MtlsIdentity::generate(&[], &["not-an-ip"], false);
    assert_eq!(
        ip.map(|_| ()).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::InvalidInput)
    );
}

#[test]
fn generates_server_and_client_identities() {
    let identity = MtlsIdentity::generate(&["dev.local"], &["10.0.0.5"], true).unwrap();
    assert!(identity.server_cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(identity.client_cert_pem.is_some());
}
