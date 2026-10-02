//! mTLS transport: every agent↔collector byte travels inside TLS 1.2+ with
//! certificates on BOTH sides (mutual TLS). No shared tokens — possession of
//! a CA-signed client cert IS the identity, and the server cert pins the
//! collector. Plaintext is only possible with an explicit `--insecure` flag
//! (and the collector prints a LOUD warning when it does).
use anyhow::{Context, Result};
use std::sync::Arc;

pub struct TlsFiles {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

/// Generate a CA + server cert + client cert(s) into `dir` (keys mode 600).
/// Explicit bounded validity (CA 10y, leaves 825d — the industry ceiling):
/// rcgen defaults to year-4096 certs, i.e. forever-credentials if stolen.
/// Expiry dates are printed so rotation is plannable, not discoverable.
pub fn keygen(dir: &str, server_sans: &[String], clients: &[String]) -> Result<()> {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    fn validity(days: i64) -> (time::OffsetDateTime, time::OffsetDateTime) {
        let now = time::OffsetDateTime::now_utc();
        (now, now + time::Duration::days(days))
    }
    std::fs::create_dir_all(dir)?;
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "dist-observe-ca");
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let (nb, na) = validity(3650);
    ca_params.not_before = nb;
    ca_params.not_after = na;
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Server cert: SANs for loopback + any operator-provided names/IPs.
    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    sans.extend(server_sans.iter().cloned());
    let mut srv_dn = DistinguishedName::new();
    srv_dn.push(DnType::CommonName, "dist-observe-collector");
    let mut srv_params = CertificateParams::new(sans)?;
    srv_params.distinguished_name = srv_dn;
    srv_params.is_ca = IsCa::ExplicitNoCa;
    let (snb, sna) = validity(825);
    srv_params.not_before = snb;
    srv_params.not_after = sna;
    let srv_key = KeyPair::generate()?;
    let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key)?;

    // Client cert(s), one identity per agent node name.
    let mut out: Vec<(String, String)> = vec![
        ("ca-cert.pem".into(), ca_cert.pem()),
        ("ca-key.pem".into(), ca_key.serialize_pem()),
        ("server-cert.pem".into(), srv_cert.pem()),
        ("server-key.pem".into(), srv_key.serialize_pem()),
    ];
    let mut owned = vec![];
    for name in clients {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("dist-observe-agent-{name}"));
        let mut p = CertificateParams::new(vec![])?;
        p.distinguished_name = dn;
        p.is_ca = IsCa::ExplicitNoCa;
        p.not_before = snb;
        p.not_after = sna;
        let k = KeyPair::generate()?;
        let c = p.signed_by(&k, &ca_cert, &ca_key)?;
        owned.push((format!("client-{name}-cert.pem"), c.pem()));
        owned.push((format!("client-{name}-key.pem"), k.serialize_pem()));
    }
    for (f, pem) in out.drain(..).chain(owned.drain(..)) {
        let path = format!("{dir}/{f}");
        std::fs::write(&path, pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    println!("keygen → {dir}/ (ca + server + {} client certs)", clients.len());
    println!("  validity: CA 10y (until {}), server/clients 825d (until {})",
        na.date(), sna.date());
    println!("  collector: --tls-ca {dir}/ca-cert.pem --tls-cert {dir}/server-cert.pem --tls-key {dir}/server-key.pem");
    if let Some(first) = clients.first() {
        println!("  agent:     --tls-ca {dir}/ca-cert.pem --tls-cert {dir}/client-{first}-cert.pem --tls-key {dir}/client-{first}-key.pem");
    }
    Ok(())
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls_pki_types::pem::PemObject;
    let bytes = std::fs::read(path).with_context(|| format!("open {path}"))?;
    Ok(rustls::pki_types::CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()?)
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls_pki_types::pem::PemObject;
    let bytes = std::fs::read(path).with_context(|| format!("open {path}"))?;
    rustls::pki_types::PrivateKeyDer::pem_slice_iter(&bytes)
        .next()
        .with_context(|| format!("no private key in {path}"))?
        .map_err(anyhow::Error::from)
}

fn roots(ca: &str) -> Result<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    for c in load_certs(ca)? {
        store.add(c)?;
    }
    Ok(store)
}

pub fn server_config(f: &TlsFiles) -> Result<Arc<rustls::ServerConfig>> {
    let verifier = rustls::server::WebPkiClientVerifier::builder(roots(&f.ca)?.into())
        .build()
        .context("client-cert verifier")?;
    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(&f.cert)?, load_key(&f.key)?)?;
    Ok(Arc::new(cfg))
}

pub fn client_config(f: &TlsFiles) -> Result<Arc<rustls::ClientConfig>> {
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots(&f.ca)?)
        .with_client_auth_cert(load_certs(&f.cert)?, load_key(&f.key)?)?;
    Ok(Arc::new(cfg))
}

pub fn server_name() -> Result<rustls::pki_types::ServerName<'static>> {
    rustls::pki_types::ServerName::try_from("localhost")
        .context("server name")
        .map(|n| n.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn test_pki(tag: &str) -> (TlsFiles, TlsFiles) {
        let dir = format!(
            "{}/dist-obs-test-{}-{}",
            std::env::temp_dir().display(),
            tag,
            std::process::id()
        );
        let _ = std::fs::remove_dir_all(&dir);
        keygen(&dir, &[], &["node-a".to_string()]).unwrap();
        let srv = TlsFiles {
            ca: format!("{dir}/ca-cert.pem"),
            cert: format!("{dir}/server-cert.pem"),
            key: format!("{dir}/server-key.pem"),
        };
        let cli = TlsFiles {
            ca: format!("{dir}/ca-cert.pem"),
            cert: format!("{dir}/client-node-a-cert.pem"),
            key: format!("{dir}/client-node-a-key.pem"),
        };
        (srv, cli)
    }

    /// Accept one connection, complete the handshake, echo one byte.
    /// Returns Ok(byte) or the handshake/IO error (rejection path).
    fn serve_once(
        cfg: Arc<rustls::ServerConfig>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<Result<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let h = std::thread::spawn(move || -> Result<u8> {
            let (mut sock, _) = listener.accept()?;
            sock.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut conn = rustls::ServerConnection::new(cfg)?;
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            let mut b = [0u8; 1];
            tls.read_exact(&mut b)?; // handshake completes here — or REJECTS
            tls.write_all(&b)?;
            tls.flush()?;
            Ok(b[0])
        });
        (addr, h)
    }

    fn client_byte(
        addr: &std::net::SocketAddr,
        cfg: &Arc<rustls::ClientConfig>,
    ) -> Result<u8> {
        let mut sock = std::net::TcpStream::connect(addr)?;
        sock.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut conn = rustls::ClientConnection::new(Arc::clone(cfg), server_name()?)?;
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(b"Q")?;
        tls.flush()?;
        let mut b = [0u8; 1];
        tls.read_exact(&mut b)?;
        Ok(b[0])
    }

    #[test]
    fn mtls_accepts_valid_client_cert() {
        let (srv, cli) = test_pki("accept");
        let (addr, h) = serve_once(server_config(&srv).unwrap());
        let got = client_byte(&addr, &client_config(&cli).unwrap()).unwrap();
        assert_eq!(got, b'Q');
        assert_eq!(h.join().unwrap().unwrap(), b'Q');
    }

    #[test]
    fn mtls_rejects_client_without_cert() {
        let (srv, cli) = test_pki("nocert");
        let (addr, h) = serve_once(server_config(&srv).unwrap());
        // Same CA roots, but NO client certificate at all.
        let roots = {
            let mut s = rustls::RootCertStore::empty();
            for c in super::load_certs(&cli.ca).unwrap() {
                s.add(c).unwrap();
            }
            s
        };
        let no_cert = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let _ = client_byte(&addr, &no_cert); // client side fails or gets RST
        let err = h.join().unwrap().expect_err("server must reject cert-less client");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("certificate") || msg.contains("Certificate"),
            "unexpected: {msg}"
        );
    }
}
