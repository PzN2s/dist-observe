//! Outbound webhooks: POST anomaly JSON to an operator URL (PagerDuty-style
//! receiver, Slack webhook, small relay). http:// and https:// both work;
//! https uses Mozilla roots, no client cert. Best-effort and non-blocking by
//! contract: failures are logged to stderr, never abort the monitoring loop.

use anyhow::Result;

/// Fire-and-log webhook POST. Returns Ok(()) unless the SEND itself failed.
pub fn notify(url: &str, payload: &serde_json::Value) -> Result<()> {
    let body = payload.to_string();
    let (https, rest) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("http://").unwrap_or(url)),
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    if hostport.is_empty() {
        anyhow::bail!("bad webhook url");
    }
    let code = if https {
        post_https(hostport, &path, &body)?
    } else {
        let (code, _) = crate::net::Conn::connect(hostport, &None)?.post(hostport, &path, &body)?;
        code
    };
    if !(200..300).contains(&code) {
        anyhow::bail!("webhook HTTP {code}");
    }
    Ok(())
}

fn post_https(hostport: &str, path: &str, body: &str) -> Result<u16> {
    use std::io::{Read, Write};
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let host = hostport.split(':').next().unwrap_or(hostport);
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("bad webhook host"))?;
    let sock = std::net::TcpStream::connect(hostport)?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    sock.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let conn = rustls::ClientConnection::new(cfg, name)?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(req.as_bytes())?;
    tls.flush()?;
    // One-shot: server closes per our header; tolerate missing close_notify
    // (data already received is still a valid response).
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match tls.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        if buf.len() > 1_048_576 {
            break;
        }
    }
    let resp = String::from_utf8_lossy(&buf).to_string();
    Ok(resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0))
}

/// Build the standard payload. `shown` mirrors the display filter so the
/// receiver sees what the operator saw.
pub fn payload(source: &str, node: &str, at_iso: &str, reasons: &[String]) -> serde_json::Value {
    serde_json::json!({
        "source": source,
        "node": node,
        "time": at_iso,
        "reasons": reasons,
    })
}

/// Notify, logging failures to stderr without ever failing the caller.
pub fn fire(url_opt: &Option<String>, payload: serde_json::Value) {
    if let Some(url) = url_opt {
        if let Err(e) = notify(url, &payload) {
            eprintln!("webhook failed ({url}): {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub receiver: reads one POST, answers 200, records the body.
    fn stub_server() -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
            let mut reader = std::io::BufReader::new(&s);
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                use std::io::BufRead;
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let t = line.trim();
                if t.is_empty() {
                    break;
                }
                if let Some(v) = t.strip_prefix("Content-Length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len.min(1_048_576)];
            use std::io::Read;
            if len > 0 {
                reader.read_exact(&mut body).ok();
            }
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            use std::io::Write;
            s.write_all(resp.as_bytes()).ok();
            String::from_utf8_lossy(&body).to_string()
        });
        (format!("http://{addr}/hook"), h)
    }

    #[test]
    fn webhook_delivers_json_payload() {
        let (url, h) = stub_server();
        let p = payload("watch", "n1", "t", &["CPU 95.0% > 90%".to_string()]);
        notify(&url, &p).expect("delivery must succeed");
        let got = h.join().unwrap();
        let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON body");
        assert_eq!(v["node"], "n1");
        assert_eq!(v["reasons"][0], "CPU 95.0% > 90%");
    }

    #[test]
    fn bad_url_is_an_error_not_a_panic() {
        assert!(notify("http://", &payload("w", "n", "t", &[])).is_err());
        assert!(notify("https://127.0.0.1:1/x", &payload("w", "n", "t", &[])).is_err());
    }
}
