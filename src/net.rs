//! Minimal HTTP transport over std only (no web framework).
//! Collector side: tiny threaded server speaking just enough HTTP/1.0-1.1 to
//! accept `POST /ingest` from agents and answer `GET /nodes|/health` (curl-able).
//! Agent side: persistent keep-alive connection (one TLS handshake per run).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Read one HTTP request from a stream (headers + Content-Length body).
/// Generic over the transport so plaintext TCP and rustls TLS share the code.
/// Body capped at 1MB (matches the collector's ingest limit).
pub fn read_request(stream: &mut impl Read) -> anyhow::Result<Request> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    // Unbounded header blocks are a memory-exhaustion vector (a cert-holding
    // attacker included): cap request line at 4KB, headers at 16KB / 128 lines.
    if request_line.len() > 4096 {
        anyhow::bail!("request line too long");
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    if method.is_empty() {
        anyhow::bail!("empty request line");
    }
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        header_bytes += line.len();
        if header_bytes > 16_384 {
            anyhow::bail!("header block too big");
        }
        if headers.len() > 128 {
            anyhow::bail!("too many headers");
        }
        let t = line.trim();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len.min(1_048_576)];
    if len > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(Request { method, path, headers, body })
}

/// keep_alive=false answers `Connection: close` (one-shot clients like curl).
pub fn respond_json_conn(
    stream: &mut impl Write,
    status: u16,
    body: &str,
    keep_alive: bool,
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Error",
        _ => "OK",
    };
    let conn_hdr = if keep_alive { "keep-alive" } else { "close" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {conn_hdr}\r\nKeep-Alive: timeout=30, max=200\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Persistent connection (one TLS handshake for the whole agent run).
/// Boxed TLS variant: StreamOwned is ~1KB, keep it off the hot stack.
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Conn {
    pub fn connect(addr: &str, tls: &Option<std::sync::Arc<rustls::ClientConfig>>) -> anyhow::Result<Self> {
        match tls {
            Some(cfg) => Self::connect_tls_owned(addr, cfg),
            None => {
                let sock = TcpStream::connect(addr)?;
                sock.set_read_timeout(Some(Duration::from_secs(10)))?;
                sock.set_write_timeout(Some(Duration::from_secs(10)))?;
                Ok(Conn::Plain(sock))
            }
        }
    }

    fn connect_tls_owned(
        addr: &str,
        cfg: &std::sync::Arc<rustls::ClientConfig>,
    ) -> anyhow::Result<Self> {
        let sock = TcpStream::connect(addr)?;
        sock.set_read_timeout(Some(Duration::from_secs(10)))?;
        sock.set_write_timeout(Some(Duration::from_secs(10)))?;
        let conn = rustls::ClientConnection::new(std::sync::Arc::clone(cfg), crate::tls::server_name()?)?;
        Ok(Conn::Tls(Box::new(rustls::StreamOwned::new(conn, sock))))
    }

    /// POST one JSON body over the open connection; returns (status, body).
    pub fn post(&mut self, host: &str, path: &str, body: &str) -> anyhow::Result<(u16, String)> {
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
            body.len()
        );
        match self {
            Conn::Plain(s) => {
                s.write_all(req.as_bytes())?;
                s.flush()?;
                read_response(s)
            }
            Conn::Tls(t) => {
                t.write_all(req.as_bytes())?;
                t.flush()?;
                read_response(t)
            }
        }
    }
}

/// Read exactly one HTTP response (status + Content-Length body).
/// Works on keep-alive connections — never reads past the frame.
fn read_response(stream: &mut impl Read) -> anyhow::Result<(u16, String)> {
    let mut reader = BufReader::new(stream);
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        head.push(byte[0]);
        if head.len() > 8192 {
            anyhow::bail!("response head too big");
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let mut len = 0usize;
    for line in lines {
        if let Some(v) = line.strip_prefix("Content-Length:") {
            len = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let len = len.min(8 * 1024 * 1024);
    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok((status, String::from_utf8_lossy(&body).to_string()))
}

pub fn listen(addr: &str) -> anyhow::Result<TcpListener> {
    Ok(TcpListener::bind(addr)?)
}

/// Normalize `--collector 127.0.0.1:8080` or `http://host:port[/]` → `host:port`.
pub fn normalize_addr(input: &str) -> String {
    let mut s = input.trim().to_string();
    for prefix in ["http://", "https://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
            break;
        }
    }
    s = s.trim_end_matches('/').to_string();
    if let Some(host) = s.split('/').next() {
        s = host.to_string();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_post_ingest_exact_bytes() {
        let raw = b"POST /ingest HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        let mut c = std::io::Cursor::new(raw);
        let r = read_request(&mut c).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/ingest");
        assert_eq!(r.body, b"{}");
    }
}
