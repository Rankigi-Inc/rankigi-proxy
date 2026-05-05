//! HTTP/HTTPS interception. The proxy listens on a TCP port and accepts
//! connections from agents that have configured `HTTPS_PROXY`. For plain
//! HTTP requests we forward to the absolute URL in the request line. For
//! `CONNECT` requests we MITM: present a dynamically issued leaf cert,
//! re-establish TLS to the upstream, and forward inner requests with full
//! capture.
//!
//! Capture is non-blocking. Once the upstream response is fully read into
//! memory, we write it to the agent and *then* enqueue the captured pair on
//! the ingest channel. The chain write happens entirely off the agent's hot
//! path.

use crate::config::Config;
use crate::event::CapturedPair;
use crate::queue::{IngestQueue, QueueItem};
use crate::tls::LeafCache;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

const MAX_BODY_BYTES: usize = 4 * 1024 * 1024; // 4 MB
const MAX_HEADER_BYTES: usize = 64 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(60);

pub struct ProxyServer {
    cfg: Arc<Config>,
    queue: IngestQueue,
    leaf_cache: Arc<LeafCache>,
    upstream: reqwest::Client,
}

impl ProxyServer {
    pub fn new(cfg: Arc<Config>, queue: IngestQueue, leaf_cache: Arc<LeafCache>) -> Self {
        let upstream = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .danger_accept_invalid_certs(false)
            .build()
            .expect("upstream reqwest client");
        Self {
            cfg,
            queue,
            leaf_cache,
            upstream,
        }
    }

    pub async fn serve(self: Arc<Self>) -> std::io::Result<()> {
        let addr = format!("0.0.0.0:{}", self.cfg.proxy_port);
        let listener = TcpListener::bind(&addr).await?;
        info!(addr = %addr, "proxy listening");
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(err = %e, "accept failed");
                    continue;
                }
            };
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle_conn(stream).await {
                    debug!(peer = %peer, err = %e, "connection ended");
                }
            });
        }
    }

    async fn handle_conn(&self, mut stream: TcpStream) -> Result<(), String> {
        // Peek the first request to decide between CONNECT-MITM and plain HTTP.
        let mut buf = Vec::with_capacity(8192);
        if !read_until_headers_end(&mut stream, &mut buf).await? {
            return Err("no request received".into());
        }
        let head = parse_request_head(&buf)?;
        if head.method.eq_ignore_ascii_case("CONNECT") {
            self.handle_connect(stream, head).await
        } else {
            self.handle_plain(stream, head, buf).await
        }
    }

    async fn handle_connect(&self, mut stream: TcpStream, head: RequestHead) -> Result<(), String> {
        // CONNECT host:port HTTP/1.1
        let target = head.target.clone();
        let (host, port) = parse_authority(&target).ok_or("bad CONNECT target")?;

        // Bypass: tunnel transparently to upstream without MITM or capture.
        // Used for the ingest endpoint itself so the proxy cannot record its
        // own submissions (capture → ingest → capture loop), plus any hosts
        // the operator opts into via RANKIGI_BYPASS_HOSTS.
        if self.cfg.is_bypassed(&host) {
            debug!(host = %host, port, "bypass: tunneling without capture");
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(|e| e.to_string())?;
            let mut upstream = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|e| e.to_string())?;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            return Ok(());
        }

        // 200 to signal tunnel established.
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;

        let server_cfg = self
            .leaf_cache
            .server_config_for(&host)
            .await
            .map_err(|e| e.to_string())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let inbound_tls = acceptor.accept(stream).await.map_err(|e| e.to_string())?;

        // After TLS accept, parse the inner HTTP request and forward.
        self.serve_inner_https(inbound_tls, host, port).await
    }

    async fn serve_inner_https(
        &self,
        mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
        host: String,
        port: u16,
    ) -> Result<(), String> {
        loop {
            let mut buf = Vec::with_capacity(8192);
            if !read_until_headers_end(&mut tls_stream, &mut buf).await? {
                return Ok(());
            }
            let head = parse_request_head(&buf)?;
            let received_at = Utc::now();
            let (req_body, _) = read_body(&mut tls_stream, &buf, &head).await?;

            let scheme = "https";
            let url = build_full_url(scheme, &host, port, &head.target);
            let path = path_from_target(&head.target);

            let (status, resp_headers, resp_body) =
                match self.forward(&head, &url, req_body.clone()).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(err = %e, "upstream forward failed");
                        let pair = CapturedPair {
                            method: head.method.clone(),
                            url: url.clone(),
                            host: host.clone(),
                            path,
                            request_body: req_body,
                            response_status: None,
                            response_body: Vec::new(),
                            proxy_received_at: received_at,
                            proxy_response_at: Some(Utc::now()),
                            body_truncated: false,
                        };
                        let _ = self.queue.try_enqueue(QueueItem::Captured(Box::new(pair)));
                        return Err(e);
                    }
                };

            let response_at = Utc::now();
            // Write back to agent BEFORE enqueueing.
            write_http_response(&mut tls_stream, status, &resp_headers, &resp_body).await?;

            let pair = CapturedPair {
                method: head.method.clone(),
                url,
                host: host.clone(),
                path: path_from_target(&head.target),
                request_body: req_body,
                response_status: Some(status),
                response_body: resp_body,
                proxy_received_at: received_at,
                proxy_response_at: Some(response_at),
                body_truncated: false,
            };
            let _ = self.queue.try_enqueue(QueueItem::Captured(Box::new(pair)));

            // Loop to handle keepalive. Stop on connection close request.
            if !is_keepalive(&head) {
                return Ok(());
            }
        }
    }

    async fn handle_plain(
        &self,
        mut stream: TcpStream,
        head: RequestHead,
        head_buf: Vec<u8>,
    ) -> Result<(), String> {
        // For plain HTTP via proxy the request line carries an absolute URL.
        let received_at = Utc::now();
        let (req_body, _) = read_body(&mut stream, &head_buf, &head).await?;

        let absolute = head.target.clone();
        let parsed =
            url::Url::parse(&absolute).map_err(|e| format!("invalid request URL: {}", e))?;
        let scheme = parsed.scheme().to_string();
        let host = parsed.host_str().ok_or("URL has no host")?.to_string();
        let port = parsed.port_or_known_default().ok_or("URL has no port")?;
        let path = format!(
            "{}{}",
            parsed.path(),
            parsed
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default()
        );

        let url = format!(
            "{}://{}{}",
            scheme,
            host_with_port(&host, port, &scheme),
            path
        );

        // Bypass: forward to upstream and relay the response without
        // enqueueing a CapturedPair. Same loop-prevention rationale as
        // handle_connect.
        if self.cfg.is_bypassed(&host) {
            debug!(host = %host, "bypass: forwarding plain HTTP without capture");
            let (status, resp_headers, resp_body) = self
                .forward(&head, &url, req_body)
                .await
                .map_err(|e| format!("bypass forward failed: {}", e))?;
            write_http_response(&mut stream, status, &resp_headers, &resp_body).await?;
            return Ok(());
        }

        let (status, resp_headers, resp_body) =
            match self.forward(&head, &url, req_body.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    let pair = CapturedPair {
                        method: head.method.clone(),
                        url: url.clone(),
                        host: host.clone(),
                        path: path.clone(),
                        request_body: req_body,
                        response_status: None,
                        response_body: Vec::new(),
                        proxy_received_at: received_at,
                        proxy_response_at: Some(Utc::now()),
                        body_truncated: false,
                    };
                    let _ = self.queue.try_enqueue(QueueItem::Captured(Box::new(pair)));
                    return Err(e);
                }
            };

        let response_at = Utc::now();
        write_http_response(&mut stream, status, &resp_headers, &resp_body).await?;

        let pair = CapturedPair {
            method: head.method.clone(),
            url,
            host,
            path,
            request_body: req_body,
            response_status: Some(status),
            response_body: resp_body,
            proxy_received_at: received_at,
            proxy_response_at: Some(response_at),
            body_truncated: false,
        };
        let _ = self.queue.try_enqueue(QueueItem::Captured(Box::new(pair)));
        Ok(())
    }

    async fn forward(
        &self,
        head: &RequestHead,
        url: &str,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        let method = reqwest::Method::from_bytes(head.method.as_bytes())
            .map_err(|e| format!("bad method: {}", e))?;
        let mut req = self.upstream.request(method, url);
        for (name, value) in &head.headers {
            // Strip hop-by-hop headers; reqwest adds its own connection headers.
            if is_hop_by_hop(name) {
                continue;
            }
            req = req.header(name, value);
        }
        if !body.is_empty() {
            req = req.body(body);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let mut headers: Vec<(String, String)> = Vec::with_capacity(resp.headers().len());
        for (name, value) in resp.headers().iter() {
            if is_hop_by_hop(name.as_str()) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                headers.push((name.as_str().to_string(), v.to_string()));
            }
        }
        // Read body with a cap so we never OOM on a streaming response.
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        let body = if bytes.len() > MAX_BODY_BYTES {
            bytes[..MAX_BODY_BYTES].to_vec()
        } else {
            bytes.to_vec()
        };
        Ok((status, headers, body))
    }
}

// ── HTTP wire helpers ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

fn parse_request_head(buf: &[u8]) -> Result<RequestHead, String> {
    let s = std::str::from_utf8(buf).map_err(|_| "non-utf8 request head".to_string())?;
    let end = s.find("\r\n\r\n").ok_or("incomplete head")?;
    let head = &s[..end];
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or("missing request line")?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().ok_or("missing method")?.to_string();
    let target = parts.next().ok_or("missing target")?.to_string();
    let version = parts.next().ok_or("missing version")?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(RequestHead {
        method,
        target,
        version,
        headers,
    })
}

async fn read_until_headers_end<R: AsyncReadExt + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> Result<bool, String> {
    let mut tmp = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(true);
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("headers too large".into());
        }
        let read_fut = r.read(&mut tmp);
        let n = match tokio::time::timeout(READ_TIMEOUT, read_fut).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("read timeout".into()),
        };
        if n == 0 {
            return Ok(!buf.is_empty());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn read_body<R: AsyncReadExt + Unpin>(
    r: &mut R,
    head_buf: &[u8],
    head: &RequestHead,
) -> Result<(Vec<u8>, bool), String> {
    let header_end = head_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("incomplete head")?;
    let already = head_buf[header_end + 4..].to_vec();
    let content_length = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());
    let transfer_encoding = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.to_ascii_lowercase());

    let mut body = already;
    if let Some(len) = content_length {
        let target_len = len.min(MAX_BODY_BYTES);
        let mut tmp = [0u8; 4096];
        while body.len() < target_len {
            let n = match tokio::time::timeout(READ_TIMEOUT, r.read(&mut tmp)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.to_string()),
                Err(_) => return Err("body read timeout".into()),
            };
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        let truncated = body.len() < len;
        body.truncate(target_len);
        Ok((body, truncated))
    } else if transfer_encoding.as_deref() == Some("chunked") {
        // Best-effort chunked reader; tolerate truncation.
        let mut tmp = [0u8; 4096];
        loop {
            if body.len() > MAX_BODY_BYTES {
                body.truncate(MAX_BODY_BYTES);
                return Ok((body, true));
            }
            // Heuristic terminator: empty chunk "0\r\n\r\n".
            if body.windows(5).any(|w| w == b"0\r\n\r\n") {
                break;
            }
            let n = match tokio::time::timeout(READ_TIMEOUT, r.read(&mut tmp)).await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) | Err(_) => break,
            };
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        Ok((body, false))
    } else {
        // No body indicator — return what was already buffered.
        Ok((body, false))
    }
}

async fn write_http_response<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), String> {
    let mut out = Vec::with_capacity(256 + body.len());
    let reason = http_reason(status);
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status, reason).as_bytes());
    let mut had_content_length = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-length") {
            had_content_length = true;
        }
        if k.eq_ignore_ascii_case("transfer-encoding") {
            // We've already buffered the full body; serve as fixed-length.
            continue;
        }
        out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    if !had_content_length {
        out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"connection: close\r\n");
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    w.write_all(&out).await.map_err(|e| e.to_string())?;
    w.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

pub fn http_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

fn parse_authority(s: &str) -> Option<(String, u16)> {
    let (h, p) = s.rsplit_once(':')?;
    let port = p.parse::<u16>().ok()?;
    Some((h.to_string(), port))
}

fn build_full_url(scheme: &str, host: &str, port: u16, target: &str) -> String {
    let path = if target.starts_with('/') {
        target.to_string()
    } else {
        format!("/{}", target)
    };
    let host_part = host_with_port(host, port, scheme);
    format!("{}://{}{}", scheme, host_part, path)
}

fn host_with_port(host: &str, port: u16, scheme: &str) -> String {
    let default = match scheme {
        "https" => 443,
        "http" => 80,
        _ => 0,
    };
    if port == default {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    }
}

fn path_from_target(target: &str) -> String {
    if let Ok(parsed) = url::Url::parse(target) {
        let mut p = parsed.path().to_string();
        if let Some(q) = parsed.query() {
            p.push('?');
            p.push_str(q);
        }
        p
    } else {
        target.to_string()
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

fn is_keepalive(head: &RequestHead) -> bool {
    let conn = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .map(|(_, v)| v.to_ascii_lowercase());
    match (head.version.as_str(), conn.as_deref()) {
        (_, Some("close")) => false,
        (_, Some("keep-alive")) => true,
        ("HTTP/1.1", _) => true,
        _ => false,
    }
}
