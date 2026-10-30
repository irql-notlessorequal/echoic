// echoic, a recursive DNS resolver.
// Copyright (C) IRQL_NOT_LESS_OR_EQUAL
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use rcgen::generate_simple_self_signed;

fn echoic() -> Command {
    Command::new(env!("CARGO_BIN_EXE_echoic"))
}

fn start_server() -> (Child, u16) {
    start_server_with_listener("")
}

fn start_server_with_listener(listener_extra: &str) -> (Child, u16) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");

    let config_path = dir.path().join("echoic.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[logging]
level = "info"

[dnssec]
enabled = false

[[tls]]
name = "public"
cert = "{}"
key = "{}"

[[listeners]]
name = "doh"
protocol = "doh"
address = "127.0.0.1:0"
tls = "public"
hostname = "localhost"
limits = {{ max_connections = 8, max_concurrent_requests = 8 }}
{listener_extra}

[server_limits]
max_doh_body = 1024
max_doh_uri = 1024
query_timeout = "5s"
idle_timeout = "5s"
"#,
            cert_path.display(),
            key_path.display()
        ),
    )
    .expect("write config");

    let mut child = echoic()
        .args(["--config"])
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("run echoic");

    let stdout = child.stdout.take().expect("stdout");
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = sender.send(line);
        }
    });

    let mut port = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(line) if line.contains("listener started") => {
                if let Some(addr) = line
                    .split("\"address\":\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    && let Ok(parsed) = addr.parse::<std::net::SocketAddr>()
                {
                    port = Some(parsed.port());
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let port = port.expect("listener address");

    std::mem::forget(dir);
    (child, port)
}

fn stop(mut child: Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[tokio::test]
async fn static_routes_require_acl() {
    let (child, port) = start_server_with_listener(r#"acl = { allow = ["192.0.2.0/24"] }"#);
    let base = format!("https://localhost:{}", port);

    let mut cmd = Command::new("curl");
    cmd.arg("-sk")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}");
    cmd.arg("--resolve")
        .arg(format!("localhost:{}:127.0.0.1", port));
    cmd.arg("-H").arg("Host: localhost");
    cmd.arg(format!("{}/healthz", base));
    let output = cmd.output().expect("curl");
    let code: i32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap();
    assert_eq!(code, 403);

    stop(child);
}

#[tokio::test]
async fn doh_http_endpoints() {
    let (child, port) = start_server();
    let base = format!("https://localhost:{}", port);

    let run = |path_and_args: &[&str]| -> (i32, String) {
        let mut cmd = Command::new("curl");
        cmd.arg("-sk")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}");
        cmd.arg("--resolve")
            .arg(format!("localhost:{}:127.0.0.1", port));
        for arg in path_and_args {
            cmd.arg(arg);
        }
        let output = cmd.output().expect("curl");
        let code = String::from_utf8_lossy(&output.stdout).to_string();
        let body = String::from_utf8_lossy(&output.stderr).to_string();
        (code.parse().unwrap_or(0), body)
    };

    // healthz
    let (code, _) = run(&[&format!("{}/healthz", base), "-H", "Host: localhost"]);
    assert_eq!(code, 200);

    // explicit non-default port in Host is accepted
    let (code, _) = run(&[
        &format!("{}/healthz", base),
        "-H",
        &format!("Host: localhost:{}", port),
    ]);
    assert_eq!(code, 200);

    // readyz
    let (code, _) = run(&[&format!("{}/readyz", base), "-H", "Host: localhost"]);
    assert_eq!(code, 200);

    // landing
    let mut cmd = Command::new("curl");
    cmd.arg("-sk")
        .arg("--resolve")
        .arg(format!("localhost:{}:127.0.0.1", port));
    cmd.arg("-H").arg("Host: localhost");
    cmd.arg(format!("{}/", base));
    let output = cmd.output().expect("curl");
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(body.contains("Statistics"), "body: {}", body);

    // missing dns
    let (code, _) = run(&[&format!("{}/dns-query", base), "-H", "Host: localhost"]);
    assert_eq!(code, 400);

    // bad base64
    let (code, _) = run(&[
        &format!("{}/dns-query?dns=!!!", base),
        "-H",
        "Host: localhost",
    ]);
    assert_eq!(code, 400);

    // bad content type
    let mut cmd = Command::new("curl");
    cmd.arg("-sk")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}");
    cmd.arg("--resolve")
        .arg(format!("localhost:{}:127.0.0.1", port));
    cmd.arg("-H").arg("Host: localhost");
    cmd.arg("-H").arg("content-type: text/plain");
    cmd.arg("--data-binary").arg("x");
    cmd.arg(format!("{}/dns-query", base));
    let output = cmd.output().expect("curl");
    let code: i32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap();
    assert_eq!(code, 415);

    // not found
    let (code, _) = run(&[&format!("{}/does-not-exist", base), "-H", "Host: localhost"]);
    assert_eq!(code, 404);

    // host mismatch
    let (code, _) = run(&[&format!("{}/healthz", base), "-H", "Host: example.com"]);
    assert_eq!(code, 400);

    stop(child);
}

fn start_server_with_landing(html: &str, css: &str) -> (Child, u16) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");

    let html_path = dir.path().join("landing.html");
    let css_path = dir.path().join("landing.css");
    std::fs::write(&html_path, html).expect("write html");
    std::fs::write(&css_path, css).expect("write css");

    let config_path = dir.path().join("echoic.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[logging]
level = "info"

[dnssec]
enabled = false

[[tls]]
name = "public"
cert = "{}"
key = "{}"

[[listeners]]
name = "doh"
protocol = "doh"
address = "127.0.0.1:0"
tls = "public"
hostname = "localhost"
limits = {{ max_connections = 8, max_concurrent_requests = 8 }}

[server_limits]
max_doh_body = 1024
max_doh_uri = 1024
query_timeout = "5s"
idle_timeout = "5s"

[landing_page]
html = "{}"
css = "{}"
"#,
            cert_path.display(),
            key_path.display(),
            html_path.display(),
            css_path.display()
        ),
    )
    .expect("write config");

    let mut child = echoic()
        .args(["--config"])
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("run echoic");

    let stdout = child.stdout.take().expect("stdout");
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = sender.send(line);
        }
    });

    let mut port = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(line) if line.contains("listener started") => {
                if let Some(addr) = line
                    .split("\"address\":\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    && let Ok(parsed) = addr.parse::<std::net::SocketAddr>()
                {
                    port = Some(parsed.port());
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let port = port.expect("listener address");

    std::mem::forget(dir);
    (child, port)
}

#[tokio::test]
async fn custom_landing_page() {
    let (child, port) = start_server_with_landing(
        "<!DOCTYPE html><html><body><h1>{{ hostname }}</h1><p>{{cache_hit_rate}}</p></body></html>",
        "body { color: rgb(1,2,3); }",
    );
    let base = format!("https://localhost:{}", port);

    let mut cmd = Command::new("curl");
    cmd.arg("-sk")
        .arg("--resolve")
        .arg(format!("localhost:{}:127.0.0.1", port));
    cmd.arg("-H").arg("Host: localhost");
    cmd.arg(format!("{}/", base));
    let output = cmd.output().expect("curl");
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(body.contains("localhost"), "body: {}", body);
    assert!(body.contains("0.0%"), "body: {}", body);

    let mut cmd = Command::new("curl");
    cmd.arg("-sk")
        .arg("--resolve")
        .arg(format!("localhost:{}:127.0.0.1", port));
    cmd.arg("-H").arg("Host: localhost");
    cmd.arg(format!("{}/assets/landing.css", base));
    let output = cmd.output().expect("curl");
    let css = String::from_utf8_lossy(&output.stdout);
    assert!(css.contains("rgb(1,2,3)"), "css: {}", css);

    stop(child);
}

#[tokio::test]
async fn landing_page_rejects_bad_host() {
    let (child, port) = start_server();
    let base = format!("https://localhost:{}", port);

    for path in ["/", "/assets/landing.css"] {
        let mut cmd = Command::new("curl");
        cmd.arg("-sk")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}");
        cmd.arg("--resolve")
            .arg(format!("localhost:{}:127.0.0.1", port));
        cmd.arg("-H").arg("Host: example.com");
        cmd.arg(format!("{}{}", base, path));
        let output = cmd.output().expect("curl");
        let code: i32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .unwrap();
        assert_eq!(code, 400, "path {}", path);
    }

    stop(child);
}

#[tokio::test]
async fn host_is_compared_case_insensitively_and_ignores_ports() {
    let (child, port) = start_server();
    let base = format!("https://localhost:{}", port);

    for host in ["LOCALHOST", "localhost.", "localhost:443"] {
        let mut cmd = Command::new("curl");
        cmd.arg("-sk")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}");
        cmd.arg("--resolve")
            .arg(format!("localhost:{}:127.0.0.1", port));
        cmd.arg("-H").arg(format!("Host: {host}"));
        cmd.arg(format!("{}/healthz", base));
        let output = cmd.output().expect("curl");
        let code: i32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .unwrap();
        assert_eq!(code, 200, "host {}", host);
    }

    stop(child);
}

#[tokio::test]
async fn unsupported_method_returns_405_with_allow() {
    let (child, port) = start_server();
    let base = format!("https://localhost:{}", port);

    let output = Command::new("curl")
        .arg("-sk")
        .arg("-D")
        .arg("-")
        .arg("-o")
        .arg("/dev/null")
        .arg("--resolve")
        .arg(format!("localhost:{}:127.0.0.1", port))
        .arg("-H")
        .arg("Host: localhost")
        .arg("-X")
        .arg("PATCH")
        .arg(format!("{}/dns-query", base))
        .output()
        .expect("curl");
    let headers = String::from_utf8_lossy(&output.stdout);
    assert!(headers.contains(" 405"), "headers: {headers}");
    let headers = headers.to_ascii_lowercase();
    assert!(headers.contains("allow: get"), "headers: {headers}");
    assert!(headers.contains("post"), "headers: {headers}");

    stop(child);
}

#[tokio::test]
async fn oversized_body_is_rejected_after_reading() {
    let (child, port) = start_server();
    let base = format!("https://localhost:{}", port);

    let output = Command::new("curl")
        .arg("-sk")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg("--resolve")
        .arg(format!("localhost:{}:127.0.0.1", port))
        .arg("-H")
        .arg("Host: localhost")
        .arg("-H")
        .arg("Content-Type: application/dns-message")
        .arg("--data-binary")
        .arg("x".repeat(2048))
        .arg(format!("{}/dns-query", base))
        .output()
        .expect("curl");
    let code: i32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap();
    assert_eq!(code, 413);

    stop(child);
}

#[tokio::test]
async fn rejected_request_does_not_wait_for_body() {
    let (child, port) = start_server();

    let request = "POST /dns-query HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/dns-message\r\nContent-Length: 100000\r\n\r\n".to_string();
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        raw_tls_exchange(port, request.as_bytes()),
    )
    .await
    .expect("server responded before reading the body");
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 400"), "response: {response}");

    stop(child);
}

async fn raw_tls_exchange(port: u16, request: &[u8]) -> Vec<u8> {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let mut tls = connector.connect(name, tcp).await.expect("tls");
    tls.write_all(request).await.expect("write request");
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = tls.read(&mut chunk).await.expect("read response");
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    response
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
