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
    assert!(body.contains("Requests served"), "body: {}", body);

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
