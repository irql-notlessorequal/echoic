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
use std::collections::HashMap;
use std::io::BufRead;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rcgen::generate_simple_self_signed;

fn echoic() -> Command {
    Command::new(env!("CARGO_BIN_EXE_echoic"))
}

fn start_server(config: &str) -> (Child, HashMap<String, SocketAddr>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");

    let config_path = dir.path().join("echoic.toml");
    let config = config
        .replace("$CERT", &cert_path.display().to_string())
        .replace("$KEY", &key_path.display().to_string());
    let expected = config.matches("[[listeners]]").count();
    std::fs::write(&config_path, config).expect("write config");

    let mut child = echoic()
        .args(["--config"])
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("run echoic");

    let stdout = child.stdout.take().expect("stdout");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = sender.send(line);
        }
    });

    let mut addresses = HashMap::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline && addresses.len() < expected {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(line) if line.contains("listener started") => {
                if let (Some(name), Some(address)) = (
                    line.split("\"listener\":\"")
                        .nth(1)
                        .and_then(|rest| rest.split('"').next()),
                    line.split("\"address\":\"")
                        .nth(1)
                        .and_then(|rest| rest.split('"').next()),
                ) && let Ok(address) = address.parse::<SocketAddr>()
                {
                    addresses.insert(name.to_string(), address);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    std::mem::forget(dir);
    (child, addresses)
}

fn reload(child: &Child) {
    let status = Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .expect("send SIGHUP");
    assert!(status.success());
    thread::sleep(Duration::from_millis(750));
}

fn stop(mut child: Child) {
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
}

fn alpn_connects(address: SocketAddr, protocol: &str) -> bool {
    let output = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &address.to_string(),
            "-servername",
            "localhost",
            "-alpn",
            protocol,
            "-brief",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("openssl");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text.contains("CONNECTION ESTABLISHED") && !text.contains("no application protocol")
}

#[test]
fn shared_certificate_keeps_transport_alpn_after_reload() {
    let config = r#"
[logging]
level = "info"

[dnssec]
enabled = false

[[tls]]
name = "public"
cert = "$CERT"
key = "$KEY"

[[listeners]]
name = "dot"
protocol = "dot"
address = "127.0.0.1:0"
tls = "public"
limits = { max_connections = 8 }

[[listeners]]
name = "doh"
protocol = "doh"
address = "127.0.0.1:0"
tls = "public"
hostname = "localhost"
limits = { max_connections = 8, max_concurrent_requests = 8 }
"#;
    let (child, addresses) = start_server(config);
    let dot = addresses["dot"];
    let doh = addresses["doh"];

    reload(&child);

    assert!(alpn_connects(dot, "dot"));
    assert!(!alpn_connects(dot, "h2"));
    assert!(alpn_connects(doh, "h2"));
    assert!(!alpn_connects(doh, "dot"));

    stop(child);
}
