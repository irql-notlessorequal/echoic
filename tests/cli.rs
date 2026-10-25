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
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use hickory_server::proto::op::{Message, Query};
use hickory_server::proto::rr::{Name, RecordType};

fn echoic() -> Command {
    Command::new(env!("CARGO_BIN_EXE_echoic"))
}

fn example_config() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/echoic.toml.example")
}

#[test]
fn check_config_accepts_example() {
    let output = echoic()
        .args(["--check-config", "--config"])
        .arg(example_config())
        .output()
        .expect("run echoic");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "configuration OK\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn check_config_rejects_invalid_configuration() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config_path = directory.path().join("echoic.toml");
    std::fs::write(
        &config_path,
        r#"
[[listeners]]
name = "lan"
protocol = "udp"
address = "127.0.0.1:5353"

[[listeners]]
name = "lan"
protocol = "tcp"
address = "127.0.0.1:5353"
"#,
    )
    .expect("write configuration");

    let output = echoic()
        .args(["--check-config", "--config"])
        .arg(config_path)
        .output()
        .expect("run echoic");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate listener name"));
}

#[test]
fn check_config_rejects_missing_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let output = echoic()
        .args(["--check-config", "--config"])
        .arg(directory.path().join("missing.toml"))
        .output()
        .expect("run echoic");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to read configuration"));
}

#[test]
fn normal_startup_initializes_logging_and_starts_listeners() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config_path = directory.path().join("echoic.toml");
    std::fs::write(
        &config_path,
        r#"
[logging]
level = "info"

[dnssec]
enabled = false

[[listeners]]
name = "plain"
protocol = "udp"
address = "127.0.0.1:0"
"#,
    )
    .expect("write configuration");

    let mut child = echoic()
        .args(["--config"])
        .arg(config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("run echoic");

    let lines = log_lines(&mut child);
    if wait_for_log_line(&lines, "echoic started", Duration::from_secs(10)).is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("echoic did not log startup");
    }

    #[cfg(unix)]
    {
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("send SIGTERM");
        assert!(status.success());
        assert!(child.wait().expect("wait for echoic").success());
    }

    #[cfg(not(unix))]
    {
        child.kill().expect("stop echoic");
        child.wait().expect("wait for echoic");
    }
}

#[test]
fn startup_rejects_unimplemented_encrypted_listeners() {
    let output = echoic()
        .args(["--config"])
        .arg(example_config())
        .output()
        .expect("run echoic");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not implemented yet"));
}

fn log_lines(child: &mut Child) -> mpsc::Receiver<String> {
    let stdout = child.stdout.take().expect("captured stdout");
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    receiver
}

fn wait_for_log_line(
    receiver: &mpsc::Receiver<String>,
    needle: &str,
    timeout: Duration,
) -> Option<String> {
    wait_for_log_line_collect(receiver, needle, timeout, &mut Vec::new())
}

fn wait_for_log_line_collect(
    receiver: &mpsc::Receiver<String>,
    needle: &str,
    timeout: Duration,
    lines: &mut Vec<String>,
) -> Option<String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match receiver.recv_timeout(remaining) {
            Ok(line) => {
                lines.push(line.clone());
                if line.contains(needle) {
                    return Some(line);
                }
            }
            Err(_) => return None,
        }
    }
}

#[test]
fn query_names_are_omitted_by_default() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config_path = directory.path().join("echoic.toml");
    std::fs::write(
        &config_path,
        r#"
[logging]
level = "info"

[dnssec]
enabled = false

[[listeners]]
name = "plain"
protocol = "udp"
address = "127.0.0.1:0"
"#,
    )
    .expect("write configuration");

    let mut child = echoic()
        .args(["--config"])
        .arg(config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("run echoic");

    let lines = log_lines(&mut child);
    let mut captured = Vec::new();
    let Some(listener_line) = wait_for_log_line_collect(
        &lines,
        "listener started",
        Duration::from_secs(10),
        &mut captured,
    ) else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("echoic did not log listener startup");
    };

    let address = listener_address(&listener_line).expect("listener address in log");
    let query_name = "secret.example.";
    let mut message = Message::query();
    message.metadata.recursion_desired = false;
    message.add_query(Query::query(
        Name::from_ascii(query_name).expect("query name"),
        RecordType::A,
    ));

    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    socket
        .send_to(&message.to_vec().expect("encode query"), address)
        .expect("send query");

    let mut response = [0_u8; 512];
    socket.recv_from(&mut response).expect("receive response");

    if wait_for_log_line_collect(
        &lines,
        "query completed",
        Duration::from_secs(10),
        &mut captured,
    )
    .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("echoic did not log query completion");
    }

    #[cfg(unix)]
    {
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("send SIGTERM");
        assert!(status.success());
        assert!(child.wait().expect("wait for echoic").success());
    }

    #[cfg(not(unix))]
    {
        child.kill().expect("stop echoic");
        child.wait().expect("wait for echoic");
    }

    while let Ok(line) = lines.recv_timeout(Duration::from_millis(500)) {
        captured.push(line);
    }

    assert!(
        !captured.iter().any(|line| line.contains(query_name)),
        "query name appeared in logs"
    );
}

fn listener_address(line: &str) -> Option<SocketAddr> {
    line.split("\"address\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .and_then(|address| address.parse().ok())
}

#[test]
fn help_succeeds() {
    let output = echoic().arg("--help").output().expect("run echoic");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: echoic"));
}

#[test]
fn unknown_argument_exits_with_usage_error() {
    let output = echoic().arg("--not-a-flag").output().expect("run echoic");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
}
