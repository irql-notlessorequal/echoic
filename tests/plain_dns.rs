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
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use echoic::config::{Config, Protocol};
use echoic::listeners::{ListenerRuntime, start_listener};
use echoic::query::QueryService;
use echoic::recursor::RecursiveResolver;
use echoic::stats::Stats;
use hickory_server::proto::dnssec::Proof;
use hickory_server::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_server::proto::rr::rdata::{A, SOA};
use hickory_server::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_server::resolver::recursor::{AuthorityData, RecursorError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;

struct MockResolver {
    validating: bool,
    saw_dnssec_ok: AtomicBool,
}

impl MockResolver {
    fn new(validating: bool) -> Self {
        Self {
            validating,
            saw_dnssec_ok: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl RecursiveResolver for MockResolver {
    async fn resolve(&self, query: Query, dnssec_ok: bool) -> Result<Message, RecursorError> {
        self.saw_dnssec_ok.store(dnssec_ok, Ordering::SeqCst);

        let name = query.name().to_string();
        let mut response = Message::response(0, OpCode::Query);
        response.add_query(query.clone());

        match name.as_str() {
            "secure.example." => {
                response.add_answer(a_record(&name, [192, 0, 2, 1], Proof::Secure));
                Ok(response)
            }
            "large.example." => {
                for index in 0..200 {
                    let octet = u8::try_from(index % 250).expect("octet");
                    response.add_answer(a_record(
                        &name,
                        [198, 51, 100, octet],
                        Proof::Indeterminate,
                    ));
                }
                Ok(response)
            }
            "missing.example." => Err(RecursorError::Negative(AuthorityData::new(
                Box::new(query),
                Some(Box::new(soa_record(&name, Proof::Secure))),
                true,
                true,
                None,
            ))),
            "nodata.example." => Err(RecursorError::Negative(AuthorityData::new(
                Box::new(query),
                Some(Box::new(soa_record(&name, Proof::Secure))),
                true,
                false,
                None,
            ))),
            "fail.example." => Err(RecursorError::Message("mock failure")),
            _ => {
                response.add_answer(a_record(&name, [192, 0, 2, 10], Proof::Indeterminate));
                Ok(response)
            }
        }
    }

    fn is_validating(&self) -> bool {
        self.validating
    }
}

struct TestServer {
    runtime: ListenerRuntime,
    stats: Arc<Stats>,
    mock: Arc<MockResolver>,
}

impl TestServer {
    async fn stop(self) {
        self.runtime.token.cancel();
        let _ = self.runtime.task.await;
    }
}

fn config_for(protocol: Protocol, listener_extra: &str) -> Config {
    let source = format!(
        r#"
[logging]
level = "off"

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "{}"
address = "127.0.0.1:0"
{listener_extra}
"#,
        protocol.as_str()
    );
    Config::from_toml_str(&source).expect("test configuration")
}

async fn start(protocol: Protocol, validating: bool) -> TestServer {
    let config = config_for(protocol, "");
    start_config(&config, validating, 16).await
}

async fn start_config(config: &Config, validating: bool, inflight: usize) -> TestServer {
    let listener = &config.listeners[0];
    let mock = Arc::new(MockResolver::new(validating));
    let stats = Arc::new(Stats::default());
    let blocklist = echoic::rpz::RpzPolicy::load(
        &config.blocklist.rpz_paths,
        config.blocklist.rpz_origin.as_deref(),
    )
    .expect("rpz policy");
    let service = QueryService::new(
        mock.clone(),
        listener,
        stats.clone(),
        Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(inflight)))),
        &config.server_limits,
        config.policy.refuse_any,
        config.logging.query_names,
        config.policy.edns_client_subnet_v4_prefix,
        config.policy.edns_client_subnet_v6_prefix,
        blocklist,
    );
    let runtime = start_listener(listener, service, config.server_limits.query_timeout)
        .await
        .expect("start listener");

    TestServer {
        runtime,
        stats,
        mock,
    }
}

fn query(name: &str, query_type: RecordType) -> Message {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii(name).expect("query name"),
        query_type,
    ));
    message
}

fn a_record(name: &str, address: [u8; 4], proof: Proof) -> Record {
    let mut record = Record::from_rdata(
        Name::from_ascii(name).expect("record name"),
        60,
        RData::A(A::new(address[0], address[1], address[2], address[3])),
    );
    record.proof = proof;
    record
}

fn soa_record(name: &str, proof: Proof) -> Record<SOA> {
    let mut record = Record::<SOA>::from_rdata(
        Name::from_ascii(name).expect("record name"),
        300,
        SOA::new(Name::root(), Name::root(), 1, 3600, 600, 86_400, 300),
    );
    record.proof = proof;
    record
}

async fn udp_query(address: SocketAddr, message: Message) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    socket
        .send_to(&message.to_vec().expect("encode query"), address)
        .await
        .expect("send query");

    let mut buffer = [0; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .expect("query timed out")
        .expect("receive response");
    Message::from_vec(&buffer[..length]).expect("decode response")
}

async fn udp_query_times_out(address: SocketAddr, message: Message) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let result = tokio::time::timeout(Duration::from_millis(250), async {
        socket
            .send_to(&message.to_vec().expect("encode query"), address)
            .await
            .expect("send query");
        let mut buffer = [0; 4096];
        socket.recv_from(&mut buffer).await
    })
    .await;

    assert!(result.is_err(), "expected the query to be dropped");
}

async fn tcp_query(address: SocketAddr, message: Message) -> Message {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let bytes = message.to_vec().expect("encode query");
    let length = u16::try_from(bytes.len()).expect("query length");
    stream
        .write_all(&length.to_be_bytes())
        .await
        .expect("write length");
    stream.write_all(&bytes).await.expect("write query");

    let mut response_length = [0; 2];
    stream
        .read_exact(&mut response_length)
        .await
        .expect("read response length");
    let mut response = vec![0; usize::from(u16::from_be_bytes(response_length))];
    stream
        .read_exact(&mut response)
        .await
        .expect("read response");
    Message::from_vec(&response).expect("decode response")
}

#[tokio::test]
async fn udp_answers_and_counts_served_queries() {
    let server = start(Protocol::Udp, false).await;
    let response = udp_query(
        server.runtime.bound_address,
        query("www.example.", RecordType::A),
    )
    .await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert!(!response.metadata.authentic_data);
    assert_eq!(server.stats.snapshot().udp, 1);

    server.stop().await;
}

#[tokio::test]
async fn tcp_answers_and_counts_served_queries() {
    let server = start(Protocol::Tcp, false).await;
    let response = tcp_query(
        server.runtime.bound_address,
        query("www.example.", RecordType::A),
    )
    .await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(server.stats.snapshot().tcp, 1);

    server.stop().await;
}

#[tokio::test]
async fn forwards_dnssec_ok_and_sets_ad_for_secure_answers() {
    let server = start(Protocol::Udp, true).await;

    let mut secure_query = query("secure.example.", RecordType::A);
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(true);
    secure_query.set_edns(edns);

    let response = udp_query(server.runtime.bound_address, secure_query).await;
    assert!(response.metadata.authentic_data);
    assert!(server.mock.saw_dnssec_ok.load(Ordering::SeqCst));

    let response = udp_query(
        server.runtime.bound_address,
        query("secure.example.", RecordType::A),
    )
    .await;
    assert!(response.metadata.authentic_data);
    assert!(!server.mock.saw_dnssec_ok.load(Ordering::SeqCst));

    server.stop().await;
}

#[tokio::test]
async fn preserves_negative_soa_and_nxdomain() {
    let server = start(Protocol::Udp, true).await;

    let response = udp_query(
        server.runtime.bound_address,
        query("missing.example.", RecordType::A),
    )
    .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(response.metadata.authentic_data);
    assert_eq!(
        response
            .authorities
            .iter()
            .filter(|record| record.record_type() == RecordType::SOA)
            .count(),
        1
    );

    let response = udp_query(
        server.runtime.bound_address,
        query("nodata.example.", RecordType::AAAA),
    )
    .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());
    assert!(response.metadata.authentic_data);
    assert_eq!(
        response
            .authorities
            .iter()
            .filter(|record| record.record_type() == RecordType::SOA)
            .count(),
        1
    );

    server.stop().await;
}

#[tokio::test]
async fn maps_recursor_failures_to_servfail_and_counts_them() {
    let server = start(Protocol::Udp, false).await;
    let response = udp_query(
        server.runtime.bound_address,
        query("fail.example.", RecordType::A),
    )
    .await;

    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(server.stats.snapshot().servfail, 1);

    server.stop().await;
}

#[tokio::test]
async fn truncates_large_udp_responses() {
    let server = start(Protocol::Udp, false).await;
    let response = udp_query(
        server.runtime.bound_address,
        query("large.example.", RecordType::A),
    )
    .await;

    assert!(response.metadata.truncation);
    assert!(response.answers.len() < 200);

    server.stop().await;
}

#[tokio::test]
async fn rejects_invalid_and_unsupported_queries() {
    let server = start(Protocol::Udp, false).await;

    let mut multiple = query("www.example.", RecordType::A);
    multiple.add_query(Query::query(
        Name::from_ascii("other.example.").expect("query name"),
        RecordType::A,
    ));
    assert_eq!(
        udp_query(server.runtime.bound_address, multiple)
            .await
            .metadata
            .response_code,
        ResponseCode::FormErr
    );

    let mut no_recursion = query("www.example.", RecordType::A);
    no_recursion.metadata.recursion_desired = false;
    assert_eq!(
        udp_query(server.runtime.bound_address, no_recursion)
            .await
            .metadata
            .response_code,
        ResponseCode::Refused
    );

    let mut any = query("www.example.", RecordType::ANY);
    any.metadata.recursion_desired = true;
    assert_eq!(
        udp_query(server.runtime.bound_address, any)
            .await
            .metadata
            .response_code,
        ResponseCode::Refused
    );

    let transfer = query("example.", RecordType::AXFR);
    assert_eq!(
        udp_query(server.runtime.bound_address, transfer)
            .await
            .metadata
            .response_code,
        ResponseCode::Refused
    );

    let mut bad_version = query("www.example.", RecordType::A);
    let mut edns = Edns::new();
    edns.set_version(1);
    bad_version.set_edns(edns);
    assert!(matches!(
        udp_query(server.runtime.bound_address, bad_version)
            .await
            .metadata
            .response_code,
        ResponseCode::BADVERS | ResponseCode::BADSIG
    ));

    let mut chaos = query("www.example.", RecordType::A);
    chaos.queries[0].set_query_class(DNSClass::CH);
    assert_eq!(
        udp_query(server.runtime.bound_address, chaos)
            .await
            .metadata
            .response_code,
        ResponseCode::Refused
    );

    let mut status = Message::new(0, MessageType::Query, OpCode::Status);
    status.metadata.recursion_desired = true;
    status.add_query(Query::query(
        Name::from_ascii("www.example.").expect("query name"),
        RecordType::A,
    ));
    assert_eq!(
        udp_query(server.runtime.bound_address, status)
            .await
            .metadata
            .response_code,
        ResponseCode::NotImp
    );

    server.stop().await;
}

#[tokio::test]
async fn acl_denial_over_tcp_returns_refused_without_counting_served() {
    let config = config_for(Protocol::Tcp, r#"acl = { allow = ["198.51.100.0/24"] }"#);
    let server = start_config(&config, false, 16).await;
    let response = tcp_query(
        server.runtime.bound_address,
        query("www.example.", RecordType::A),
    )
    .await;

    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    let snapshot = server.stats.snapshot();
    assert_eq!(snapshot.acl_denied, 1);
    assert_eq!(snapshot.tcp, 1);

    server.stop().await;
}

#[tokio::test]
async fn rate_limit_refuses_after_burst_and_counts_it() {
    let config = config_for(Protocol::Tcp, r#"limits = { qps = 1, burst = 1 }"#);
    let server = start_config(&config, false, 16).await;

    let first = tcp_query(
        server.runtime.bound_address,
        query("www.example.", RecordType::A),
    )
    .await;
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);

    let second = tcp_query(
        server.runtime.bound_address,
        query("www.example.", RecordType::A),
    )
    .await;
    assert_eq!(second.metadata.response_code, ResponseCode::Refused);

    let snapshot = server.stats.snapshot();
    assert_eq!(snapshot.rate_limited, 1);
    assert_eq!(snapshot.tcp, 2);

    server.stop().await;
}

#[tokio::test]
async fn overload_drops_udp_queries_and_counts_them() {
    let config = config_for(Protocol::Udp, "");
    let server = start_config(&config, false, 0).await;
    udp_query_times_out(
        server.runtime.bound_address,
        query("www.example.", RecordType::A),
    )
    .await;

    let snapshot = server.stats.snapshot();
    assert_eq!(snapshot.overloaded, 1);
    assert_eq!(snapshot.udp, 0);

    server.stop().await;
}

#[tokio::test]
async fn edns_padding_pads_response_to_block_size() {
    let server = start(Protocol::Udp, false).await;
    let address = server.runtime.bound_address;

    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("example.com.").expect("name"),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(EdnsCode::Padding.into(), vec![0; 8]));
    request.set_edns(edns);

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    socket
        .send_to(&request.to_vec().expect("encode query"), address)
        .await
        .expect("send query");

    let mut buffer = [0; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .expect("query timed out")
        .expect("receive response");

    let response = Message::from_vec(&buffer[..length]).expect("decode response");
    assert_eq!(length % 128, 0);
    assert!(
        response
            .edns
            .as_ref()
            .expect("response edns")
            .option(EdnsCode::Padding)
            .is_some()
    );

    server.stop().await;
}

#[tokio::test]
async fn tcp_keepalive_is_included_in_tcp_responses() {
    let server = start(Protocol::Tcp, false).await;
    let address = server.runtime.bound_address;

    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("example.com.").expect("name"),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(EdnsCode::Padding.into(), vec![0; 4]));
    request.set_edns(edns);

    let response = tcp_query(address, request).await;
    let keepalive = response
        .edns
        .as_ref()
        .expect("response edns")
        .option(EdnsCode::Keepalive)
        .expect("keepalive option");
    match keepalive {
        EdnsOption::Unknown(code, value) => {
            assert_eq!(*code, u16::from(EdnsCode::Keepalive));
            assert_eq!(u16::from_be_bytes([value[0], value[1]]), 10);
        }
        other => panic!("unexpected keepalive option: {other:?}"),
    }

    server.stop().await;
}

#[tokio::test]
async fn ecs_is_generated_when_enabled() {
    let source = r#"
[logging]
level = "off"

[policy]
refuse_any = true
edns_client_subnet_v4_prefix = 24
edns_client_subnet_v6_prefix = 56

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#;
    let config = Config::from_toml_str(source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("example.com.").expect("name"),
        RecordType::A,
    ));
    request.set_edns(Edns::new());

    let response = udp_query(address, request).await;
    let ecs = response
        .edns
        .as_ref()
        .expect("response edns")
        .option(EdnsCode::Subnet)
        .expect("generated ecs");
    match ecs {
        EdnsOption::Subnet(client_subnet) => {
            assert_eq!(client_subnet.source_prefix(), 24);
            assert_eq!(client_subnet.scope_prefix(), 0);
        }
        other => panic!("unexpected ecs option: {other:?}"),
    }

    server.stop().await;
}

#[tokio::test]
async fn ecs_is_stripped_when_disabled() {
    let server = start(Protocol::Udp, false).await;
    let address = server.runtime.bound_address;

    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("example.com.").expect("name"),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            24,
            0,
        )));
    request.set_edns(edns);

    let response = udp_query(address, request).await;
    assert!(
        response
            .edns
            .as_ref()
            .expect("response edns")
            .option(EdnsCode::Subnet)
            .is_none()
    );

    server.stop().await;
}

#[tokio::test]
async fn rpz_filters_and_redirects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
blocked.example.com CNAME .
*.ads.example.com CNAME .
redirect.example.com CNAME target.example.com.
local.example.com A 127.0.0.1
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut blocked = Message::query();
    blocked.metadata.recursion_desired = true;
    blocked.add_query(Query::query(
        Name::from_ascii("blocked.example.com.").expect("name"),
        RecordType::A,
    ));
    blocked.set_edns(Edns::new());
    let response = udp_query(address, blocked).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);

    let mut wildcard = Message::query();
    wildcard.metadata.recursion_desired = true;
    wildcard.add_query(Query::query(
        Name::from_ascii("foo.bar.ads.example.com.").expect("name"),
        RecordType::A,
    ));
    wildcard.set_edns(Edns::new());
    let response = udp_query(address, wildcard).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);

    let mut redirect = Message::query();
    redirect.metadata.recursion_desired = true;
    redirect.add_query(Query::query(
        Name::from_ascii("redirect.example.com.").expect("name"),
        RecordType::A,
    ));
    redirect.set_edns(Edns::new());
    let response = udp_query(address, redirect).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        response
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::CNAME)
    );

    let mut local = Message::query();
    local.metadata.recursion_desired = true;
    local.add_query(Query::query(
        Name::from_ascii("local.example.com.").expect("name"),
        RecordType::A,
    ));
    local.set_edns(Edns::new());
    let response = udp_query(address, local).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.iter().any(|record| {
        record.record_type() == RecordType::A && record.name.to_string() == "local.example.com."
    }));

    server.stop().await;
}

#[tokio::test]
async fn rpz_wildcard_does_not_match_partial_label() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
*.example.com CNAME .
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut blocked = Message::query();
    blocked.metadata.recursion_desired = true;
    blocked.add_query(Query::query(
        Name::from_ascii("bar.example.com.").expect("name"),
        RecordType::A,
    ));
    blocked.set_edns(Edns::new());
    let response = udp_query(address, blocked).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);

    let mut allowed = Message::query();
    allowed.metadata.recursion_desired = true;
    allowed.add_query(Query::query(
        Name::from_ascii("fooexample.com.").expect("name"),
        RecordType::A,
    ));
    allowed.set_edns(Edns::new());
    let response = udp_query(address, allowed).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.answers.is_empty());

    server.stop().await;
}

#[tokio::test]
async fn rpz_preserves_redirect_ttl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
redirect.example.com 600 CNAME target.example.com.
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut query_message = Message::query();
    query_message.metadata.recursion_desired = true;
    query_message.add_query(Query::query(
        Name::from_ascii("redirect.example.com.").expect("name"),
        RecordType::A,
    ));
    query_message.set_edns(Edns::new());
    let response = udp_query(address, query_message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    let cname = response
        .answers
        .iter()
        .find(|record| record.record_type() == RecordType::CNAME)
        .expect("cname");
    assert_eq!(cname.ttl, 600);

    server.stop().await;
}

#[tokio::test]
async fn rpz_apex_trigger_uses_local_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
@ A 127.0.0.1
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut query_message = Message::query();
    query_message.metadata.recursion_desired = true;
    query_message.add_query(Query::query(Name::root(), RecordType::A));
    query_message.set_edns(Edns::new());
    let response = udp_query(address, query_message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.iter().any(|record| {
        record.record_type() == RecordType::A && record.data.to_string() == "127.0.0.1"
    }));

    server.stop().await;
}

#[tokio::test]
async fn rpz_configured_origin_works() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
 300
rpz.local. SOA localhost. root.localhost. 1 1h 15m 30d 2h
rpz.local. NS localhost.
redirect.example.com.rpz.local. 600 CNAME target.example.com.
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]
rpz_origin = "rpz.local."

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut query_message = Message::query();
    query_message.metadata.recursion_desired = true;
    query_message.add_query(Query::query(
        Name::from_ascii("redirect.example.com.").expect("name"),
        RecordType::A,
    ));
    query_message.set_edns(Edns::new());
    let response = udp_query(address, query_message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        response
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::CNAME)
    );

    server.stop().await;
}

#[tokio::test]
async fn rpz_nodata_returns_no_answers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
nodata.example.com CNAME *.
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii("nodata.example.com.").expect("name"),
        RecordType::A,
    ));
    message.set_edns(Edns::new());
    let response = udp_query(address, message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());

    server.stop().await;
}

#[tokio::test]
async fn rpz_passthru_allows_normal_resolution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
allowed.example.com CNAME rpz-passthru.
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii("allowed.example.com.").expect("name"),
        RecordType::A,
    ));
    message.set_edns(Edns::new());
    let response = udp_query(address, message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.answers.is_empty());

    server.stop().await;
}

#[tokio::test]
async fn rpz_drop_udp_returns_no_response() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
drop.example.com CNAME rpz-drop.
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii("drop.example.com.").expect("name"),
        RecordType::A,
    ));
    message.set_edns(Edns::new());
    udp_query_times_out(address, message).await;

    server.stop().await;
}

#[tokio::test]
async fn rpz_tcp_only_udp_is_truncated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
tcp.example.com CNAME rpz-tcp-only.
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii("tcp.example.com.").expect("name"),
        RecordType::A,
    ));
    message.set_edns(Edns::new());
    let response = udp_query(address, message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.metadata.truncation);

    server.stop().await;
}

#[tokio::test]
async fn rpz_local_data_supports_cname_and_txt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
cname.example.com CNAME target.example.com.
text.example.com TXT "blocked"
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut cname_query = Message::query();
    cname_query.metadata.recursion_desired = true;
    cname_query.add_query(Query::query(
        Name::from_ascii("cname.example.com.").expect("name"),
        RecordType::CNAME,
    ));
    cname_query.set_edns(Edns::new());
    let response = udp_query(address, cname_query).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        response
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::CNAME)
    );

    let mut txt_query = Message::query();
    txt_query.metadata.recursion_desired = true;
    txt_query.add_query(Query::query(
        Name::from_ascii("text.example.com.").expect("name"),
        RecordType::TXT,
    ));
    txt_query.set_edns(Edns::new());
    let response = udp_query(address, txt_query).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        response
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::TXT)
    );

    server.stop().await;
}

#[tokio::test]
async fn rpz_redirect_failure_returns_servfail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
redirect.example.com CNAME fail.example.
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii("redirect.example.com.").expect("name"),
        RecordType::A,
    ));
    message.set_edns(Edns::new());
    let response = udp_query(address, message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);

    server.stop().await;
}

#[tokio::test]
async fn rpz_multiple_files_use_first_exact_trigger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("first.rpz");
    let second = dir.path().join("second.rpz");
    std::fs::write(
        &first,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
example.com CNAME .
"#,
    )
    .expect("write first");
    std::fs::write(
        &second,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
example.com CNAME rpz-passthru.
"#,
    )
    .expect("write second");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}", "{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        first.display(),
        second.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii("example.com.").expect("name"),
        RecordType::A,
    ));
    message.set_edns(Edns::new());
    let response = udp_query(address, message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);

    server.stop().await;
}

#[tokio::test]
async fn rpz_wildcard_more_specific_wins() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
*.com CNAME .
*.example.com CNAME rpz-passthru.
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut specific = Message::query();
    specific.metadata.recursion_desired = true;
    specific.add_query(Query::query(
        Name::from_ascii("host.example.com.").expect("name"),
        RecordType::A,
    ));
    specific.set_edns(Edns::new());
    let response = udp_query(address, specific).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.answers.is_empty());

    let mut broad = Message::query();
    broad.metadata.recursion_desired = true;
    broad.add_query(Query::query(
        Name::from_ascii("host.other.com.").expect("name"),
        RecordType::A,
    ));
    broad.set_edns(Edns::new());
    let response = udp_query(address, broad).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);

    server.stop().await;
}

#[tokio::test]
async fn rpz_invalid_origin_is_rejected() {
    let source = r#"
[logging]
level = "off"

[blocklist]
rpz_origin = "not-a-fqdn"

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#;
    assert!(Config::from_toml_str(source).is_err());
}

#[tokio::test]
async fn rpz_blocks_increment_stats() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpz_path = dir.path().join("block.rpz");
    std::fs::write(
        &rpz_path,
        r#"
$ORIGIN rpz.local.
$TTL 300
@ SOA localhost. root.localhost. 1 1h 15m 30d 2h
  NS localhost.
blocked.example.com CNAME .
"#,
    )
    .expect("write rpz");

    let source = format!(
        r#"
[logging]
level = "off"

[blocklist]
rpz_paths = ["{}"]

[server_limits]
max_udp_payload = 512
query_timeout = "2s"

[dnssec]
enabled = false

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        rpz_path.display()
    );
    let config = Config::from_toml_str(&source).expect("config");
    let server = start_config(&config, false, 16).await;
    let address = server.runtime.bound_address;

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii("blocked.example.com.").expect("name"),
        RecordType::A,
    ));
    message.set_edns(Edns::new());
    let response = udp_query(address, message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(server.stats.snapshot().blocked, 1);

    server.stop().await;
}
