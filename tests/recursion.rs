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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use echoic::config::Config;
use echoic::listeners::{ListenerRuntime, start_listener};
use echoic::metrics::EchoicMetricsRecorder;
use echoic::query::QueryService;
use echoic::recursor::build_recursor_with_provider;
use echoic::stats::Stats;
use hickory_server::net::NetError;
use hickory_server::net::runtime::TokioRuntimeProvider;
use hickory_server::net::xfer::DnsHandle;
use hickory_server::proto::op::{DnsRequest, DnsResponse, Message, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::rdata::{A, NS, SOA};
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use hickory_server::resolver::config::ConnectionConfig;
use hickory_server::resolver::{ConnectionProvider, PoolContext};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const AUTH_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Root,
    Tld,
    Auth,
}

#[derive(Clone, Default)]
struct Counters {
    root: Arc<AtomicU64>,
    tld: Arc<AtomicU64>,
    auth: Arc<AtomicU64>,
}

impl Counters {
    fn record(&self, role: Role) {
        let counter = match role {
            Role::Root => &self.root,
            Role::Tld => &self.tld,
            Role::Auth => &self.auth,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn count(&self, role: Role) -> u64 {
        let counter = match role {
            Role::Root => &self.root,
            Role::Tld => &self.tld,
            Role::Auth => &self.auth,
        };
        counter.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
struct MockProvider {
    counters: Counters,
    runtime: TokioRuntimeProvider,
}

impl MockProvider {
    fn new(counters: Counters) -> Self {
        Self {
            counters,
            runtime: TokioRuntimeProvider::new(),
        }
    }
}

impl ConnectionProvider for MockProvider {
    type Conn = MockHandle;
    type FutureConn = std::future::Ready<Result<Self::Conn, NetError>>;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        _config: &ConnectionConfig,
        _cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let role = if ip == IpAddr::V4(ROOT_IP) {
            Role::Root
        } else if ip == IpAddr::V4(TLD_IP) {
            Role::Tld
        } else if ip == IpAddr::V4(AUTH_IP) {
            Role::Auth
        } else {
            return Err(NetError::from(format!("unexpected mock server {ip}")));
        };

        Ok(std::future::ready(Ok(MockHandle {
            role,
            counters: self.counters.clone(),
        })))
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

#[derive(Clone)]
struct MockHandle {
    role: Role,
    counters: Counters,
}

impl DnsHandle for MockHandle {
    type Response = futures_util::stream::Iter<std::vec::IntoIter<Result<DnsResponse, NetError>>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        self.counters.record(self.role);

        let response = match request.queries.first() {
            Some(query) => answer(self.role, request.metadata.id, query),
            None => Message::error_msg(request.metadata.id, OpCode::Query, ResponseCode::FormErr),
        };
        let response = DnsResponse::from_message(response).map_err(NetError::from);

        futures_util::stream::iter(vec![response])
    }
}

fn answer(role: Role, id: u16, query: &Query) -> Message {
    let mut response = Message::response(id, OpCode::Query);
    response.add_query(query.clone());

    let name = query.name().to_string().to_ascii_lowercase();
    match role {
        Role::Root => referral(&mut response, "example.", "ns.example.", TLD_IP),
        Role::Tld => referral(&mut response, "sub.example.", "ns.auth.example.", AUTH_IP),
        Role::Auth if query.query_type() == RecordType::NS => {
            response.metadata.authoritative = true;
        }
        Role::Auth => match name.as_str() {
            "www.sub.example." => {
                response.metadata.authoritative = true;
                response.add_answer(a_record("www.sub.example.", ANSWER_IP, 60));
            }
            "missing.sub.example." => {
                response.metadata.authoritative = true;
                response.metadata.response_code = ResponseCode::NXDomain;
                response.add_authority(soa_record("sub.example."));
            }
            "nodata.sub.example." => {
                response.metadata.authoritative = true;
                response.add_authority(soa_record("sub.example."));
            }
            _ => {
                response.metadata.authoritative = true;
                response.metadata.response_code = ResponseCode::NXDomain;
                response.add_authority(soa_record("sub.example."));
            }
        },
    }

    response
}

fn referral(response: &mut Message, zone: &str, name_server: &str, address: Ipv4Addr) {
    response.add_authority(Record::from_rdata(
        Name::from_ascii(zone).expect("zone name"),
        60,
        RData::NS(NS(Name::from_ascii(name_server).expect("name server"))),
    ));
    response.add_additional(a_record(name_server, address, 60));
}

fn a_record(name: &str, address: Ipv4Addr, ttl: u32) -> Record {
    let [a, b, c, d] = address.octets();
    Record::from_rdata(
        Name::from_ascii(name).expect("record name"),
        ttl,
        RData::A(A::new(a, b, c, d)),
    )
}

fn soa_record(zone: &str) -> Record {
    Record::from_rdata(
        Name::from_ascii(zone).expect("zone name"),
        300,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.example.").expect("mname"),
            Name::from_ascii("hostmaster.example.").expect("rname"),
            1,
            3600,
            600,
            86_400,
            300,
        )),
    )
}

struct RecursionServer {
    runtime: ListenerRuntime,
    stats: Arc<Stats>,
}

impl RecursionServer {
    async fn stop(self) {
        self.runtime.token.cancel();
        let _ = self.runtime.task.await;
    }
}

fn config_with_root_hints(root_hints: &std::path::Path) -> Config {
    let source = format!(
        r#"
[logging]
level = "off"

[dnssec]
enabled = false

[recursor]
root_hints = "{}"
deny_server = []

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        root_hints.display()
    );
    Config::from_toml_str(&source).expect("test configuration")
}

async fn start_recursion_server(stats: Arc<Stats>) -> (RecursionServer, Counters) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root_hints = directory.path().join("root.hints");
    std::fs::write(
        &root_hints,
        format!(
            ". 3600000 IN NS a.root-servers.test.\na.root-servers.test. 3600000 IN A {ROOT_IP}\n"
        ),
    )
    .expect("write root hints");

    let config = config_with_root_hints(&root_hints);
    let counters = Counters::default();
    let resolver = build_recursor_with_provider(&config, MockProvider::new(counters.clone()))
        .expect("build recursor");
    let service = QueryService::new(
        resolver,
        &config.listeners[0],
        stats.clone(),
        Arc::new(ArcSwap::from_pointee(Arc::new(Semaphore::new(16)))),
        &config.server_limits,
        config.policy.refuse_any,
        config.logging.query_names,
        config.policy.edns_client_subnet_v4_prefix,
        config.policy.edns_client_subnet_v6_prefix,
        echoic::rpz::RpzPolicy::empty(),
    );
    let runtime = start_listener(
        &config.listeners[0],
        service,
        config.server_limits.query_timeout,
    )
    .await
    .expect("start listener");

    (RecursionServer { runtime, stats }, counters)
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

#[tokio::test]
async fn recurses_through_delegations_and_maps_negative_answers() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    let stats = Arc::new(Stats::default());
    let (server, counters) = start_recursion_server(stats.clone()).await;

    let response = udp_query(
        server.runtime.bound_address,
        query("www.sub.example.", RecordType::A),
    )
    .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        response
            .answers
            .iter()
            .any(|record| { matches!(record.data, RData::A(address) if address.0 == ANSWER_IP) })
    );
    assert_eq!(server.stats.snapshot().udp, 1);

    let response = udp_query(
        server.runtime.bound_address,
        query("missing.sub.example.", RecordType::A),
    )
    .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
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
        query("nodata.sub.example.", RecordType::AAAA),
    )
    .await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());
    assert_eq!(
        response
            .authorities
            .iter()
            .filter(|record| record.record_type() == RecordType::SOA)
            .count(),
        1
    );

    assert!(counters.count(Role::Root) >= 1);
    assert!(counters.count(Role::Tld) >= 1);
    assert!(counters.count(Role::Auth) >= 1);

    server.stop().await;
}

#[tokio::test]
async fn recursor_cache_hit_is_recorded_after_startup() {
    let stats = Arc::new(Stats::default());
    metrics::set_global_recorder(EchoicMetricsRecorder::new(stats.clone()))
        .expect("install metrics recorder");
    let (server, counters) = start_recursion_server(stats.clone()).await;

    let first = udp_query(
        server.runtime.bound_address,
        query("www.sub.example.", RecordType::A),
    )
    .await;
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);

    let root_count_after_first = counters.count(Role::Root);

    let second = udp_query(
        server.runtime.bound_address,
        query("www.sub.example.", RecordType::A),
    )
    .await;
    assert_eq!(second.metadata.response_code, ResponseCode::NoError);
    assert_eq!(counters.count(Role::Root), root_count_after_first);

    let snapshot = stats.snapshot();
    assert!(snapshot.cache_hits > 0);
    assert!(snapshot.cache_hits + snapshot.cache_misses > 0);

    server.stop().await;
}
