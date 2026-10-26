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
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use echoic::config::Config;
use echoic::listeners::{ListenerRuntime, start_listener};
use echoic::query::QueryService;
use echoic::recursor::build_recursor_with_provider;
use echoic::stats::Stats;
use futures_util::Stream;
use hickory_server::dnssec::NxProofKind;
use hickory_server::net::NetError;
use hickory_server::net::runtime::{TokioRuntimeProvider, TokioTime};
use hickory_server::net::xfer::{DnsHandle, Protocol};
use hickory_server::proto::dnssec::crypto::RsaSigningKey;
use hickory_server::proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS};
use hickory_server::proto::dnssec::{Algorithm, DigestType, DnssecSigner, SigningKey};
use hickory_server::proto::op::{DnsRequest, DnsResponse, Edns, Message, Query, ResponseCode};
use hickory_server::proto::rr::rdata::{A, NS, SOA};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType, RrKey};
use hickory_server::proto::serialize::binary::BinEncoder;
use hickory_server::resolver::config::ConnectionConfig;
use hickory_server::resolver::{ConnectionProvider, PoolContext};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, MessageResponse, ZoneHandler, ZoneType};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const AUTH_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
const SIGNING_KEY: &[u8] = include_bytes!("fixtures/rsa-2048.pk8");

#[derive(Clone)]
struct CaptureResponse {
    buffer: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Default for CaptureResponse {
    fn default() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl ResponseHandler for CaptureResponse {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut buffer = Vec::new();
        let mut encoder = BinEncoder::new(&mut buffer);
        encoder.set_max_size(u16::MAX);
        let info = response
            .destructive_emit(&mut encoder)
            .map_err(NetError::from)?;
        *self.buffer.lock().expect("capture lock") = Some(buffer);
        Ok(info)
    }
}

impl CaptureResponse {
    fn take(&self) -> Option<Vec<u8>> {
        self.buffer.lock().expect("capture lock").take()
    }
}

#[derive(Clone)]
struct SignedProvider {
    root: Arc<Catalog>,
    tld: Arc<Catalog>,
    auth: Arc<Catalog>,
    runtime: TokioRuntimeProvider,
}

impl SignedProvider {
    fn new(root: Catalog, tld: Catalog, auth: Catalog) -> Self {
        Self {
            root: Arc::new(root),
            tld: Arc::new(tld),
            auth: Arc::new(auth),
            runtime: TokioRuntimeProvider::new(),
        }
    }
}

impl ConnectionProvider for SignedProvider {
    type Conn = SignedHandle;
    type FutureConn = std::future::Ready<Result<Self::Conn, NetError>>;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        _config: &ConnectionConfig,
        _cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let catalog = if ip == IpAddr::V4(ROOT_IP) {
            self.root.clone()
        } else if ip == IpAddr::V4(TLD_IP) {
            self.tld.clone()
        } else if ip == IpAddr::V4(AUTH_IP) {
            self.auth.clone()
        } else {
            return Err(NetError::from(format!("unexpected mock server {ip}")));
        };

        Ok(std::future::ready(Ok(SignedHandle { catalog })))
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

#[derive(Clone)]
struct SignedHandle {
    catalog: Arc<Catalog>,
}

impl DnsHandle for SignedHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let catalog = self.catalog.clone();
        Box::pin(futures_util::stream::once(async move {
            answer(&catalog, &request).await
        }))
    }
}

async fn answer(catalog: &Catalog, request: &DnsRequest) -> Result<DnsResponse, NetError> {
    let query = request
        .queries
        .first()
        .cloned()
        .ok_or_else(|| NetError::from("mock request without a query"))?;

    let mut message = Message::query();
    message.metadata.id = request.metadata.id;
    message.metadata.recursion_desired = true;
    message.add_query(query);
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(1232);
    message.edns = Some(edns);

    let query_type = request.queries.first().map(|query| query.query_type());

    let bytes = message.to_vec().map_err(NetError::from)?;
    let request = Request::from_bytes(
        bytes,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53_000)),
        Protocol::Udp,
    )
    .map_err(NetError::from)?;

    let capture = CaptureResponse::default();
    catalog
        .handle_request::<_, TokioTime>(&request, capture.clone())
        .await;

    let bytes = capture
        .take()
        .ok_or_else(|| NetError::from("mock catalog did not respond"))?;
    let mut message = Message::from_vec(&bytes).map_err(NetError::from)?;
    if query_type == Some(RecordType::NS) {
        add_glue(&mut message);
    }
    DnsResponse::from_message(message).map_err(NetError::from)
}

fn add_glue(message: &mut Message) {
    let targets: Vec<Name> = message
        .answers
        .iter()
        .chain(message.authorities.iter())
        .filter(|record| record.record_type() == RecordType::NS)
        .filter_map(|record| match &record.data {
            RData::NS(ns) => Some(ns.0.clone()),
            _ => None,
        })
        .collect();

    for target in targets {
        let Some(address) = glue_address(&target) else {
            continue;
        };
        if message
            .additionals
            .iter()
            .any(|record| record.name == target && record.record_type() == RecordType::A)
        {
            continue;
        }
        message.add_additional(a(&target.to_string(), address));
    }
}

fn glue_address(target: &Name) -> Option<Ipv4Addr> {
    match target.to_string().to_ascii_lowercase().as_str() {
        "a.root-servers.test." => Some(ROOT_IP),
        "ns.example." => Some(TLD_IP),
        "ns.sub.example." | "ns.bogus.example." | "ns.insecure.example." => Some(AUTH_IP),
        _ => None,
    }
}

fn name(value: &str) -> Name {
    Name::from_ascii(value).expect("valid name")
}

fn root_name() -> Name {
    Name::root()
}

fn soa(origin: &Name, primary: &str, mailbox: &str) -> Record {
    Record::from_rdata(
        origin.clone(),
        300,
        RData::SOA(SOA::new(
            name(primary),
            name(mailbox),
            1,
            3600,
            600,
            86_400,
            300,
        )),
    )
}

fn ns(owner: &Name, target: &str) -> Record {
    Record::from_rdata(owner.clone(), 300, RData::NS(NS(name(target))))
}

fn a(owner: &str, address: Ipv4Addr) -> Record {
    let [a, b, c, d] = address.octets();
    Record::from_rdata(name(owner), 60, RData::A(A::new(a, b, c, d)))
}

fn ds(owner: &Name, key: &DNSKEY) -> Record {
    let digest = DS::from_key(key.public_key(), owner, DigestType::SHA256).expect("DS digest");
    Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::DS(digest)))
}

fn zone(origin: &Name, records: Vec<Record>) -> InMemoryZoneHandler {
    let mut zone = InMemoryZoneHandler::empty(
        origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(NxProofKind::Nsec),
    );
    for record in records {
        zone.upsert_mut(record, 0);
    }
    zone
}

fn secure_zone(mut zone: InMemoryZoneHandler, origin: &Name) -> (InMemoryZoneHandler, DNSKEY) {
    let key =
        RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(SIGNING_KEY), Algorithm::RSASHA256)
            .expect("test signing key");
    let public_key = key.to_public_key().expect("public key");
    let dnskey = DNSKEY::from_key(&public_key);
    let signer = DnssecSigner::new(
        dnskey.clone(),
        Box::new(key),
        origin.clone(),
        Duration::from_secs(7 * 24 * 60 * 60),
    );
    zone.add_zone_signing_key_mut(signer)
        .expect("add signing key");
    zone.secure_zone_mut().expect("sign zone");
    (zone, dnskey)
}

fn catalog(zone: InMemoryZoneHandler) -> Catalog {
    let mut catalog = Catalog::new();
    catalog.upsert(
        LowerName::new(zone.origin()),
        vec![Arc::new(zone) as Arc<dyn ZoneHandler>],
    );
    catalog
}

fn signed_hierarchy() -> (SignedProvider, DNSKEY) {
    let sub_origin = name("sub.example.");
    let sub = zone(
        &sub_origin,
        vec![
            soa(&sub_origin, "ns.sub.example.", "hostmaster.example."),
            ns(&sub_origin, "ns.sub.example."),
            a("ns.sub.example.", AUTH_IP),
            a("www.sub.example.", Ipv4Addr::new(192, 0, 2, 10)),
        ],
    );
    let (sub, sub_key) = secure_zone(sub, &sub_origin);

    let bogus_origin = name("bogus.example.");
    let bogus = zone(
        &bogus_origin,
        vec![
            soa(&bogus_origin, "ns.bogus.example.", "hostmaster.example."),
            ns(&bogus_origin, "ns.bogus.example."),
            a("ns.bogus.example.", AUTH_IP),
            a("www.bogus.example.", Ipv4Addr::new(192, 0, 2, 20)),
        ],
    );
    let (mut bogus, bogus_key) = secure_zone(bogus, &bogus_origin);
    let tampered_name = name("www.bogus.example.");
    let rr_key = RrKey::new(LowerName::new(&tampered_name), RecordType::A);
    let rrsigs = bogus
        .records_get_mut()
        .get(&rr_key)
        .map(|rrset| rrset.rrsigs().to_vec())
        .unwrap_or_default();
    bogus.upsert_mut(
        a(&tampered_name.to_string(), Ipv4Addr::new(192, 0, 2, 21)),
        1,
    );
    if let Some(rrset) = bogus.records_get_mut().get_mut(&rr_key) {
        for rrsig in rrsigs {
            Arc::make_mut(rrset).insert_rrsig(rrsig);
        }
    }

    let insecure_origin = name("insecure.example.");
    let insecure = zone(
        &insecure_origin,
        vec![
            soa(
                &insecure_origin,
                "ns.insecure.example.",
                "hostmaster.example.",
            ),
            ns(&insecure_origin, "ns.insecure.example."),
            a("ns.insecure.example.", AUTH_IP),
            a("www.insecure.example.", Ipv4Addr::new(192, 0, 2, 30)),
        ],
    );

    let example_origin = name("example.");
    let example = zone(
        &example_origin,
        vec![
            soa(&example_origin, "ns.example.", "hostmaster.example."),
            ns(&example_origin, "ns.example."),
            a("ns.example.", TLD_IP),
            ns(&sub_origin, "ns.sub.example."),
            a("ns.sub.example.", AUTH_IP),
            ds(&sub_origin, &sub_key),
            ns(&bogus_origin, "ns.bogus.example."),
            a("ns.bogus.example.", AUTH_IP),
            ds(&bogus_origin, &bogus_key),
            ns(&insecure_origin, "ns.insecure.example."),
            a("ns.insecure.example.", AUTH_IP),
        ],
    );
    let (example, example_key) = secure_zone(example, &example_origin);

    let root = zone(
        &root_name(),
        vec![
            soa(
                &root_name(),
                "a.root-servers.test.",
                "hostmaster.root-servers.test.",
            ),
            ns(&root_name(), "a.root-servers.test."),
            a("a.root-servers.test.", ROOT_IP),
            ns(&example_origin, "ns.example."),
            a("ns.example.", TLD_IP),
            ds(&example_origin, &example_key),
        ],
    );
    let (root, root_key) = secure_zone(root, &root_name());

    let mut auth = Catalog::new();
    auth.upsert(
        LowerName::new(sub.origin()),
        vec![Arc::new(sub) as Arc<dyn ZoneHandler>],
    );
    auth.upsert(
        LowerName::new(bogus.origin()),
        vec![Arc::new(bogus) as Arc<dyn ZoneHandler>],
    );
    auth.upsert(
        LowerName::new(insecure.origin()),
        vec![Arc::new(insecure) as Arc<dyn ZoneHandler>],
    );

    (
        SignedProvider::new(catalog(root), catalog(example), auth),
        root_key,
    )
}

struct DnssecServer {
    runtime: ListenerRuntime,
    stats: Arc<Stats>,
}

impl DnssecServer {
    async fn stop(self) {
        self.runtime.token.cancel();
        let _ = self.runtime.task.await;
    }
}

fn config(root_hints: &std::path::Path, trust_anchor: &std::path::Path) -> Config {
    let source = format!(
        r#"
[logging]
level = "off"

[dnssec]
enabled = true
trust_anchor = "{}"

[recursor]
root_hints = "{}"
deny_server = []

[[listeners]]
name = "test"
protocol = "udp"
address = "127.0.0.1:0"
"#,
        trust_anchor.display(),
        root_hints.display()
    );
    Config::from_toml_str(&source).expect("test configuration")
}

async fn start_dnssec_server() -> DnssecServer {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root_hints = directory.path().join("root.hints");
    std::fs::write(
        &root_hints,
        format!(
            ". 3600000 IN NS a.root-servers.test.\na.root-servers.test. 3600000 IN A {ROOT_IP}\n"
        ),
    )
    .expect("write root hints");

    let (provider, root_key) = signed_hierarchy();
    let trust_anchor = directory.path().join("trust-anchor.key");
    std::fs::write(&trust_anchor, format!(". 3600 IN DNSKEY {root_key}\n"))
        .expect("write trust anchor");

    let config = config(&root_hints, &trust_anchor);
    let resolver =
        build_recursor_with_provider(&config, provider).expect("build validating recursor");
    let stats = Arc::new(Stats::default());
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

    DnssecServer { runtime, stats }
}

fn query(qname: &str, query_type: RecordType) -> Message {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name(qname), query_type));
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
async fn validates_secure_insecure_and_bogus_answers() {
    let server = start_dnssec_server().await;

    let secure = udp_query(
        server.runtime.bound_address,
        query("www.sub.example.", RecordType::A),
    )
    .await;
    assert_eq!(secure.metadata.response_code, ResponseCode::NoError);
    assert!(secure.metadata.authentic_data);
    assert!(secure.answers.iter().any(|record| {
        matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::new(192, 0, 2, 10))
    }));

    let insecure = udp_query(
        server.runtime.bound_address,
        query("www.insecure.example.", RecordType::A),
    )
    .await;
    assert_eq!(insecure.metadata.response_code, ResponseCode::NoError);
    assert!(!insecure.metadata.authentic_data);
    assert!(insecure.answers.iter().any(|record| {
        matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::new(192, 0, 2, 30))
    }));

    let bogus = udp_query(
        server.runtime.bound_address,
        query("www.bogus.example.", RecordType::A),
    )
    .await;
    assert_eq!(bogus.metadata.response_code, ResponseCode::ServFail);
    assert!(bogus.answers.is_empty());
    assert_eq!(server.stats.snapshot().servfail, 1);

    server.stop().await;
}
