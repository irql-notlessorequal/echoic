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
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::Duration;

use echoic::config::Config;
use echoic::dot::start_dot_listener;
use echoic::listeners::ListenerRuntime;
use echoic::query::QueryService;
use echoic::recursor::RecursiveResolver;
use echoic::stats::Stats;
use echoic::tls::TlsState;
use hickory_server::proto::op::{Message, Query, ResponseCode};
use hickory_server::proto::rr::{Name, RecordType};
use hickory_server::resolver::recursor::RecursorError;
use rcgen::generate_simple_self_signed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
struct MockResolver;

#[async_trait::async_trait]
impl RecursiveResolver for MockResolver {
    async fn resolve(
        &self,
        query: hickory_server::proto::op::Query,
        _dnssec_ok: bool,
    ) -> Result<Message, RecursorError> {
        let mut response = Message::response(0, hickory_server::proto::op::OpCode::Query);
        response.add_query(query.clone());
        response.add_answer(hickory_server::proto::rr::Record::from_rdata(
            query.name().clone(),
            60,
            hickory_server::proto::rr::RData::A(hickory_server::proto::rr::rdata::A::new(
                192, 0, 2, 10,
            )),
        ));
        Ok(response)
    }

    fn is_validating(&self) -> bool {
        false
    }
}

struct TestServer {
    runtime: ListenerRuntime,
    #[allow(dead_code)]
    tls_state: Arc<TlsState>,
}

impl TestServer {
    async fn stop(self) {
        self.runtime.token.cancel();
        let _ = self.runtime.task.await;
    }
}

async fn start() -> TestServer {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");

    // Keep tempdir alive by leaking it for the test process lifetime.
    std::mem::forget(dir);

    let tls_state = Arc::new(TlsState::load(&cert_path, &key_path).expect("tls"));

    let config: Config = toml::from_str(
        r#"
[dnssec]
enabled = false

[[listeners]]
name = "dot"
protocol = "dot"
address = "127.0.0.1:0"
tls = "public"
limits = { max_connections = 8 }
"#,
    )
    .expect("config");
    // Attach tls entry manually via Config construction is not possible; use listener directly.
    let mut listener = config.listeners[0].clone();
    listener.tls = Some("public".to_string());

    let stats = Arc::new(Stats::default());
    let service = QueryService::new(
        Arc::new(MockResolver),
        &listener,
        stats,
        Arc::new(ArcSwap::from_pointee(Arc::new(
            tokio::sync::Semaphore::new(8),
        ))),
        &config.server_limits,
        config.policy.refuse_any,
        false,
        config.policy.edns_client_subnet_v4_prefix,
        config.policy.edns_client_subnet_v6_prefix,
        echoic::rpz::RpzPolicy::empty(),
    );

    let runtime = start_dot_listener(
        &listener,
        service,
        tls_state.clone(),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .expect("start dot");

    TestServer { runtime, tls_state }
}

#[tokio::test]
async fn dot_resolves() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server = start().await;
    let address = server.runtime.bound_address;

    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    // Reuse the server's certificate by reading from its TlsState? Instead trust any cert via custom verifier.
    let _ = cert;

    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"dot".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(address).await.expect("tcp");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let mut tls = connector.connect(server_name, tcp).await.expect("tls");

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii("example.com.").expect("name"),
        RecordType::A,
    ));
    let bytes = message.to_vec().expect("encode");
    tls.write_all(&(bytes.len() as u16).to_be_bytes())
        .await
        .expect("write len");
    tls.write_all(&bytes).await.expect("write msg");
    tls.flush().await.expect("flush");

    let mut len_buf = [0_u8; 2];
    tls.read_exact(&mut len_buf).await.expect("read len");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0_u8; len];
    tls.read_exact(&mut response).await.expect("read response");
    let response = Message::from_vec(&response).expect("decode");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);

    server.stop().await;
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
