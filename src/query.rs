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
use std::iter;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_server::net::runtime::Time;
use hickory_server::net::{DnsError, NetError};
use hickory_server::proto::op::{
    Edns, Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_server::proto::rr::rdata::SOA;
use hickory_server::proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_server::proto::rr::{DNSClass, Name, Record, RecordType};
use hickory_server::resolver::recursor::RecursorError;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{MessageResponseBuilder, Queries};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{AclConfig, ListenerConfig, Protocol, ServerLimits};
use crate::net::normalize_ip;
use crate::rate_limit::{KeyedRateLimiter, RateKey, keyed_limiter};
use crate::recursor::{RecursiveResolver, RecursorHandle};
use crate::stats::Stats;

const KEEPALIVE_TIMEOUT_UNIT_MS: u128 = 100;

#[derive(Clone, Copy, Debug)]
enum ExtendedDnsError {
    DnssecBogus,
    Blocked,
    Filtered,
    StaleAnswer,
}

impl ExtendedDnsError {
    fn info_code(self) -> u16 {
        match self {
            Self::DnssecBogus => 6,
            Self::Blocked => 15,
            Self::Filtered => 17,
            Self::StaleAnswer => 3,
        }
    }

    fn text(self) -> &'static str {
        match self {
            Self::DnssecBogus => "DNSSEC validation failed",
            Self::Blocked => "Blocked",
            Self::Filtered => "Filtered",
            Self::StaleAnswer => "Stale Answer",
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = self.info_code().to_be_bytes().to_vec();
        bytes.extend_from_slice(self.text().as_bytes());
        bytes
    }
}

fn rpz_extended_dns_error(action: &crate::rpz::RpzAction) -> Option<ExtendedDnsError> {
    match action {
        crate::rpz::RpzAction::Passthru => None,
        crate::rpz::RpzAction::Nxdomain => Some(ExtendedDnsError::Filtered),
        _ => Some(ExtendedDnsError::Blocked),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    AclDenied,
    RateLimited,
    Overloaded,
}

#[derive(Clone)]
pub struct ListenerQueryState {
    pub acl: Arc<AclConfig>,
    pub rate_limiter: Arc<KeyedRateLimiter>,
    pub refuse_any: bool,
    pub max_udp_payload: u16,
    pub query_timeout: Duration,
    pub idle_timeout: Duration,
    pub query_names: bool,
    pub require_dot_alpn: bool,
    pub edns_padding_block_size: usize,
    pub blocklist: Arc<crate::rpz::RpzPolicy>,
}

fn padding_requested(request: &Request, state: &ListenerQueryState) -> bool {
    state.edns_padding_block_size != 0
        && request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.option(EdnsCode::Padding).is_some())
}

fn padding_len(state: &ListenerQueryState, base_len: usize) -> usize {
    let block_size = state.edns_padding_block_size;
    (block_size - ((base_len + 4) % block_size)) % block_size
}

pub struct QueryService {
    resolver: RecursorHandle,
    listener_name: String,
    protocol: Protocol,
    state: Arc<ArcSwap<ListenerQueryState>>,
    stats: Arc<Stats>,
    inflight: Arc<ArcSwap<Arc<Semaphore>>>,
}

impl QueryService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resolver: RecursorHandle,
        listener: &ListenerConfig,
        stats: Arc<Stats>,
        inflight: Arc<ArcSwap<Arc<Semaphore>>>,
        server_limits: &ServerLimits,
        refuse_any: bool,
        query_names: bool,
        blocklist: Arc<crate::rpz::RpzPolicy>,
    ) -> Self {
        let limits = listener.limits.effective(listener.protocol);
        let state = ListenerQueryState {
            acl: Arc::new(listener.acl.clone()),
            rate_limiter: Arc::new(keyed_limiter(limits.qps, limits.burst)),
            refuse_any,
            max_udp_payload: server_limits.max_udp_payload,
            query_timeout: server_limits.query_timeout,
            idle_timeout: server_limits.idle_timeout,
            query_names,
            require_dot_alpn: listener.require_dot_alpn,
            edns_padding_block_size: listener.edns_padding_block_size(),
            blocklist,
        };

        Self {
            resolver,
            listener_name: listener.name.clone(),
            protocol: listener.protocol,
            state: Arc::new(ArcSwap::from_pointee(state)),
            stats,
            inflight,
        }
    }

    pub fn rate_limiter(&self) -> Arc<KeyedRateLimiter> {
        self.state.load().rate_limiter.clone()
    }

    pub fn state(&self) -> Arc<ArcSwap<ListenerQueryState>> {
        self.state.clone()
    }

    pub fn inflight(&self) -> Arc<Semaphore> {
        Arc::clone(&*self.inflight.load())
    }

    pub fn acl(&self) -> Arc<AclConfig> {
        self.state.load().acl.clone()
    }

    pub fn resolver(&self) -> Arc<dyn RecursiveResolver> {
        self.resolver.current()
    }

    pub fn validating(&self) -> bool {
        self.resolver().is_validating()
    }

    pub fn refuse_any(&self) -> bool {
        self.state.load().refuse_any
    }

    pub fn query_names(&self) -> bool {
        self.state.load().query_names
    }

    pub fn edns_padding_block_size(&self) -> usize {
        self.state.load().edns_padding_block_size
    }

    pub fn blocklist(&self) -> Arc<crate::rpz::RpzPolicy> {
        self.state.load().blocklist.clone()
    }

    pub fn max_udp_payload(&self) -> u16 {
        self.state.load().max_udp_payload
    }

    pub fn query_timeout(&self) -> Duration {
        self.state.load().query_timeout
    }

    pub fn idle_timeout(&self) -> Duration {
        self.state.load().idle_timeout
    }

    pub fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    pub fn snapshot(&self) -> Arc<ListenerQueryState> {
        self.state.load_full()
    }

    pub fn admit(
        &self,
        source: IpAddr,
        state: &ListenerQueryState,
    ) -> Result<OwnedSemaphorePermit, AdmissionError> {
        let inflight = self.inflight();
        self.admit_with(source, state, inflight)
    }

    pub fn admit_with(
        &self,
        source: IpAddr,
        state: &ListenerQueryState,
        inflight: Arc<Semaphore>,
    ) -> Result<OwnedSemaphorePermit, AdmissionError> {
        let source = normalize_ip(source);
        if !state.acl.is_allowed(source, self.protocol) {
            self.stats.record_acl_denied();
            return Err(AdmissionError::AclDenied);
        }
        if state
            .rate_limiter
            .check_key(&RateKey::from(source))
            .is_err()
        {
            self.stats.record_rate_limited();
            return Err(AdmissionError::RateLimited);
        }
        match inflight.try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(_) => {
                self.stats.record_overloaded();
                Err(AdmissionError::Overloaded)
            }
        }
    }

    async fn reject<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        response_code: ResponseCode,
        state: &ListenerQueryState,
        started: Instant,
    ) -> ResponseInfo {
        if self.protocol == Protocol::Udp {
            drop_response(request)
        } else {
            self.send_status(
                request,
                response_handle,
                response_code,
                None,
                state,
                started,
            )
            .await
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_status<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        response_code: ResponseCode,
        extended_error: Option<ExtendedDnsError>,
        state: &ListenerQueryState,
        started: Instant,
    ) -> ResponseInfo {
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;
        metadata.response_code = response_code;

        let mut edns = response_edns(request, state, self.protocol, extended_error);
        if let Some(edns) = &mut edns {
            edns.options_mut().remove(EdnsCode::Padding);
        }
        if padding_requested(request, state)
            && let Some(edns) = &mut edns
        {
            let measurement = MessageResponseBuilder::new(&request.queries, Some(edns))
                .build_no_records(metadata);
            let mut measurement_bytes = Vec::with_capacity(512);
            let mut measurement_encoder =
                hickory_server::proto::serialize::binary::BinEncoder::new(&mut measurement_bytes);
            let _ = measurement.destructive_emit(&mut measurement_encoder);
            let pad_len = padding_len(state, measurement_bytes.len());
            edns.options_mut().insert(EdnsOption::Unknown(
                EdnsCode::Padding.into(),
                vec![0; pad_len],
            ));
        }

        let response =
            MessageResponseBuilder::new(&request.queries, edns.as_ref()).build_no_records(metadata);

        match response_handle.send_response(response).await {
            Ok(info) => {
                self.record_response(request, response_code, state, started, false);
                info
            }
            Err(error) => {
                tracing::warn!(
                    listener = %self.listener_name,
                    error = %error,
                    "failed to send DNS response"
                );
                drop_response(request)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_message<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        mut message: hickory_server::proto::op::Message,
        extended_error: Option<ExtendedDnsError>,
        state: &ListenerQueryState,
        validating: bool,
        started: Instant,
    ) -> ResponseInfo {
        if validating {
            if message_is_bogus(&message) {
                let answer_types = bogus_record_types(&message.answers);
                let authority_types = bogus_record_types(&message.authorities);
                tracing::warn!(
                    listener = %self.listener_name,
                    answer_types = ?answer_types,
                    authority_types = ?authority_types,
                    "DNSSEC validation failed"
                );
                return self
                    .send_status(
                        request,
                        response_handle,
                        ResponseCode::ServFail,
                        Some(ExtendedDnsError::DnssecBogus),
                        state,
                        started,
                    )
                    .await;
            }

            if message
                .additionals
                .iter()
                .any(|record| record.proof.is_bogus())
            {
                let record_types = bogus_record_types(&message.additionals);
                tracing::debug!(
                    listener = %self.listener_name,
                    record_types = ?record_types,
                    "dropping bogus DNSSEC additional records"
                );
                message
                    .additionals
                    .retain(|record| !record.proof.is_bogus());
            }
        }

        let response_code = message.metadata.response_code;
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;
        metadata.response_code = response_code;
        metadata.authentic_data = validating
            && matches!(
                response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
            && message_is_secure(&message);

        let mut edns = response_edns(request, state, self.protocol, extended_error);
        if let Some(edns) = &mut edns {
            edns.options_mut().remove(EdnsCode::Padding);
        }
        if padding_requested(request, state)
            && let Some(edns) = &mut edns
        {
            let measurement = MessageResponseBuilder::new(&request.queries, Some(edns)).build(
                metadata,
                &message.answers,
                &message.authorities,
                iter::empty::<&Record>(),
                &message.additionals,
            );
            let mut measurement_bytes = Vec::with_capacity(512);
            let mut measurement_encoder =
                hickory_server::proto::serialize::binary::BinEncoder::new(&mut measurement_bytes);
            let _ = measurement.destructive_emit(&mut measurement_encoder);
            let pad_len = padding_len(state, measurement_bytes.len());
            edns.options_mut().insert(EdnsOption::Unknown(
                EdnsCode::Padding.into(),
                vec![0; pad_len],
            ));
        }

        let response = MessageResponseBuilder::new(&request.queries, edns.as_ref()).build(
            metadata,
            &message.answers,
            &message.authorities,
            iter::empty::<&Record>(),
            &message.additionals,
        );

        match response_handle.send_response(response).await {
            Ok(info) => {
                self.record_response(
                    request,
                    response_code,
                    state,
                    started,
                    metadata.authentic_data,
                );
                info
            }
            Err(error) => {
                tracing::warn!(
                    listener = %self.listener_name,
                    error = %error,
                    "failed to send DNS response"
                );
                drop_response(request)
            }
        }
    }

    async fn send_negative<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        negative: NegativeResponse,
        state: &ListenerQueryState,
        validating: bool,
        started: Instant,
    ) -> ResponseInfo {
        let NegativeResponse {
            response_code,
            authorities,
            soa,
            secure,
        } = negative;
        let authentic_data = validating && secure;
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;
        metadata.response_code = response_code;
        metadata.authentic_data = authentic_data;

        let mut edns = response_edns(request, state, self.protocol, None);
        if let Some(edns) = &mut edns {
            edns.options_mut().remove(EdnsCode::Padding);
        }
        if padding_requested(request, state)
            && let Some(edns) = &mut edns
        {
            let measurement = MessageResponseBuilder::new(&request.queries, Some(edns)).build(
                metadata,
                iter::empty::<&Record>(),
                authorities.iter(),
                soa.iter(),
                iter::empty::<&Record>(),
            );
            let mut measurement_bytes = Vec::with_capacity(512);
            let mut measurement_encoder =
                hickory_server::proto::serialize::binary::BinEncoder::new(&mut measurement_bytes);
            let _ = measurement.destructive_emit(&mut measurement_encoder);
            let pad_len = padding_len(state, measurement_bytes.len());
            edns.options_mut().insert(EdnsOption::Unknown(
                EdnsCode::Padding.into(),
                vec![0; pad_len],
            ));
        }

        let response = MessageResponseBuilder::new(&request.queries, edns.as_ref()).build(
            metadata,
            iter::empty::<&Record>(),
            authorities.iter(),
            soa.iter(),
            iter::empty::<&Record>(),
        );

        match response_handle.send_response(response).await {
            Ok(info) => {
                self.record_response(request, response_code, state, started, authentic_data);
                info
            }
            Err(error) => {
                tracing::warn!(
                    listener = %self.listener_name,
                    error = %error,
                    "failed to send DNS response"
                );
                drop_response(request)
            }
        }
    }

    pub async fn handle_malformed<R: ResponseHandler>(
        &self,
        source: std::net::SocketAddr,
        header: Header,
        queries: Queries,
        response_handle: R,
        started: Instant,
    ) -> ResponseInfo {
        let state = self.snapshot();
        let _permit = match self.admit(source.ip(), &state) {
            Ok(permit) => permit,
            Err(_) if self.protocol == Protocol::Udp => return drop_simple(&header),
            Err(_) => {
                return self
                    .send_simple(
                        source,
                        header,
                        &queries,
                        response_handle,
                        ResponseCode::Refused,
                        &state,
                        started,
                    )
                    .await;
            }
        };

        self.send_simple(
            source,
            header,
            &queries,
            response_handle,
            ResponseCode::FormErr,
            &state,
            started,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_simple<R: ResponseHandler>(
        &self,
        source: std::net::SocketAddr,
        header: Header,
        queries: &Queries,
        mut response_handle: R,
        response_code: ResponseCode,
        state: &ListenerQueryState,
        started: Instant,
    ) -> ResponseInfo {
        let mut metadata = header.metadata;
        metadata.message_type = MessageType::Response;
        metadata.recursion_available = true;
        metadata.response_code = response_code;
        metadata.authentic_data = false;

        let response = MessageResponseBuilder::new(queries, None).build_no_records(metadata);

        match response_handle.send_response(response).await {
            Ok(info) => {
                self.stats.record(self.protocol);
                if response_code == ResponseCode::ServFail {
                    self.stats.record_servfail();
                }

                let elapsed_ms = started.elapsed().as_millis();
                let query = queries.queries().first();
                if state.query_names {
                    tracing::debug!(
                        listener = %self.listener_name,
                        protocol = self.protocol.as_str(),
                        src = %source.ip(),
                        name = query.map(|query| query.name().to_string()),
                        qtype = query.map(|query| query.query_type().to_string()),
                        rcode = %response_code,
                        elapsed_ms,
                        dnssec = false,
                        "query completed"
                    );
                } else {
                    tracing::debug!(
                        listener = %self.listener_name,
                        protocol = self.protocol.as_str(),
                        src = %source.ip(),
                        qtype = query.map(|query| query.query_type().to_string()),
                        rcode = %response_code,
                        elapsed_ms,
                        dnssec = false,
                        "query completed"
                    );
                }

                info
            }
            Err(error) => {
                tracing::warn!(
                    listener = %self.listener_name,
                    error = %error,
                    "failed to send DNS response"
                );
                ResponseInfo::from(hickory_server::proto::op::Header {
                    metadata,
                    counts: hickory_server::proto::op::HeaderCounts::default(),
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_status_truncated<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        response_code: ResponseCode,
        extended_error: Option<ExtendedDnsError>,
        state: &ListenerQueryState,
        started: Instant,
    ) -> ResponseInfo {
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;
        metadata.response_code = response_code;
        metadata.truncation = true;

        let edns = response_edns(request, state, self.protocol, extended_error);
        let response =
            MessageResponseBuilder::new(&request.queries, edns.as_ref()).build_no_records(metadata);

        match response_handle.send_response(response).await {
            Ok(info) => {
                self.record_response(request, response_code, state, started, false);
                info
            }
            Err(error) => {
                tracing::warn!(
                    listener = %self.listener_name,
                    error = %error,
                    "failed to send DNS response"
                );
                drop_response(request)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_rpz_redirect<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        query: &hickory_server::proto::op::Query,
        target: Name,
        ttl: u32,
        state: &ListenerQueryState,
        validating: bool,
        started: Instant,
        dnssec_ok: bool,
    ) -> ResponseInfo {
        let target_query =
            hickory_server::proto::op::Query::query(target.clone(), query.query_type());
        let target_response = match tokio::time::timeout(
            state.query_timeout,
            self.resolver().resolve(target_query, dnssec_ok),
        )
        .await
        {
            Ok(Ok(response)) => response,
            _ => {
                return self
                    .send_status(
                        request,
                        response_handle,
                        ResponseCode::ServFail,
                        None,
                        state,
                        started,
                    )
                    .await;
            }
        };

        let mut answers = Vec::with_capacity(target_response.answers.len() + 1);
        answers.push(Record::from_rdata(
            query.name().clone(),
            ttl,
            hickory_server::proto::rr::RData::CNAME(hickory_server::proto::rr::rdata::CNAME(
                target,
            )),
        ));
        answers.extend(target_response.answers.iter().cloned());

        self.send_rpz_message(
            request,
            response_handle,
            query,
            answers,
            target_response.metadata.response_code,
            state,
            validating,
            started,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_rpz_local_data<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        query: &hickory_server::proto::op::Query,
        records: Arc<[Record]>,
        state: &ListenerQueryState,
        validating: bool,
        started: Instant,
    ) -> ResponseInfo {
        let matching: Vec<Record> = records
            .iter()
            .filter(|record| {
                query.query_type() == RecordType::ANY || record.record_type() == query.query_type()
            })
            .map(|record| Record::from_rdata(query.name().clone(), record.ttl, record.data.clone()))
            .collect();

        if matching.is_empty() {
            return self
                .send_status(
                    request,
                    response_handle,
                    ResponseCode::NoError,
                    Some(ExtendedDnsError::Blocked),
                    state,
                    started,
                )
                .await;
        }

        self.send_rpz_message(
            request,
            response_handle,
            query,
            matching,
            ResponseCode::NoError,
            state,
            validating,
            started,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_rpz_message<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        query: &hickory_server::proto::op::Query,
        answers: Vec<Record>,
        response_code: ResponseCode,
        state: &ListenerQueryState,
        validating: bool,
        started: Instant,
    ) -> ResponseInfo {
        let mut message =
            hickory_server::proto::op::Message::response(request.metadata.id, OpCode::Query);
        message.add_query(query.clone());
        message.metadata.recursion_available = true;
        message.metadata.response_code = response_code;
        for record in answers {
            message.add_answer(record);
        }

        self.send_message(
            request,
            response_handle,
            message,
            Some(ExtendedDnsError::Blocked),
            state,
            validating,
            started,
        )
        .await
    }

    fn record_response(
        &self,
        request: &Request,
        response_code: ResponseCode,
        state: &ListenerQueryState,
        started: Instant,
        authentic_data: bool,
    ) {
        self.stats.record(self.protocol);
        if response_code == ResponseCode::ServFail {
            self.stats.record_servfail();
        }

        let elapsed_ms = started.elapsed().as_millis();
        if state.query_names {
            let query = request.queries.queries().first();
            tracing::debug!(
                listener = %self.listener_name,
                protocol = self.protocol.as_str(),
                src = %request.src().ip(),
                name = query.map(|query| query.name().to_string()),
                qtype = query.map(|query| query.query_type().to_string()),
                rcode = %response_code,
                elapsed_ms,
                dnssec = authentic_data,
                "query completed"
            );
        } else {
            let query = request.queries.queries().first();
            tracing::debug!(
                listener = %self.listener_name,
                protocol = self.protocol.as_str(),
                src = %request.src().ip(),
                qtype = query.map(|query| query.query_type().to_string()),
                rcode = %response_code,
                elapsed_ms,
                dnssec = authentic_data,
                "query completed"
            );
        }
    }
}

#[async_trait]
impl RequestHandler for QueryService {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let started = Instant::now();
        let state = self.snapshot();
        let inflight = self.inflight();
        let _permit = match self.admit_with(request.src().ip(), &state, inflight) {
            Ok(permit) => permit,
            Err(_) => {
                return self
                    .reject(
                        request,
                        response_handle,
                        ResponseCode::Refused,
                        &state,
                        started,
                    )
                    .await;
            }
        };

        self.handle_admitted_request::<R, T>(request, response_handle, &state, started)
            .await
    }
}

impl QueryService {
    pub async fn handle_admitted_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
        state: &ListenerQueryState,
        started: Instant,
    ) -> ResponseInfo {
        let resolver = self.resolver();
        let validating = resolver.is_validating();
        if request.queries.len() != 1 {
            return self
                .send_status(
                    request,
                    response_handle,
                    ResponseCode::FormErr,
                    None,
                    state,
                    started,
                )
                .await;
        }

        if request.metadata.op_code != OpCode::Query {
            return self
                .send_status(
                    request,
                    response_handle,
                    ResponseCode::NotImp,
                    None,
                    state,
                    started,
                )
                .await;
        }

        if request.version() != 0 {
            return self
                .send_status(
                    request,
                    response_handle,
                    ResponseCode::BADVERS,
                    None,
                    state,
                    started,
                )
                .await;
        }

        if !request.metadata.recursion_desired {
            return self
                .send_status(
                    request,
                    response_handle,
                    ResponseCode::Refused,
                    None,
                    state,
                    started,
                )
                .await;
        }

        let lower_query = &request.queries.queries()[0];
        if lower_query.query_class() != DNSClass::IN {
            return self
                .send_status(
                    request,
                    response_handle,
                    ResponseCode::Refused,
                    None,
                    state,
                    started,
                )
                .await;
        }

        if matches!(
            lower_query.query_type(),
            RecordType::AXFR | RecordType::IXFR
        ) {
            return self
                .send_status(
                    request,
                    response_handle,
                    ResponseCode::Refused,
                    None,
                    state,
                    started,
                )
                .await;
        }

        if state.refuse_any && lower_query.query_type() == RecordType::ANY {
            return self
                .send_status(
                    request,
                    response_handle,
                    ResponseCode::Refused,
                    None,
                    state,
                    started,
                )
                .await;
        }

        let dnssec_ok = request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);
        let query = lower_query.original().clone();

        if let Some(action) = state.blocklist.evaluate(lower_query.name()) {
            let extended_error = rpz_extended_dns_error(&action);
            if extended_error.is_some() {
                self.stats.record_blocked();
            }

            match action {
                crate::rpz::RpzAction::Passthru => {}
                crate::rpz::RpzAction::Nxdomain => {
                    return self
                        .send_status(
                            request,
                            response_handle,
                            ResponseCode::NXDomain,
                            extended_error,
                            state,
                            started,
                        )
                        .await;
                }
                crate::rpz::RpzAction::Nodata => {
                    return self
                        .send_status(
                            request,
                            response_handle,
                            ResponseCode::NoError,
                            extended_error,
                            state,
                            started,
                        )
                        .await;
                }
                crate::rpz::RpzAction::Drop => {
                    if self.protocol == Protocol::Doh {
                        return self
                            .send_status(
                                request,
                                response_handle,
                                ResponseCode::NoError,
                                extended_error,
                                state,
                                started,
                            )
                            .await;
                    }
                    return drop_response(request);
                }
                crate::rpz::RpzAction::TcpOnly => {
                    if self.protocol == Protocol::Udp {
                        return self
                            .send_status_truncated(
                                request,
                                response_handle,
                                ResponseCode::NoError,
                                extended_error,
                                state,
                                started,
                            )
                            .await;
                    }
                }
                crate::rpz::RpzAction::Redirect(target, ttl) => {
                    return self
                        .send_rpz_redirect(
                            request,
                            response_handle,
                            &query,
                            target.clone(),
                            ttl,
                            state,
                            validating,
                            started,
                            dnssec_ok,
                        )
                        .await;
                }
                crate::rpz::RpzAction::LocalData(records) => {
                    return self
                        .send_rpz_local_data(
                            request,
                            response_handle,
                            &query,
                            records,
                            state,
                            validating,
                            started,
                        )
                        .await;
                }
            }
        }

        match tokio::time::timeout(
            state.query_timeout,
            resolver.resolve_cached(query.clone(), dnssec_ok),
        )
        .await
        {
            Ok(Ok(resolved)) => {
                if resolved.cache_hit {
                    self.stats.record_cache_hit(1);
                }
                let extended_error = if resolved.stale {
                    Some(ExtendedDnsError::StaleAnswer)
                } else {
                    None
                };
                self.send_message(
                    request,
                    response_handle,
                    resolved.message,
                    extended_error,
                    state,
                    validating,
                    started,
                )
                .await
            }
            Ok(Err(error)) => {
                self.handle_recursor_error(
                    request,
                    response_handle,
                    error,
                    state,
                    validating,
                    started,
                )
                .await
            }
            Err(_) => {
                tracing::warn!(
                    listener = %self.listener_name,
                    timeout_ms = state.query_timeout.as_millis(),
                    "query timed out"
                );
                if let Some(message) = resolver
                    .stale_cached_response(query.clone(), dnssec_ok)
                    .await
                {
                    self.stats.record_cache_hit(1);
                    return self
                        .send_message(
                            request,
                            response_handle,
                            message,
                            Some(ExtendedDnsError::StaleAnswer),
                            state,
                            validating,
                            started,
                        )
                        .await;
                }
                self.send_status(
                    request,
                    response_handle,
                    ResponseCode::ServFail,
                    None,
                    state,
                    started,
                )
                .await
            }
        }
    }

    async fn handle_recursor_error<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        error: RecursorError,
        state: &ListenerQueryState,
        validating: bool,
        started: Instant,
    ) -> ResponseInfo {
        if let Some(negative) = negative_response(&error) {
            return self
                .send_negative(
                    request,
                    response_handle,
                    negative,
                    state,
                    validating,
                    started,
                )
                .await;
        }

        tracing::warn!(
            listener = %self.listener_name,
            error = %error,
            "recursive query failed"
        );
        self.send_status(
            request,
            response_handle,
            ResponseCode::ServFail,
            None,
            state,
            started,
        )
        .await
    }
}

struct NegativeResponse {
    response_code: ResponseCode,
    authorities: Vec<Record>,
    soa: Option<Record>,
    secure: bool,
}

fn negative_response(error: &RecursorError) -> Option<NegativeResponse> {
    match error {
        RecursorError::Negative(data) => {
            let response_code = if data.is_nx_domain() {
                ResponseCode::NXDomain
            } else {
                ResponseCode::NoError
            };
            negative_from_authority_data(data.authorities.clone(), data.soa.clone(), response_code)
        }
        RecursorError::Net(NetError::Dns(DnsError::NoRecordsFound(records))) => {
            negative_from_authority_data(
                records.authorities.clone(),
                records.soa.clone(),
                records.response_code,
            )
        }
        _ => None,
    }
}

fn negative_from_authority_data(
    authorities: Option<std::sync::Arc<[Record]>>,
    soa: Option<Box<Record<SOA>>>,
    response_code: ResponseCode,
) -> Option<NegativeResponse> {
    let authorities = authorities
        .map(|records| {
            records
                .iter()
                .filter(|record| record.record_type() != RecordType::SOA)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let soa = soa.map(|record| record.into_record_of_rdata());
    if authorities
        .iter()
        .chain(soa.iter())
        .any(|record| record.proof.is_bogus())
    {
        return None;
    }
    let secure = (!authorities.is_empty() || soa.is_some())
        && authorities.iter().all(|record| record.proof.is_secure())
        && soa.as_ref().is_none_or(|record| record.proof.is_secure());

    Some(NegativeResponse {
        response_code,
        authorities,
        soa,
        secure,
    })
}

fn bogus_record_types(records: &[Record]) -> Vec<RecordType> {
    records
        .iter()
        .filter(|record| record.proof.is_bogus())
        .map(Record::record_type)
        .collect()
}

fn message_is_bogus(message: &hickory_server::proto::op::Message) -> bool {
    message
        .answers
        .iter()
        .chain(message.authorities.iter())
        .any(|record| record.proof.is_bogus())
}

fn message_is_secure(message: &hickory_server::proto::op::Message) -> bool {
    let answers_secure = records_are_secure(&message.answers);
    let authorities_secure = records_are_secure(&message.authorities);

    (answers_secure || authorities_secure)
        && message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .all(|record| record.proof.is_secure())
}

fn records_are_secure(records: &[Record]) -> bool {
    !records.is_empty() && records.iter().all(|record| record.proof.is_secure())
}

fn response_edns(
    request: &Request,
    state: &ListenerQueryState,
    protocol: Protocol,
    extended_error: Option<ExtendedDnsError>,
) -> Option<Edns> {
    request.edns.as_ref().map(|request_edns| {
        let mut edns = request_edns.clone();
        let max_payload = edns.max_payload().max(512).min(state.max_udp_payload);
        edns.set_max_payload(max_payload);
        edns.set_version(0);
        edns.options_mut().remove(EdnsCode::Subnet);

        if matches!(protocol, Protocol::Tcp | Protocol::Dot) {
            let timeout = state
                .idle_timeout
                .as_millis()
                .div_ceil(KEEPALIVE_TIMEOUT_UNIT_MS)
                .clamp(1, u16::MAX as u128) as u16;
            edns.options_mut().remove(EdnsCode::Keepalive);
            edns.options_mut().insert(EdnsOption::Unknown(
                EdnsCode::Keepalive.into(),
                timeout.to_be_bytes().to_vec(),
            ));
        }

        if let Some(error) = extended_error {
            edns.options_mut().remove(EdnsCode::Unknown(15));
            edns.options_mut()
                .insert(EdnsOption::Unknown(15, error.encode()));
        }

        edns
    })
}

fn drop_response(request: &Request) -> ResponseInfo {
    let metadata = Metadata::response_from_request(&request.metadata);
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

fn drop_simple(header: &Header) -> ResponseInfo {
    let mut metadata = header.metadata;
    metadata.message_type = MessageType::Response;
    metadata.recursion_available = true;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}
