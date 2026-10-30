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
use std::path::Path;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use tokio_rustls::TlsAcceptor;

use crate::config::Protocol;

pub fn install_crypto_provider() {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider was already installed");
    }
}

pub fn alpn_for_protocol(protocol: Protocol) -> Vec<Vec<u8>> {
    match protocol {
        Protocol::Dot => vec![b"dot".to_vec()],
        Protocol::Doh => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        Protocol::Udp | Protocol::Tcp => Vec::new(),
    }
}

pub struct TlsState {
    acceptor: TlsAcceptor,
}

impl TlsState {
    pub fn load(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        protocol: Protocol,
    ) -> Result<Self> {
        Self::load_with_alpn(cert_path, key_path, alpn_for_protocol(protocol))
    }

    pub fn load_with_alpn(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let config = load_server_config(cert_path.as_ref(), key_path.as_ref(), alpn)?;
        Ok(Self {
            acceptor: TlsAcceptor::from(config),
        })
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.clone()
    }
}

pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
    alpn: Vec<Vec<u8>>,
) -> Result<std::sync::Arc<ServerConfig>> {
    use rustls::pki_types::CertificateDer;

    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("failed to open certificate {}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificate {}", cert_path.display()))?;

    if cert_chain.is_empty() {
        anyhow::bail!(
            "certificate {} contains no certificates",
            cert_path.display()
        );
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("failed to read private key {}", key_path.display()))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .with_context(|| {
            format!(
                "failed to build TLS configuration from {} and {}",
                cert_path.display(),
                key_path.display()
            )
        })?;

    config.alpn_protocols = alpn;

    Ok(std::sync::Arc::new(config))
}
