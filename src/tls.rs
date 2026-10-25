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
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use tokio_rustls::TlsAcceptor;

pub struct TlsState {
    cert_path: PathBuf,
    key_path: PathBuf,
    alpn: Vec<Vec<u8>>,
    current: RwLock<Arc<ServerConfig>>,
}

impl TlsState {
    pub fn load(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        Self::load_with_alpn(cert_path, key_path, vec![b"dot".to_vec()])
    }

    pub fn load_doh(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        Self::load_with_alpn(
            cert_path,
            key_path,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        )
    }

    pub fn load_with_alpn(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_path = cert_path.as_ref().to_path_buf();
        let key_path = key_path.as_ref().to_path_buf();
        let config = load_server_config(&cert_path, &key_path, alpn.clone())?;
        Ok(Self {
            cert_path,
            key_path,
            alpn,
            current: RwLock::new(config),
        })
    }

    pub fn current(&self) -> Arc<ServerConfig> {
        self.current
            .read()
            .expect("tls state lock poisoned")
            .clone()
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.current())
    }

    pub fn reload(&self) -> Result<()> {
        let config = load_server_config(&self.cert_path, &self.key_path, self.alpn.clone())?;
        *self.current.write().expect("tls state lock poisoned") = config;
        Ok(())
    }
}

pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
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

    Ok(Arc::new(config))
}
