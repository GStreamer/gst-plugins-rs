// Copyright (C) 2024, Asymptotic Inc.
//      Author: Sanchayan Maity <sanchayan@asymptotic.io>
//G
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use crate::common::*;
use futures::future;
use futures::prelude::*;
use gst::ErrorMessage;
use once_cell::sync::Lazy;
use quinn::{
    crypto::rustls::QuicClientConfig, crypto::rustls::QuicServerConfig, default_runtime,
    ClientConfig, Connection, Endpoint, EndpointConfig, MtuDiscoveryConfig, ServerConfig,
    TransportConfig,
};
use quinn_proto::{ConnectionStats, FrameStats, PathStats, UdpStats};
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::runtime;

pub const CONNECTION_CLOSE_CODE: u32 = 0;
pub const CONNECTION_CLOSE_MSG: &str = "Stopped";

#[derive(Debug)]
pub struct QuinnQuicEndpointConfig {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub client_addr: SocketAddr,
    pub secure_conn: bool,
    pub alpns: Vec<String>,
    pub certificate_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
    pub keep_alive_interval: u64,
    pub transport_config: QuinnQuicTransportConfig,
}

#[derive(Error, Debug)]
pub enum WaitError {
    #[error("Future aborted")]
    FutureAborted,
    #[error("Future returned an error: {0}")]
    FutureError(ErrorMessage),
}

pub static RUNTIME: Lazy<runtime::Runtime> = Lazy::new(|| {
    runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .thread_name("gst-quic-runtime")
        .build()
        .unwrap()
});

#[derive(Default)]
pub enum Canceller {
    #[default]
    None,
    Handle(future::AbortHandle),
    Cancelled,
}

impl Canceller {
    pub fn abort(&mut self) {
        if let Canceller::Handle(ref canceller) = *self {
            canceller.abort();
        }

        *self = Canceller::Cancelled;
    }
}

pub fn wait<F, T>(
    canceller_mutex: &Mutex<Canceller>,
    future: F,
    timeout: u32,
) -> Result<T, WaitError>
where
    F: Send + Future<Output = T>,
    T: Send + 'static,
{
    let mut canceller = canceller_mutex.lock().unwrap();
    if matches!(*canceller, Canceller::Cancelled) {
        return Err(WaitError::FutureAborted);
    } else if matches!(*canceller, Canceller::Handle(..)) {
        return Err(WaitError::FutureError(gst::error_msg!(
            gst::ResourceError::Failed,
            ["Old Canceller should not exist"]
        )));
    }
    let (abort_handle, abort_registration) = future::AbortHandle::new_pair();
    *canceller = Canceller::Handle(abort_handle);
    drop(canceller);

    let future = async {
        if timeout == 0 {
            Ok(future.await)
        } else {
            let res = tokio::time::timeout(Duration::from_secs(timeout.into()), future).await;

            match res {
                Ok(r) => Ok(r),
                Err(e) => Err(gst::error_msg!(
                    gst::ResourceError::Read,
                    ["Request timeout, elapsed: {}", e.to_string()]
                )),
            }
        }
    };

    let future = async {
        match future::Abortable::new(future, abort_registration).await {
            Ok(Ok(res)) => Ok(res),

            Ok(Err(err)) => Err(WaitError::FutureError(gst::error_msg!(
                gst::ResourceError::Failed,
                ["Future resolved with an error {:?}", err]
            ))),

            Err(future::Aborted) => Err(WaitError::FutureAborted),
        }
    };

    let res = RUNTIME.block_on(future);

    let mut canceller = canceller_mutex.lock().unwrap();
    if matches!(*canceller, Canceller::Cancelled) {
        return Err(WaitError::FutureAborted);
    }
    *canceller = Canceller::None;

    res
}

pub fn make_socket_addr(addr: &str) -> Result<SocketAddr, WaitError> {
    match addr.parse::<SocketAddr>() {
        Ok(address) => Ok(address),
        Err(e) => Err(WaitError::FutureError(gst::error_msg!(
            gst::ResourceError::Failed,
            ["Invalid address: {}", e]
        ))),
    }
}

/*
 * Following functions are taken from Quinn documentation/repository
 */
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

fn configure_client(ep_config: &QuinnQuicEndpointConfig) -> Result<ClientConfig, Box<dyn Error>> {
    let mut crypto = if ep_config.secure_conn {
        let (certs, key) = read_certs_from_file(
            ep_config.certificate_file.clone(),
            ep_config.private_key_file.clone(),
        )?;
        let mut cert_store = rustls::RootCertStore::empty();
        cert_store.add_parsable_certificates(certs.clone());

        rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(cert_store))
            .with_client_auth_cert(certs, key)?
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth()
    };

    let alpn_protocols: Vec<Vec<u8>> = ep_config
        .alpns
        .iter()
        .map(|x| x.as_bytes().to_vec())
        .collect::<Vec<_>>();
    crypto.alpn_protocols = alpn_protocols;
    crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let transport_config = {
        let mtu_config = MtuDiscoveryConfig::default()
            .upper_bound(ep_config.transport_config.upper_bound_mtu)
            .to_owned();
        let mut transport_config = TransportConfig::default();

        if ep_config.keep_alive_interval > 0 {
            transport_config
                .keep_alive_interval(Some(Duration::from_millis(ep_config.keep_alive_interval)));
        }
        transport_config.initial_mtu(ep_config.transport_config.initial_mtu);
        transport_config.min_mtu(ep_config.transport_config.min_mtu);
        transport_config.datagram_receive_buffer_size(Some(
            ep_config.transport_config.datagram_receive_buffer_size,
        ));
        transport_config
            .datagram_send_buffer_size(ep_config.transport_config.datagram_send_buffer_size);
        transport_config.max_concurrent_bidi_streams(0u32.into());
        transport_config.max_concurrent_uni_streams(1u32.into());
        transport_config.mtu_discovery_config(Some(mtu_config));

        transport_config
    };

    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?))
        .transport_config(Arc::new(transport_config))
        .to_owned();

    Ok(client_config)
}

fn read_certs_from_file(
    certificate_file: Option<PathBuf>,
    private_key_file: Option<PathBuf>,
) -> Result<
    (
        Vec<rustls_pki_types::CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn Error>,
> {
    /*
     * NOTE:
     *
     * Certificate file here should correspond to fullchain.pem where
     * fullchain.pem = cert.pem + chain.pem.
     * fullchain.pem DOES NOT include a CA's Root Certificates.
     *
     * One typically uses chain.pem (or the first certificate in it) when asked
     * for a CA bundle or CA certificate.
     *
     * One typically uses fullchain.pem when asked for the entire certificate
     * chain in a single file. For example, this is the case of modern day
     * Apache and nginx.
     */
    let cert_file = certificate_file
        .clone()
        .expect("Expected path to certificates be valid");
    let key_file = private_key_file.expect("Expected path to certificates be valid");

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = {
        let cert_file = File::open(cert_file.as_path())?;
        let mut cert_file_rdr = BufReader::new(cert_file);
        let cert_vec = rustls_pemfile::certs(&mut cert_file_rdr);
        cert_vec.into_iter().map(|c| c.unwrap()).collect()
    };

    let key: rustls_pki_types::PrivateKeyDer<'static> = {
        let key_file = File::open(key_file.as_path())?;
        let mut key_file_rdr = BufReader::new(key_file);

        let keys_iter = rustls_pemfile::read_all(&mut key_file_rdr);
        let key_item = keys_iter
            .into_iter()
            .map(|c| c.unwrap())
            .next()
            .ok_or("Certificate should have at least one private key")?;

        match key_item {
            rustls_pemfile::Item::Pkcs1Key(key) => rustls_pki_types::PrivateKeyDer::from(key),
            rustls_pemfile::Item::Pkcs8Key(key) => rustls_pki_types::PrivateKeyDer::from(key),
            _ => unimplemented!(),
        }
    };

    Ok((certs, key))
}

fn configure_server(
    ep_config: &QuinnQuicEndpointConfig,
) -> Result<(ServerConfig, Vec<rustls_pki_types::CertificateDer>), Box<dyn Error>> {
    let (certs, key) = if ep_config.secure_conn {
        read_certs_from_file(
            ep_config.certificate_file.clone(),
            ep_config.private_key_file.clone(),
        )?
    } else {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![ep_config.server_name.clone()]).unwrap();
        let priv_key = rustls_pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
        let cert_chain = vec![rustls_pki_types::CertificateDer::from(cert)];

        (cert_chain, priv_key)
    };

    let mut crypto = if ep_config.secure_conn {
        let mut cert_store = rustls::RootCertStore::empty();
        cert_store.add_parsable_certificates(certs.clone());

        let auth_client = rustls::server::WebPkiClientVerifier::builder(Arc::new(cert_store))
            .build()
            .unwrap();
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(auth_client)
            .with_single_cert(certs.clone(), key)
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
    }?;

    let alpn_protocols: Vec<Vec<u8>> = ep_config
        .alpns
        .iter()
        .map(|x| x.as_bytes().to_vec())
        .collect::<Vec<_>>();
    crypto.alpn_protocols = alpn_protocols;
    crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let transport_config = {
        let mtu_config = MtuDiscoveryConfig::default()
            .upper_bound(ep_config.transport_config.upper_bound_mtu)
            .to_owned();
        let mut transport_config = TransportConfig::default();

        transport_config.initial_mtu(ep_config.transport_config.initial_mtu);
        transport_config.min_mtu(ep_config.transport_config.min_mtu);
        transport_config.datagram_receive_buffer_size(Some(
            ep_config.transport_config.datagram_receive_buffer_size,
        ));
        transport_config
            .datagram_send_buffer_size(ep_config.transport_config.datagram_send_buffer_size);
        transport_config.max_concurrent_bidi_streams(0u32.into());
        transport_config.max_concurrent_uni_streams(1u32.into());
        transport_config.mtu_discovery_config(Some(mtu_config));

        transport_config
    };

    let server_config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?))
        .transport_config(Arc::new(transport_config))
        .to_owned();

    Ok((server_config, certs))
}

pub fn server_endpoint(ep_config: &QuinnQuicEndpointConfig) -> Result<Endpoint, Box<dyn Error>> {
    let (server_config, _) = configure_server(ep_config)?;
    let socket = std::net::UdpSocket::bind(ep_config.server_addr)?;
    let runtime = default_runtime()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "No async runtime found"))?;
    let endpoint_config = EndpointConfig::default()
        .max_udp_payload_size(ep_config.transport_config.max_udp_payload_size)
        .unwrap()
        .to_owned();
    let endpoint = Endpoint::new(endpoint_config, Some(server_config), socket, runtime)?;

    Ok(endpoint)
}

pub fn client_endpoint(ep_config: &QuinnQuicEndpointConfig) -> Result<Endpoint, Box<dyn Error>> {
    let client_cfg = configure_client(ep_config)?;
    let mut endpoint = Endpoint::client(ep_config.client_addr)?;

    endpoint.set_default_client_config(client_cfg);

    Ok(endpoint)
}

pub fn get_stats(connection: Option<Connection>) -> gst::Structure {
    match connection {
        Some(conn) => {
            // See quinn_proto::ConnectionStats
            let stats = conn.stats();
            let udp_stats = |udp: UdpStats, name: String| -> gst::Structure {
                gst::Structure::builder(name)
                    .field("datagrams", udp.datagrams)
                    .field("bytes", udp.bytes)
                    .field("ios", udp.ios)
                    .build()
            };
            let frame_stats = |frame: FrameStats, name: String| -> gst::Structure {
                gst::Structure::builder(name)
                    .field("acks", frame.acks)
                    .field("ack-frequency", frame.ack_frequency)
                    .field("crypto", frame.crypto)
                    .field("connection-close", frame.connection_close)
                    .field("data-blocked", frame.data_blocked)
                    .field("datagram", frame.datagram)
                    .field("handshake-done", frame.handshake_done)
                    .field("immediate-ack", frame.immediate_ack)
                    .field("max-data", frame.max_data)
                    .field("max-stream-data", frame.max_stream_data)
                    .field("max-streams-bidi", frame.max_streams_bidi)
                    .field("max-streams-uni", frame.max_streams_uni)
                    .field("new-connection-id", frame.new_connection_id)
                    .field("new-token", frame.new_token)
                    .field("path-challenge", frame.path_challenge)
                    .field("path-response", frame.path_response)
                    .field("ping", frame.ping)
                    .field("reset-stream", frame.reset_stream)
                    .field("retire-connection-id", frame.retire_connection_id)
                    .field("stream-data-blocked", frame.stream_data_blocked)
                    .field("streams-blocked-bidi", frame.streams_blocked_bidi)
                    .field("streams-blocked-uni", frame.streams_blocked_uni)
                    .field("stop-sending", frame.stop_sending)
                    .field("stream", frame.stream)
                    .build()
            };
            let path_stats = gst::Structure::builder("path")
                .field("cwnd", stats.path.cwnd)
                .field("congestion-events", stats.path.congestion_events)
                .field("lost-packets", stats.path.lost_packets)
                .field("lost-bytes", stats.path.lost_bytes)
                .field("sent-packets", stats.path.sent_packets)
                .field("sent-plpmtud-probes", stats.path.sent_plpmtud_probes)
                .field("lost-plpmtud-probes", stats.path.lost_plpmtud_probes)
                .field("black-holes-detected", stats.path.black_holes_detected)
                .build();

            gst::Structure::builder("stats")
                .field("udp-tx", udp_stats(stats.udp_tx, "udp-tx".to_string()))
                .field("udp-rx", udp_stats(stats.udp_rx, "udp-rx".to_string()))
                .field("path", path_stats)
                .field(
                    "frame-tx",
                    frame_stats(stats.frame_tx, "frame-tx".to_string()),
                )
                .field(
                    "frame-rx",
                    frame_stats(stats.frame_rx, "frame-rx".to_string()),
                )
                .build()
        }
        None => gst::Structure::new_empty("stats"),
    }
}
