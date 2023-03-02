use crate::utils::{gvalue_to_json, serialize_json_object};
use crate::webrtcsrc::signaller::{prelude::*, Signallable};
use crate::RUNTIME;
use anyhow::{anyhow, Error};
use async_tungstenite::tungstenite::Message as WsMessage;
use futures::channel::mpsc;
use futures::prelude::*;
use gst::glib;
use gst::glib::prelude::*;
use gst::subclass::prelude::*;
use gst_plugin_webrtc_protocol as p;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::ops::ControlFlow;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;
use tokio::{task, time::timeout};
use url::Url;

use super::CAT;

#[derive(Debug, Eq, PartialEq, Clone, Copy, glib::Enum, Default)]
#[repr(u32)]
#[enum_type(name = "GstRSWebRTCSignallerRole")]
pub enum WebRTCSignallerRole {
    #[default]
    Consumer,
    Producer,
    Listener,
}

pub struct Settings {
    uri: Url,
    producer_peer_id: Option<String>,
    cafile: Option<String>,
    role: WebRTCSignallerRole,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            uri: Url::from_str("ws://127.0.0.1:8443").unwrap(),
            producer_peer_id: None,
            cafile: Default::default(),
            role: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct Signaller {
    state: Mutex<State>,
    settings: Mutex<Settings>,
}

#[derive(Default)]
struct State {
    /// Sender for the websocket messages
    websocket_sender: Option<mpsc::Sender<p::IncomingMessage>>,
    send_task_handle: Option<task::JoinHandle<Result<(), Error>>>,
    receive_task_handle: Option<task::JoinHandle<()>>,
    producers: HashSet<String>,
}

impl Signaller {
    fn uri(&self) -> Url {
        self.settings.lock().unwrap().uri.clone()
    }

    fn set_uri(&self, uri: &str) -> Result<(), Error> {
        let mut settings = self.settings.lock().unwrap();
        let mut uri = Url::from_str(uri).map_err(|err| anyhow!("{err:?}"))?;

        if let Some(peer_id) = uri
            .query_pairs()
            .find(|(k, _)| k == "peer-id")
            .map(|v| v.1.to_string())
        {
            if !matches!(settings.role, WebRTCSignallerRole::Consumer) {
                gst::warning!(
                    CAT,
                    "Setting peer-id doesn't make sense for {:?}",
                    settings.role
                );
            } else {
                settings.producer_peer_id = Some(peer_id);
            }
        }

        if let Some(peer_id) = &settings.producer_peer_id {
            uri.query_pairs_mut()
                .clear()
                .append_pair("peer-id", peer_id);
        }

        settings.uri = uri;

        Ok(())
    }

    async fn connect(&self) -> Result<(), Error> {
        let obj = self.obj();

        let role = self.settings.lock().unwrap().role;
        if let super::WebRTCSignallerRole::Consumer = role {
            self.producer_peer_id()
                .ok_or_else(|| anyhow!("No target producer peer id set"))?;
        }

        let connector = if let Some(path) = obj.property::<Option<String>>("cafile") {
            let cert = tokio::fs::read_to_string(&path).await?;
            let cert = tokio_native_tls::native_tls::Certificate::from_pem(cert.as_bytes())?;
            let mut connector_builder = tokio_native_tls::native_tls::TlsConnector::builder();
            let connector = connector_builder.add_root_certificate(cert).build()?;
            Some(tokio_native_tls::TlsConnector::from(connector))
        } else {
            None
        };

        let mut uri = self.uri();
        uri.set_query(None);
        let (ws, _) = timeout(
            // FIXME: Make the timeout configurable
            Duration::from_secs(20),
            async_tungstenite::tokio::connect_async_with_tls_connector(uri.to_string(), connector),
        )
        .await??;

        gst::info!(CAT, imp: self, "connected");

        // Channel for asynchronously sending out websocket message
        let (mut ws_sink, mut ws_stream) = ws.split();

        // 1000 is completely arbitrary, we simply don't want infinite piling
        // up of messages as with unbounded
        let (websocket_sender, mut websocket_receiver) = mpsc::channel::<p::IncomingMessage>(1000);
        let send_task_handle =
            RUNTIME.spawn(glib::clone!(@weak-allow-none self as this => async move {
                while let Some(msg) = websocket_receiver.next().await {
                    gst::log!(CAT, "Sending websocket message {:?}", msg);
                    ws_sink
                        .send(WsMessage::Text(serde_json::to_string(&msg).unwrap()))
                        .await?;
                }

                let msg = "Done sending";
                this.map_or_else(|| gst::info!(CAT, "{msg}"),
                    |this| gst::info!(CAT, imp: this, "{msg}")
                );

                ws_sink.send(WsMessage::Close(None)).await?;
                ws_sink.close().await?;

                Ok::<(), Error>(())
            }));

        let obj = self.obj();
        let meta =
            if let Some(meta) = obj.emit_by_name::<Option<gst::Structure>>("request-meta", &[]) {
                gvalue_to_json(&meta.to_value())
            } else {
                None
            };

        let receive_task_handle =
            RUNTIME.spawn(glib::clone!(@weak-allow-none self as this => async move {
                while let Some(msg) = tokio_stream::StreamExt::next(&mut ws_stream).await {
                    if let Some(ref this) = this {
                        if let ControlFlow::Break(_) = this.handle_message(msg, &meta) {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                let msg = "Stopped websocket receiving";
                this.map_or_else(|| gst::info!(CAT, "{msg}"),
                    |this| gst::info!(CAT, imp: this, "{msg}")
                );
            }));

        let mut state = self.state.lock().unwrap();
        state.websocket_sender = Some(websocket_sender);
        state.send_task_handle = Some(send_task_handle);
        state.receive_task_handle = Some(receive_task_handle);

        Ok(())
    }

    fn set_status(&self, meta: &Option<serde_json::Value>, peer_id: &str) {
        let role = self.settings.lock().unwrap().role;
        self.send(p::IncomingMessage::SetPeerStatus(match role {
            super::WebRTCSignallerRole::Consumer => p::PeerStatus {
                meta: meta.clone(),
                peer_id: Some(peer_id.to_string()),
                roles: vec![],
            },
            super::WebRTCSignallerRole::Producer => p::PeerStatus {
                meta: meta.clone(),
                peer_id: Some(peer_id.to_string()),
                roles: vec![p::PeerRole::Producer],
            },
            super::WebRTCSignallerRole::Listener => p::PeerStatus {
                meta: meta.clone(),
                peer_id: Some(peer_id.to_string()),
                roles: vec![p::PeerRole::Listener],
            },
        }));
    }

    fn producer_peer_id(&self) -> Option<String> {
        let settings = self.settings.lock().unwrap();

        settings.producer_peer_id.clone()
    }

    fn send(&self, msg: p::IncomingMessage) {
        let state = self.state.lock().unwrap();
        if let Some(mut sender) = state.websocket_sender.clone() {
            RUNTIME.spawn(glib::clone!(@weak self as this => async move {
                if let Err(err) = sender.send(msg).await {
                    this.obj().emit_by_name::<()>("error", &[&format!("Error: {}", err)]);
                }
            }));
        }
    }

    pub fn start_session(&self) {
        let role = self.settings.lock().unwrap().role;
        if matches!(role, super::WebRTCSignallerRole::Consumer) {
            let target_producer = self.producer_peer_id().unwrap();

            self.send(p::IncomingMessage::StartSession(p::StartSessionMessage {
                peer_id: target_producer.clone(),
            }));

            gst::info!(
                CAT,
                imp: self,
                "Started session with producer peer id {target_producer}",
            );
        }
    }

    fn handle_message(
        &self,
        msg: Result<WsMessage, async_tungstenite::tungstenite::Error>,
        meta: &Option<serde_json::Value>,
    ) -> ControlFlow<()> {
        match msg {
            Ok(WsMessage::Text(msg)) => {
                gst::trace!(CAT, imp: self, "Received message {}", msg);

                if let Ok(msg) = serde_json::from_str::<p::OutgoingMessage>(&msg) {
                    match msg {
                        p::OutgoingMessage::Welcome { peer_id } => {
                            self.set_status(meta, &peer_id);
                            self.start_session();
                        }
                        p::OutgoingMessage::PeerStatusChanged(p::PeerStatus {
                            meta,
                            roles,
                            peer_id,
                        }) => {
                            let meta = meta.and_then(|m| match m {
                                serde_json::Value::Object(v) => Some(serialize_json_object(&v)),
                                _ => {
                                    gst::error!(CAT, imp: self, "Invalid json value: {m:?}");
                                    None
                                }
                            });

                            let peer_id =
                                peer_id.expect("Status changed should always contain a peer ID");
                            let mut state = self.state.lock().unwrap();
                            if roles.iter().any(|r| matches!(r, p::PeerRole::Producer)) {
                                if !state.producers.contains(&peer_id) {
                                    state.producers.insert(peer_id.clone());
                                    drop(state);

                                    self.obj()
                                        .emit_by_name::<()>("producer-added", &[&peer_id, &meta]);
                                }
                            } else if state.producers.remove(&peer_id) {
                                drop(state);

                                self.obj()
                                    .emit_by_name::<()>("producer-removed", &[&peer_id, &meta]);
                            }
                        }
                        p::OutgoingMessage::SessionStarted {
                            peer_id,
                            session_id,
                        } => {
                            self.obj()
                                .emit_by_name::<()>("session-started", &[&session_id, &peer_id]);
                        }
                        p::OutgoingMessage::StartSession {
                            session_id,
                            peer_id,
                        } => {
                            assert!(matches!(
                                self.obj().property::<WebRTCSignallerRole>("role"),
                                super::WebRTCSignallerRole::Producer
                            ));

                            self.obj()
                                .emit_by_name::<()>("session-requested", &[&session_id, &peer_id]);
                        }
                        p::OutgoingMessage::EndSession(p::EndSessionMessage { session_id }) => {
                            gst::info!(CAT, imp: self, "Session {session_id} ended");

                            self.obj()
                                .emit_by_name::<()>("session-ended", &[&session_id]);
                        }
                        p::OutgoingMessage::Peer(p::PeerMessage {
                            session_id,
                            peer_message,
                        }) => match peer_message {
                            p::PeerMessageInner::Sdp(reply) => {
                                let (sdp, desc_type) = match reply {
                                    p::SdpMessage::Answer { sdp } => {
                                        (sdp, gst_webrtc::WebRTCSDPType::Answer)
                                    }
                                    p::SdpMessage::Offer { sdp } => {
                                        (sdp, gst_webrtc::WebRTCSDPType::Offer)
                                    }
                                };
                                let sdp = match gst_sdp::SDPMessage::parse_buffer(sdp.as_bytes()) {
                                    Ok(sdp) => sdp,
                                    Err(err) => {
                                        self.obj().emit_by_name::<()>(
                                            "error",
                                            &[&format!("Error parsing SDP: {sdp} {err:?}")],
                                        );

                                        return ControlFlow::Break(());
                                    }
                                };

                                let desc =
                                    gst_webrtc::WebRTCSessionDescription::new(desc_type, sdp);
                                self.obj().emit_by_name::<()>(
                                    "session-description",
                                    &[&session_id, &desc],
                                );
                            }
                            p::PeerMessageInner::Ice {
                                candidate,
                                sdp_m_line_index,
                            } => {
                                let sdp_mid: Option<String> = None;
                                self.obj().emit_by_name::<()>(
                                    "handle-ice",
                                    &[&session_id, &sdp_m_line_index, &sdp_mid, &candidate],
                                );
                            }
                        },
                        p::OutgoingMessage::Error { details } => {
                            self.obj().emit_by_name::<()>(
                                "error",
                                &[&format!("Error message from server: {details}")],
                            );
                        }
                        _ => {
                            gst::warning!(CAT, imp: self, "Ignoring unsupported message {:?}", msg);
                        }
                    }
                } else {
                    gst::error!(CAT, imp: self, "Unknown message from server: {}", msg);

                    self.obj().emit_by_name::<()>(
                        "error",
                        &[&format!("Unknown message from server: {}", msg)],
                    );
                }
            }
            Ok(WsMessage::Close(reason)) => {
                gst::info!(CAT, imp: self, "websocket connection closed: {:?}", reason);
                return ControlFlow::Break(());
            }
            Ok(_) => (),
            Err(err) => {
                self.obj()
                    .emit_by_name::<()>("error", &[&format!("Error receiving: {}", err)]);
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }
}

#[glib::object_subclass]
impl ObjectSubclass for Signaller {
    const NAME: &'static str = "GstWebRTCSignaller";
    type Type = super::Signaller;
    type ParentType = glib::Object;
    type Interfaces = (Signallable,);
}

impl ObjectImpl for Signaller {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPS: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecString::builder("uri")
                    .flags(glib::ParamFlags::READWRITE)
                    .build(),
                glib::ParamSpecString::builder("producer-peer-id")
                    .flags(glib::ParamFlags::READWRITE)
                    .build(),
                glib::ParamSpecString::builder("cafile")
                    .flags(glib::ParamFlags::READWRITE)
                    .build(),
                glib::ParamSpecEnum::builder_with_default("role", WebRTCSignallerRole::Consumer)
                    .flags(glib::ParamFlags::READWRITE)
                    .build(),
            ]
        });

        PROPS.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "uri" => {
                if let Err(e) = self.set_uri(value.get::<&str>().expect("type checked upstream")) {
                    gst::error!(CAT, "Couldn't set URI: {e:?}");
                }
            }
            "producer-peer-id" => {
                let mut settings = self.settings.lock().unwrap();

                if !matches!(settings.role, WebRTCSignallerRole::Consumer) {
                    gst::warning!(
                        CAT,
                        "Setting `producer-peer-id` doesn't make sense for {:?}",
                        settings.role
                    );
                } else {
                    settings.producer_peer_id = value
                        .get::<Option<String>>()
                        .expect("type checked upstream");
                }
            }
            "cafile" => {
                self.settings.lock().unwrap().cafile = value
                    .get::<Option<String>>()
                    .expect("type checked upstream")
            }
            "role" => {
                self.settings.lock().unwrap().role = value
                    .get::<WebRTCSignallerRole>()
                    .expect("type checked upstream")
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        let settings = self.settings.lock().unwrap();
        match pspec.name() {
            "uri" => settings.uri.to_string().to_value(),
            "producer-peer-id" => {
                if !matches!(settings.role, WebRTCSignallerRole::Consumer) {
                    gst::warning!(
                        CAT,
                        "`producer-peer-id` doesn't make sense for {:?}",
                        settings.role
                    );
                }

                settings.producer_peer_id.to_value()
            }
            "cafile" => settings.cafile.to_value(),
            "role" => settings.role.to_value(),
            _ => unimplemented!(),
        }
    }
}

impl SignallableImpl for Signaller {
    fn start(&self) {
        gst::info!(CAT, imp: self, "Starting");
        RUNTIME.spawn(glib::clone!(@weak self as this => async move {
            if let Err(err) = this.connect().await {
                this.obj().emit_by_name::<()>("error", &[&format!("Error receiving: {}", err)]);
            }
        }));
    }

    fn stop(&self) {
        gst::info!(CAT, imp: self, "Stopping now");

        let mut state = self.state.lock().unwrap();
        let send_task_handle = state.send_task_handle.take();
        let receive_task_handle = state.receive_task_handle.take();
        if let Some(mut sender) = state.websocket_sender.take() {
            RUNTIME.block_on(async move {
                sender.close_channel();

                if let Some(handle) = send_task_handle {
                    if let Err(err) = handle.await {
                        gst::warning!(CAT, imp: self, "Error while joining send task: {}", err);
                    }
                }

                if let Some(handle) = receive_task_handle {
                    if let Err(err) = handle.await {
                        gst::warning!(CAT, imp: self, "Error while joining receive task: {}", err);
                    }
                }
            });
        }
    }

    fn send_sdp(&self, session_id: &str, sdp: &gst_webrtc::WebRTCSessionDescription) {
        gst::debug!(CAT, imp: self, "Sending SDP {sdp:#?}");

        let role = self.settings.lock().unwrap().role;
        let is_consumer = matches!(role, super::WebRTCSignallerRole::Consumer);

        let msg = p::IncomingMessage::Peer(p::PeerMessage {
            session_id: session_id.to_owned(),
            peer_message: p::PeerMessageInner::Sdp(if is_consumer {
                p::SdpMessage::Answer {
                    sdp: sdp.sdp().as_text().unwrap(),
                }
            } else {
                p::SdpMessage::Offer {
                    sdp: sdp.sdp().as_text().unwrap(),
                }
            }),
        });

        self.send(msg);
    }

    fn add_ice(
        &self,
        session_id: &str,
        candidate: &str,
        sdp_m_line_index: Option<u32>,
        _sdp_mid: Option<String>,
    ) {
        gst::debug!(
            CAT,
            imp: self,
            "Adding ice candidate {candidate:?} for {sdp_m_line_index:?} on session {session_id}"
        );

        let msg = p::IncomingMessage::Peer(p::PeerMessage {
            session_id: session_id.to_string(),
            peer_message: p::PeerMessageInner::Ice {
                candidate: candidate.to_string(),
                sdp_m_line_index: sdp_m_line_index.unwrap(),
            },
        });

        self.send(msg);
    }

    fn end_session(&self, session_id: &str) {
        gst::debug!(CAT, imp: self, "Signalling session done {}", session_id);

        let state = self.state.lock().unwrap();
        let session_id = session_id.to_string();
        if let Some(mut sender) = state.websocket_sender.clone() {
            RUNTIME.spawn(glib::clone!(@weak self as this => async move {
                if let Err(err) = sender
                    .send(p::IncomingMessage::EndSession(p::EndSessionMessage {
                        session_id,
                    }))
                    .await
                {
                    this.obj().emit_by_name::<()>("error", &[&format!("Error: {}", err)]);
                }
            }));
        }
    }
}

impl GstObjectImpl for Signaller {}
