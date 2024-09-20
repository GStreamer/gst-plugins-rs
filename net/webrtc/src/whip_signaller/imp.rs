// SPDX-License-Identifier: MPL-2.0

use crate::signaller::{Signallable, SignallableImpl};
use crate::utils::{
    build_link_header, build_reqwest_client, parse_redirect_location, set_ice_servers, wait,
    wait_async, WaitError,
};
use crate::RUNTIME;
use async_recursion::async_recursion;
use gst::glib::{self, RustClosure};
use gst::prelude::*;
use gst::subclass::prelude::*;
use gst_sdp::SDPMessage;
use gst_webrtc::{WebRTCICEGatheringState, WebRTCSessionDescription};
use once_cell::sync::Lazy;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use std::sync::Mutex;

use core::time::Duration;
use crossbeam_channel::unbounded;
use std::net::SocketAddr;
use url::Url;
use warp::{
    http,
    hyper::{
        header::{CONTENT_TYPE, LINK},
        Body,
    },
    Filter, Reply,
};

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "webrtc-whip-signaller",
        gst::DebugColorFlags::empty(),
        Some("WebRTC WHIP signaller"),
    )
});

const MAX_REDIRECTS: u8 = 10;
const DEFAULT_TIMEOUT: u32 = 15;

const ROOT: &str = "whip";
const ENDPOINT_PATH: &str = "endpoint";
const RESOURCE_PATH: &str = "resource";
const DEFAULT_HOST_ADDR: &str = "http://127.0.0.1:8080";
const DEFAULT_STUN_SERVER: Option<&str> = Some("stun://stun.l.google.com:19303");
const DEFAULT_PRODUCER_PEER_ID: Option<&str> = Some("whip-client");
const CONTENT_SDP: &str = "application/sdp";
const CONTENT_TRICKLE_ICE: &str = "application/trickle-ice-sdpfrag";

#[derive(Debug)]
enum WhipClientState {
    Stopped,
    Post { redirects: u8 },
    Running { whip_resource_url: String },
}

impl Default for WhipClientState {
    fn default() -> Self {
        Self::Stopped
    }
}

#[derive(Clone)]
struct WhipClientSettings {
    whip_endpoint: Option<String>,
    use_link_headers: bool,
    auth_token: Option<String>,
    timeout: u32,
}

impl Default for WhipClientSettings {
    fn default() -> Self {
        Self {
            whip_endpoint: None,
            use_link_headers: false,
            auth_token: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Default)]
pub struct WhipClient {
    state: Mutex<WhipClientState>,
    settings: Mutex<WhipClientSettings>,
    canceller: Mutex<Option<futures::future::AbortHandle>>,
}

impl WhipClient {
    fn raise_error(&self, msg: String) {
        self.obj()
            .emit_by_name::<()>("error", &[&format!("Error: {msg}")]);
    }

    fn handle_future_error(&self, err: WaitError) {
        match err {
            WaitError::FutureAborted => {
                gst::warning!(CAT, imp: self, "Future aborted")
            }
            WaitError::FutureError(err) => self.raise_error(err.to_string()),
        };
    }

    async fn send_offer(&self, webrtcbin: &gst::Element) {
        {
            let mut state = self.state.lock().unwrap();
            *state = WhipClientState::Post { redirects: 0 };
            drop(state);
        }

        let local_desc =
            webrtcbin.property::<Option<WebRTCSessionDescription>>("local-description");

        let offer_sdp = match local_desc {
            None => {
                self.raise_error("Local description is not set".to_string());
                return;
            }
            Some(offer) => offer,
        };

        gst::debug!(
            CAT,
            imp: self,
            "Sending offer SDP: {:?}",
            offer_sdp.sdp().as_text()
        );

        let timeout;
        let endpoint;
        {
            let settings = self.settings.lock().unwrap();
            timeout = settings.timeout;
            endpoint =
                reqwest::Url::parse(settings.whip_endpoint.as_ref().unwrap().as_str()).unwrap();
            drop(settings);
        }

        if let Err(e) = wait_async(
            &self.canceller,
            self.do_post(offer_sdp, webrtcbin, endpoint),
            timeout,
        )
        .await
        {
            self.handle_future_error(e);
        }
    }

    #[async_recursion]
    async fn do_post(
        &self,
        offer: gst_webrtc::WebRTCSessionDescription,
        webrtcbin: &gst::Element,
        endpoint: reqwest::Url,
    ) {
        let auth_token;

        {
            let settings = self.settings.lock().unwrap();
            auth_token = settings.auth_token.clone();
            drop(settings);
        }

        #[allow(unused_mut)]
        let mut redirects;

        {
            let state = self.state.lock().unwrap();
            redirects = match *state {
                WhipClientState::Post { redirects } => redirects,
                _ => {
                    self.raise_error("Trying to do POST in unexpected state".to_string());
                    return;
                }
            };
            drop(state);
        }

        // Default policy for redirect does not share the auth token to new location
        // So disable inbuilt redirecting and do a recursive call upon 3xx response code
        let pol = reqwest::redirect::Policy::none();
        let client = build_reqwest_client(pol);

        let sdp = offer.sdp();
        let body = sdp.as_text().unwrap();

        gst::debug!(CAT, imp: self, "Using endpoint {}", endpoint.as_str());
        let mut headermap = HeaderMap::new();
        headermap.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/sdp"),
        );

        if let Some(token) = auth_token.as_ref() {
            let bearer_token = "Bearer ".to_owned() + token;
            headermap.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(bearer_token.as_str())
                    .expect("Failed to set auth token to header"),
            );
        }

        let res = client
            .request(reqwest::Method::POST, endpoint.clone())
            .headers(headermap)
            .body(body)
            .send()
            .await;

        match res {
            Ok(resp) => {
                self.parse_endpoint_response(offer, resp, redirects, webrtcbin)
                    .await
            }
            Err(err) => self.raise_error(err.to_string()),
        }
    }

    async fn parse_endpoint_response(
        &self,
        offer: gst_webrtc::WebRTCSessionDescription,
        resp: reqwest::Response,
        redirects: u8,
        webrtcbin: &gst::Element,
    ) {
        gst::debug!(CAT, imp: self, "Parsing endpoint response");

        let endpoint;
        let use_link_headers;

        {
            let settings = self.settings.lock().unwrap();
            endpoint =
                reqwest::Url::parse(settings.whip_endpoint.as_ref().unwrap().as_str()).unwrap();
            use_link_headers = settings.use_link_headers;
            drop(settings);
        }

        gst::debug!(CAT, "response status: {}", resp.status());

        match resp.status() {
            StatusCode::OK | StatusCode::CREATED => {
                if use_link_headers {
                    if let Err(e) = set_ice_servers(webrtcbin, resp.headers()) {
                        self.raise_error(e.to_string());
                        return;
                    };
                }

                // Get the url of the resource from 'location' header.
                // The resource created is expected be a relative path
                // and not an absolute path
                // So we want to construct the full url of the resource
                // using the endpoint url i.e., replace the end point path with
                // resource path
                let location = match resp.headers().get(reqwest::header::LOCATION) {
                    Some(location) => location,
                    None => {
                        self.raise_error(
                            "Location header field should be present for WHIP resource URL"
                                .to_string(),
                        );
                        return;
                    }
                };

                let location = match location.to_str() {
                    Ok(loc) => loc,
                    Err(e) => {
                        self.raise_error(format!("Failed to convert location to string: {e}"));
                        return;
                    }
                };

                let url = reqwest::Url::parse(endpoint.as_str()).unwrap();

                gst::debug!(CAT, imp: self, "WHIP resource: {:?}", location);

                let url = match url.join(location) {
                    Ok(joined_url) => joined_url,
                    Err(err) => {
                        self.raise_error(format!("URL join operation failed: {err:?}"));
                        return;
                    }
                };

                {
                    let mut state = self.state.lock().unwrap();
                    *state = match *state {
                        WhipClientState::Post { redirects: _r } => WhipClientState::Running {
                            whip_resource_url: url.to_string(),
                        },
                        _ => {
                            self.raise_error("Expected to be in POST state".to_string());
                            return;
                        }
                    };
                    drop(state);
                }

                match resp.bytes().await {
                    Ok(ans_bytes) => match gst_sdp::SDPMessage::parse_buffer(&ans_bytes) {
                        Ok(ans_sdp) => {
                            let answer = gst_webrtc::WebRTCSessionDescription::new(
                                gst_webrtc::WebRTCSDPType::Answer,
                                ans_sdp,
                            );
                            self.obj()
                                .emit_by_name::<()>("session-description", &[&"unique", &answer]);
                        }
                        Err(err) => {
                            self.raise_error(format!("Could not parse answer SDP: {err}"));
                        }
                    },
                    Err(err) => self.raise_error(err.to_string()),
                }
            }

            s if s.is_redirection() => {
                gst::debug!(CAT, "redirected");

                if redirects < MAX_REDIRECTS {
                    match parse_redirect_location(resp.headers(), &endpoint) {
                        Ok(redirect_url) => {
                            {
                                let mut state = self.state.lock().unwrap();
                                *state = match *state {
                                    WhipClientState::Post { redirects: _r } => {
                                        WhipClientState::Post {
                                            redirects: redirects + 1,
                                        }
                                    }
                                    /*
                                     * As per section 4.6 of the specification, redirection is
                                     * not required to be supported for the PATCH and DELETE
                                     * requests to the final WHEP resource URL. Only the initial
                                     * POST request may support redirection.
                                     */
                                    WhipClientState::Running { .. } => {
                                        self.raise_error(
                                            "Unexpected redirection in RUNNING state".to_string(),
                                        );
                                        return;
                                    }
                                    WhipClientState::Stopped => unreachable!(),
                                };
                                drop(state);
                            }

                            gst::debug!(
                                CAT,
                                imp: self,
                                "Redirecting endpoint to {}",
                                redirect_url.as_str()
                            );

                            self.do_post(offer, webrtcbin, redirect_url).await
                        }
                        Err(e) => self.raise_error(e.to_string()),
                    }
                } else {
                    self.raise_error("Too many redirects. Unable to connect.".to_string());
                }
            }

            s => {
                match resp.bytes().await {
                    Ok(r) => {
                        let res = r.escape_ascii().to_string();

                        // FIXME: Check and handle 'Retry-After' header in case of server error
                        self.raise_error(format!("Unexpected response: {} - {}", s.as_str(), res));
                    }
                    Err(err) => self.raise_error(err.to_string()),
                }
            }
        }
    }

    fn terminate_session(&self) {
        let settings = self.settings.lock().unwrap();
        let state = self.state.lock().unwrap();
        let timeout = settings.timeout;

        let resource_url = match *state {
            WhipClientState::Running {
                whip_resource_url: ref resource_url,
            } => resource_url.clone(),
            _ => {
                self.raise_error("Terminated in unexpected state".to_string());
                return;
            }
        };

        drop(state);

        let mut headermap = HeaderMap::new();
        if let Some(token) = &settings.auth_token {
            let bearer_token = "Bearer ".to_owned() + token.as_str();
            headermap.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(bearer_token.as_str())
                    .expect("Failed to set auth token to header"),
            );
        }

        gst::debug!(CAT, imp: self, "DELETE request on {}", resource_url);
        let client = build_reqwest_client(reqwest::redirect::Policy::default());
        let future = async {
            client
                .delete(resource_url.clone())
                .headers(headermap)
                .send()
                .await
                .map_err(|err| {
                    gst::error_msg!(
                        gst::ResourceError::Failed,
                        ["DELETE request failed {}: {:?}", resource_url, err]
                    )
                })
        };

        let res = wait(&self.canceller, future, timeout);
        match res {
            Ok(r) => {
                gst::debug!(CAT, imp: self, "Response to DELETE : {}", r.status());
            }
            Err(e) => match e {
                WaitError::FutureAborted => {
                    gst::warning!(CAT, imp: self, "DELETE request aborted")
                }
                WaitError::FutureError(e) => {
                    gst::error!(CAT, imp: self, "Error on DELETE request : {}", e)
                }
            },
        };
    }
}

impl SignallableImpl for WhipClient {
    fn start(&self) {
        if self.settings.lock().unwrap().whip_endpoint.is_none() {
            self.raise_error("WHIP endpoint URL must be set".to_string());
            return;
        }

        self.obj().connect_closure(
            "webrtcbin-ready",
            false,
            glib::closure!(|signaller: &super::WhipClientSignaller,
                            _consumer_identifier: &str,
                            webrtcbin: &gst::Element| {
                let obj_weak = signaller.downgrade();
                webrtcbin.connect_notify(Some("ice-gathering-state"), move |webrtcbin, _pspec| {
                    let Some(obj) = obj_weak.upgrade() else {
                        return;
                    };

                    let state =
                        webrtcbin.property::<WebRTCICEGatheringState>("ice-gathering-state");

                    match state {
                        WebRTCICEGatheringState::Gathering => {
                            gst::info!(CAT, obj: obj, "ICE gathering started");
                        }
                        WebRTCICEGatheringState::Complete => {
                            gst::info!(CAT, obj: obj, "ICE gathering complete");

                            let webrtcbin = webrtcbin.clone();

                            RUNTIME.spawn(async move {
                                /* Note that we check for a valid WHIP endpoint in change_state */
                                obj.imp().send_offer(&webrtcbin).await
                            });
                        }
                        _ => (),
                    }
                });
            }),
        );

        self.obj().emit_by_name::<()>(
            "session-requested",
            &[
                &"unique",
                &"unique",
                &None::<gst_webrtc::WebRTCSessionDescription>,
            ],
        );
    }

    fn stop(&self) {
        // Interrupt requests in progress, if any
        if let Some(canceller) = &*self.canceller.lock().unwrap() {
            canceller.abort();
        }

        let state = self.state.lock().unwrap();
        if let WhipClientState::Running { .. } = *state {
            // Release server-side resources
            drop(state);
        }
    }

    fn end_session(&self, session_id: &str) {
        assert_eq!(session_id, "unique");

        // Interrupt requests in progress, if any
        if let Some(canceller) = &*self.canceller.lock().unwrap() {
            canceller.abort();
        }

        let state = self.state.lock().unwrap();
        if let WhipClientState::Running { .. } = *state {
            // Release server-side resources
            drop(state);
            self.terminate_session();
        }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for WhipClient {
    const NAME: &'static str = "GstWhipClientSignaller";
    type Type = super::WhipClientSignaller;
    type ParentType = glib::Object;
    type Interfaces = (Signallable,);
}

impl ObjectImpl for WhipClient {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![glib::ParamSpecString::builder("whip-endpoint")
                    .nick("WHIP Endpoint")
                    .blurb("The WHIP server endpoint to POST SDP offer to.
                        e.g.: https://example.com/whip/endpoint/room1234")
                    .mutable_ready()
                    .build(),

                glib::ParamSpecBoolean::builder("use-link-headers")
                    .nick("Use Link Headers")
                    .blurb("Use link headers to configure ice-servers from the WHIP server response to the POST request.
                        If set to TRUE and the WHIP server returns valid ice-servers,
                        this property overrides the ice-servers values set using the stun-server and turn-server properties.")
                    .mutable_ready()
                    .build(),

                glib::ParamSpecString::builder("auth-token")
                    .nick("Authorization Token")
                    .blurb("Authentication token to use, will be sent in the HTTP Header as 'Bearer <auth-token>'")
                    .mutable_ready()
                    .build(),

                glib::ParamSpecUInt::builder("timeout")
                    .nick("Timeout")
                    .blurb("Value in seconds to timeout WHIP endpoint requests (0 = No timeout).")
                    .maximum(3600)
                    .default_value(DEFAULT_TIMEOUT)
                    .build(),
            ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "whip-endpoint" => {
                let mut settings = self.settings.lock().unwrap();
                settings.whip_endpoint = value.get().unwrap();
            }
            "use-link-headers" => {
                let mut settings = self.settings.lock().unwrap();
                settings.use_link_headers = value.get().unwrap();
            }
            "auth-token" => {
                let mut settings = self.settings.lock().unwrap();
                settings.auth_token = value.get().unwrap();
            }
            "timeout" => {
                let mut settings = self.settings.lock().unwrap();
                settings.timeout = value.get().unwrap();
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        match pspec.name() {
            "whip-endpoint" => {
                let settings = self.settings.lock().unwrap();
                settings.whip_endpoint.to_value()
            }
            "use-link-headers" => {
                let settings = self.settings.lock().unwrap();
                settings.use_link_headers.to_value()
            }
            "auth-token" => {
                let settings = self.settings.lock().unwrap();
                settings.auth_token.to_value()
            }
            "timeout" => {
                let settings = self.settings.lock().unwrap();
                settings.timeout.to_value()
            }
            _ => unimplemented!(),
        }
    }
}

// WHIP server implementation

#[derive(Debug)]
enum WhipServerState {
    Idle,
    Negotiating,
    Ready,
}

impl Default for WhipServerState {
    fn default() -> Self {
        Self::Idle
    }
}

struct WhipServerSettings {
    stun_server: Option<String>,
    turn_servers: gst::Array,
    host_addr: Url,
    producer_peer_id: Option<String>,
    timeout: u32,
    shutdown_signal: Option<tokio::sync::oneshot::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
    sdp_answer: Option<crossbeam_channel::Sender<Option<SDPMessage>>>,
}

impl Default for WhipServerSettings {
    fn default() -> Self {
        Self {
            host_addr: Url::parse(DEFAULT_HOST_ADDR).unwrap(),
            stun_server: DEFAULT_STUN_SERVER.map(String::from),
            turn_servers: gst::Array::new(Vec::new() as Vec<glib::SendValue>),
            producer_peer_id: DEFAULT_PRODUCER_PEER_ID.map(String::from),
            timeout: DEFAULT_TIMEOUT,
            shutdown_signal: None,
            server_handle: None,
            sdp_answer: None,
        }
    }
}

pub struct WhipServer {
    state: Mutex<WhipServerState>,
    settings: Mutex<WhipServerSettings>,
}

impl Default for WhipServer {
    fn default() -> Self {
        Self {
            settings: Mutex::new(WhipServerSettings::default()),
            state: Mutex::new(WhipServerState::default()),
        }
    }
}

impl WhipServer {
    pub fn on_webrtcbin_ready(&self) -> RustClosure {
        glib::closure!(|signaller: &super::WhipServerSignaller,
                        _producer_identifier: &str,
                        webrtcbin: &gst::Element| {
            let obj_weak = signaller.downgrade();
            webrtcbin.connect_notify(Some("ice-gathering-state"), move |webrtcbin, _pspec| {
                let obj = match obj_weak.upgrade() {
                    Some(obj) => obj,
                    None => return,
                };

                let state = webrtcbin.property::<WebRTCICEGatheringState>("ice-gathering-state");

                match state {
                    WebRTCICEGatheringState::Gathering => {
                        gst::info!(CAT, obj: obj, "ICE gathering started");
                    }
                    WebRTCICEGatheringState::Complete => {
                        gst::info!(CAT, obj: obj, "ICE gathering complete");
                        let ans: Option<gst_sdp::SDPMessage>;
                        let settings = obj.imp().settings.lock().unwrap();
                        if let Some(answer_sdp) = webrtcbin
                            .property::<Option<WebRTCSessionDescription>>("local-description")
                        {
                            ans = Some(answer_sdp.sdp());
                        } else {
                            ans = None;
                        }
                        if let Some(tx) = &settings.sdp_answer {
                            tx.send(ans).unwrap()
                        }
                    }
                    _ => (),
                }
            });
        })
    }

    async fn patch_handler(&self, _id: String) -> Result<impl warp::Reply, warp::Rejection> {
        // FIXME: implement ICE Trickle and ICE restart
        // emit signal `handle-ice` to for ICE trickle
        let reply = warp::reply::reply();
        let res = warp::reply::with_status(reply, http::StatusCode::NOT_IMPLEMENTED);
        Ok(res.into_response())

        //FIXME: add state checking once ICE trickle is implemented
    }

    async fn delete_handler(&self, _id: String) -> Result<impl warp::Reply, warp::Rejection> {
        let mut state = self.state.lock().unwrap();
        match *state {
            WhipServerState::Ready => {
                // FIXME: session-ended will make webrtcsrc send EOS
                // and producer-removed is not handled
                // Need to address the usecase where when the client terminates
                // the webrtcsrc should be running without sending EOS and reset
                // for next client connection like a usual server

                self.obj().emit_by_name::<bool>("session-ended", &[&ROOT]);

                gst::info!(CAT, imp:self, "Ending session");
                *state = WhipServerState::Idle;
                Ok(warp::reply::reply().into_response())
            }
            _ => {
                gst::error!(CAT, imp: self, "DELETE requested in {state:?} state. Can't Proceed");
                let res = http::Response::builder()
                    .status(http::StatusCode::CONFLICT)
                    .body(Body::from(String::from("Session not Ready")))
                    .unwrap();
                Ok(res)
            }
        }
    }

    async fn options_handler(&self) -> Result<impl warp::Reply, warp::Rejection> {
        let settings = self.settings.lock().unwrap();
        let peer_id = settings.producer_peer_id.clone().unwrap();
        drop(settings);

        let mut state = self.state.lock().unwrap();
        match *state {
            WhipServerState::Idle => {
                self.obj()
                    .emit_by_name::<()>("session-started", &[&ROOT, &peer_id]);
                *state = WhipServerState::Negotiating
            }
            WhipServerState::Ready => {
                gst::error!(CAT, imp: self, "OPTIONS requested in {state:?} state. Can't proceed");
                let res = http::Response::builder()
                    .status(http::StatusCode::CONFLICT)
                    .body(Body::from(String::from("Session active already")))
                    .unwrap();
                return Ok(res);
            }
            _ => {}
        };
        drop(state);

        let mut links = HeaderMap::new();
        let settings = self.settings.lock().unwrap();
        match &settings.stun_server {
            Some(stun) => match build_link_header(stun.as_str()) {
                Ok(stun_link) => {
                    links.append(LINK, HeaderValue::from_str(stun_link.as_str()).unwrap());
                }
                Err(e) => {
                    gst::error!(CAT, imp: self, "Failed to parse {stun:?} : {e:?}");
                }
            },
            None => {}
        }

        if !settings.turn_servers.is_empty() {
            for turn_server in settings.turn_servers.iter() {
                if let Ok(turn) = turn_server.get::<String>() {
                    gst::debug!(CAT, imp: self, "turn server: {}",turn.as_str());
                    match build_link_header(turn.as_str()) {
                        Ok(turn_link) => {
                            links.append(LINK, HeaderValue::from_str(turn_link.as_str()).unwrap());
                        }
                        Err(e) => {
                            gst::error!(CAT, imp: self, "Failed to parse {turn_server:?} : {e:?}");
                        }
                    }
                } else {
                    gst::debug!(CAT, imp: self, "Failed to get String value of {turn_server:?}");
                }
            }
        }

        let mut res = http::Response::builder()
            .header("Access-Post", "application/sdp")
            .body(Body::empty())
            .unwrap();

        let headers = res.headers_mut();
        headers.extend(links);

        Ok(res)
    }

    async fn post_handler(
        &self,
        body: warp::hyper::body::Bytes,
    ) -> Result<http::Response<warp::hyper::Body>, warp::Rejection> {
        let mut settings = self.settings.lock().unwrap();
        let peer_id = settings.producer_peer_id.clone().unwrap();
        let wait_timeout = settings.timeout;
        let (tx, rx) = unbounded::<Option<SDPMessage>>();
        settings.sdp_answer = Some(tx);
        drop(settings);

        let mut state = self.state.lock().unwrap();
        match *state {
            WhipServerState::Idle => {
                self.obj()
                    .emit_by_name::<()>("session-started", &[&ROOT, &peer_id]);
                *state = WhipServerState::Negotiating
            }
            WhipServerState::Ready => {
                gst::error!(CAT, imp: self, "POST requested in {state:?} state. Can't Proceed");
                let res = http::Response::builder()
                    .status(http::StatusCode::CONFLICT)
                    .body(Body::from(String::from("Session active already")))
                    .unwrap();
                return Ok(res);
            }
            _ => {}
        };
        drop(state);

        match gst_sdp::SDPMessage::parse_buffer(body.as_ref()) {
            Ok(offer_sdp) => {
                let offer = gst_webrtc::WebRTCSessionDescription::new(
                    gst_webrtc::WebRTCSDPType::Offer,
                    offer_sdp,
                );

                self.obj()
                    .emit_by_name::<()>("session-description", &[&"unique", &offer]);
            }
            Err(err) => {
                gst::error!(CAT, imp: self, "Could not parse offer SDP: {err}");
                let reply = warp::reply::reply();
                let res = warp::reply::with_status(reply, http::StatusCode::NOT_ACCEPTABLE);
                return Ok(res.into_response());
            }
        }

        // We don't want to wait infinitely for the ice gathering to complete.
        let answer = match rx.recv_timeout(Duration::from_secs(wait_timeout as u64)) {
            Ok(a) => a,
            Err(e) => {
                let reply = warp::reply::reply();
                let res;
                if e.is_timeout() {
                    res = warp::reply::with_status(reply, http::StatusCode::REQUEST_TIMEOUT);
                    gst::error!(CAT, imp: self, "Timedout waiting for SDP answer");
                } else {
                    res = warp::reply::with_status(reply, http::StatusCode::INTERNAL_SERVER_ERROR);
                    gst::error!(CAT, imp: self, "Channel got disconnected");
                }
                return Ok(res.into_response());
            }
        };

        let settings = self.settings.lock().unwrap();
        let mut links = HeaderMap::new();

        match &settings.stun_server {
            Some(stun) => match build_link_header(stun.as_str()) {
                Ok(stun_link) => {
                    links.append(LINK, HeaderValue::from_str(stun_link.as_str()).unwrap());
                }
                Err(e) => {
                    gst::error!(CAT, imp: self, "Failed to parse {stun:?} : {e:?}");
                }
            },
            None => {}
        }

        if !settings.turn_servers.is_empty() {
            for turn_server in settings.turn_servers.iter() {
                if let Ok(turn) = turn_server.get::<String>() {
                    gst::debug!(CAT, imp: self, "turn server: {}",turn.as_str());
                    match build_link_header(turn.as_str()) {
                        Ok(turn_link) => {
                            links.append(LINK, HeaderValue::from_str(turn_link.as_str()).unwrap());
                        }
                        Err(e) => {
                            gst::error!(CAT, imp: self, "Failed to  parse {turn_server:?} : {e:?}");
                        }
                    }
                } else {
                    gst::error!(CAT, imp: self, "Failed to get String value of {turn_server:?}");
                }
            }
        }

        // Note: including the ETag in the original "201 Created" response is only REQUIRED
        // if the WHIP resource supports ICE restarts and OPTIONAL otherwise.

        let ans_text: Result<String, String>;
        if let Some(sdp) = answer {
            match sdp.as_text() {
                Ok(text) => {
                    ans_text = Ok(text);
                    gst::debug!(CAT, imp: self, "{ans_text:?}");
                }
                Err(e) => {
                    ans_text = Err(format!("Failed to get SDP answer: {e:?}"));
                    gst::error!(CAT, imp: self, "{e:?}");
                }
            }
        } else {
            let e = "SDP Answer is empty!".to_string();
            gst::error!(CAT, imp: self, "{e:?}");
            ans_text = Err(e);
        }

        // If ans_text is an error. Send error code and error string in the response
        if let Err(e) = ans_text {
            let res = http::Response::builder()
                .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(e))
                .unwrap();
            return Ok(res);
        }

        drop(settings);

        // Got SDP answer, send answer in the response
        let resource_url = "/".to_owned() + ROOT + "/" + RESOURCE_PATH + "/" + &peer_id;
        let mut res = http::Response::builder()
            .status(StatusCode::CREATED)
            .header(CONTENT_TYPE, "application/sdp")
            .header("location", resource_url)
            .body(Body::from(ans_text.unwrap()))
            .unwrap();

        let headers = res.headers_mut();
        headers.extend(links);

        let mut state = self.state.lock().unwrap();
        *state = WhipServerState::Ready;
        drop(state);

        Ok(res)
    }

    fn serve(&self) -> Option<tokio::task::JoinHandle<()>> {
        let mut settings = self.settings.lock().unwrap();
        let addr: SocketAddr;
        match settings.host_addr.socket_addrs(|| None) {
            Ok(v) => {
                // pick the first vector item
                addr = v[0];
                gst::info!(CAT, imp:self, "using {addr:?} as address");
            }
            Err(e) => {
                gst::error!(CAT, imp:self, "error getting addr from uri  {e:?}");
                self.obj()
                    .emit_by_name::<()>("error", &[&format!("Unable to start WHIP Server: {e:?}")]);
                return None;
            }
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        settings.shutdown_signal = Some(tx);
        drop(settings);

        let prefix = warp::path(ROOT);

        let self_weak = self.downgrade();

        // POST /endpoint
        let post_filter = warp::post()
            .and(warp::path(ENDPOINT_PATH))
            .and(warp::path::end())
            .and(warp::header::exact(CONTENT_TYPE.as_str(), CONTENT_SDP))
            .and(warp::body::bytes())
            .and_then(move |body| {
                let s = self_weak.upgrade();
                async {
                    let self_ = s.expect("Need to have the ObjectRef");
                    self_.post_handler(body).await
                }
            });

        let self_weak = self.downgrade();

        // OPTIONS /endpoint
        let options_filter = warp::options()
            .and(warp::path(ENDPOINT_PATH))
            .and(warp::path::end())
            .and_then(move || {
                let s = self_weak.upgrade();
                async {
                    let self_ = s.expect("Need to have the ObjectRef");
                    self_.options_handler().await
                }
            });

        let self_weak = self.downgrade();

        // PATCH /resource/:id
        let patch_filter = warp::patch()
            .and(warp::path(RESOURCE_PATH))
            .and(warp::path::param::<String>())
            .and(warp::path::end())
            .and(warp::header::exact(
                CONTENT_TYPE.as_str(),
                CONTENT_TRICKLE_ICE,
            ))
            .and_then(move |id| {
                let s = self_weak.upgrade();
                async {
                    let self_ = s.expect("Need to have the ObjectRef");
                    self_.patch_handler(id).await
                }
            });

        let self_weak = self.downgrade();

        // DELETE /resource/:id
        let delete_filter = warp::delete()
            .and(warp::path(RESOURCE_PATH))
            .and(warp::path::param::<String>())
            .and(warp::path::end())
            .and_then(move |id| {
                let s = self_weak.upgrade();
                async {
                    let self_ = s.expect("Need to have the ObjectRef");
                    self_.delete_handler(id).await
                }
            });

        let api = prefix
            .and(post_filter)
            .or(prefix.and(options_filter))
            .or(prefix.and(patch_filter))
            .or(prefix.and(delete_filter));

        let s = warp::serve(api);
        let jh = RUNTIME.spawn(async move {
            let (_, server) = s.bind_with_graceful_shutdown(addr, async move {
                match rx.await {
                    Ok(_) => gst::debug!(CAT, "Server shut down signal received"),
                    Err(e) => gst::error!(CAT, "{e:?}: Sender dropped"),
                }
            });

            server.await;
            gst::debug!(CAT, "Stopped the server task...");
        });

        gst::debug!(CAT, imp: self, "Started the server...");
        Some(jh)
    }

    fn set_host_addr(&self, host_addr: &str) -> Result<(), url::ParseError> {
        let mut settings = self.settings.lock().unwrap();
        settings.host_addr = Url::parse(host_addr)?;
        Ok(())
    }
}

impl SignallableImpl for WhipServer {
    fn start(&self) {
        gst::info!(CAT, imp: self, "starting the WHIP server");
        let jh = self.serve();
        let mut settings = self.settings.lock().unwrap();
        settings.server_handle = jh;
    }

    fn stop(&self) {
        let mut settings = self.settings.lock().unwrap();

        let handle = settings
            .server_handle
            .take()
            .expect("Server handle should be set");

        let tx = settings
            .shutdown_signal
            .take()
            .expect("Shutdown signal Sender needs to be valid");

        if tx.send(()).is_err() {
            gst::error!(CAT, imp: self, "Failed to send shutdown signal. Receiver dropped");
        }

        gst::debug!(CAT, imp: self, "Await server handle to join");
        RUNTIME.block_on(async {
            if let Err(e) = handle.await {
                gst::error!(CAT, imp:self, "Failed to join server handle: {e:?}");
            };
        });

        gst::info!(CAT, imp: self, "stopped the WHIP server");
    }

    fn end_session(&self, _session_id: &str) {
        //FIXME: send any events to the client
    }
}

#[glib::object_subclass]
impl ObjectSubclass for WhipServer {
    const NAME: &'static str = "GstWhipServerSignaller";
    type Type = super::WhipServerSignaller;
    type ParentType = glib::Object;
    type Interfaces = (Signallable,);
}

impl ObjectImpl for WhipServer {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecString::builder("host-addr")
                    .nick("Host address")
                    .blurb("The the host address of the WHIP endpoint e.g., http://127.0.0.1:8080")
                    .default_value(DEFAULT_HOST_ADDR)
                    .flags(glib::ParamFlags::READWRITE)
                    .build(),
                // needed by webrtcsrc in handle_webrtc_src_pad
                glib::ParamSpecString::builder("producer-peer-id")
                    .default_value(DEFAULT_PRODUCER_PEER_ID)
                    .flags(glib::ParamFlags::READABLE)
                    .build(),
                glib::ParamSpecString::builder("stun-server")
                    .nick("STUN Server")
                    .blurb("The STUN server of the form stun://hostname:port")
                    .default_value(DEFAULT_STUN_SERVER)
                    .build(),
                gst::ParamSpecArray::builder("turn-servers")
                    .nick("List of TURN Servers to use")
                    .blurb("The TURN servers of the form <\"turn(s)://username:password@host:port\", \"turn(s)://username1:password1@host1:port1\">")
                    .element_spec(&glib::ParamSpecString::builder("turn-server")
                        .nick("TURN Server")
                        .blurb("The TURN server of the form turn(s)://username:password@host:port.")
                        .build()
                    )
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt::builder("timeout")
                    .nick("Timeout")
                    .blurb("Value in seconds to timeout WHIP endpoint requests (0 = No timeout).")
                    .maximum(3600)
                    .default_value(DEFAULT_TIMEOUT)
                    .build(),
            ]
        });
        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "host-addr" => {
                if let Err(e) =
                    self.set_host_addr(value.get::<&str>().expect("type checked upstream"))
                {
                    gst::error!(CAT, "Couldn't set the host address as {e:?}, fallback to the default value {DEFAULT_HOST_ADDR:?}");
                }
            }
            "stun-server" => {
                let mut settings = self.settings.lock().unwrap();
                settings.stun_server = value
                    .get::<Option<String>>()
                    .expect("type checked upstream")
            }
            "turn-servers" => {
                let mut settings = self.settings.lock().unwrap();
                settings.turn_servers = value.get::<gst::Array>().expect("type checked upstream")
            }
            "timeout" => {
                let mut settings = self.settings.lock().unwrap();
                settings.timeout = value.get().unwrap();
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        let settings = self.settings.lock().unwrap();
        match pspec.name() {
            "host-addr" => settings.host_addr.to_string().to_value(),
            "stun-server" => settings.stun_server.to_value(),
            "turn-servers" => settings.turn_servers.to_value(),
            "producer-peer-id" => settings.producer_peer_id.to_value(),
            "timeout" => settings.timeout.to_value(),
            _ => unimplemented!(),
        }
    }
}
