// SPDX-License-Identifier: MPL-2.0

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant, SystemTime};

use futures::future::{AbortHandle, Abortable};
use futures::StreamExt;
use gst::{glib, prelude::*, subclass::prelude::*};
use once_cell::sync::Lazy;

use super::session::{
    RecvReply, RtcpRecvReply, RtpProfile, SendReply, Session, RTCP_MIN_REPORT_INTERVAL,
};
use super::source::{ReceivedRb, SourceState};

use crate::rtpbin2::RUNTIME;

const DEFAULT_LATENCY: gst::ClockTime = gst::ClockTime::from_mseconds(0);
const DEFAULT_MIN_RTCP_INTERVAL: Duration = RTCP_MIN_REPORT_INTERVAL;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "rtpbin2",
        gst::DebugColorFlags::empty(),
        Some("RTP management bin"),
    )
});

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, glib::Enum)]
#[repr(u32)]
#[enum_type(name = "GstRtpBin2Profile")]
enum Profile {
    #[default]
    #[enum_value(name = "AVP profile as specified in RFC 3550", nick = "avp")]
    Avp,
    #[enum_value(name = "AVPF profile as specified in RFC 4585", nick = "avpf")]
    Avpf,
}

impl From<RtpProfile> for Profile {
    fn from(value: RtpProfile) -> Self {
        match value {
            RtpProfile::Avp => Self::Avp,
            RtpProfile::Avpf => Self::Avpf,
        }
    }
}

impl From<Profile> for RtpProfile {
    fn from(value: Profile) -> Self {
        match value {
            Profile::Avp => Self::Avp,
            Profile::Avpf => Self::Avpf,
        }
    }
}

#[derive(Debug, Clone)]
struct Settings {
    latency: gst::ClockTime,
    min_rtcp_interval: Duration,
    profile: Profile,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            latency: DEFAULT_LATENCY,
            min_rtcp_interval: DEFAULT_MIN_RTCP_INTERVAL,
            profile: Profile::default(),
        }
    }
}

#[derive(Debug)]
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct RtcpSendStream {
    state: Arc<Mutex<State>>,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl RtcpSendStream {
    fn new(state: Arc<Mutex<State>>) -> Self {
        Self {
            state,
            sleep: Box::pin(tokio::time::sleep(Duration::from_secs(1))),
        }
    }
}

impl futures::stream::Stream for RtcpSendStream {
    type Item = (Vec<u8>, usize);

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let ntp_now = SystemTime::now();
        let mut lowest_wait = None;
        for session in state.sessions.iter_mut() {
            let mut session = session.inner.lock().unwrap();
            if let Some(data) = session.session.poll_rtcp_send(now, ntp_now) {
                return Poll::Ready(Some((data, session.id)));
            }
            if let Some(wait) = session.session.poll_rtcp_send_timeout(now) {
                if lowest_wait.map_or(true, |lowest_wait| wait < lowest_wait) {
                    lowest_wait = Some(wait);
                }
            }
        }
        state.rtcp_waker = Some(cx.waker().clone());
        drop(state);

        // default to the minimum initial rtcp delay so we don't busy loop if there are no sessions or no
        // timeouts available
        let lowest_wait =
            lowest_wait.unwrap_or(now + crate::rtpbin2::session::RTCP_MIN_REPORT_INTERVAL / 2);
        let this = self.get_mut();
        this.sleep.as_mut().reset(lowest_wait.into());
        if !std::future::Future::poll(this.sleep.as_mut(), cx).is_pending() {
            // wake us again if the delay is not pending for another go at finding the next timeout
            // value
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RtpRecvSrcPad {
    pt: u8,
    ssrc: u32,
    pad: gst::Pad,
}

#[derive(Debug)]
struct HeldRecvBuffer {
    hold_id: Option<usize>,
    buffer: gst::Buffer,
    srcpad: gst::Pad,
    new_pad: bool,
}

#[derive(Debug, Clone)]
struct BinSession {
    id: usize,
    inner: Arc<Mutex<BinSessionInner>>,
}

impl BinSession {
    fn new(id: usize, settings: &Settings) -> Self {
        let mut inner = BinSessionInner::new(id);
        inner
            .session
            .set_min_rtcp_interval(settings.min_rtcp_interval);
        inner.session.set_profile(settings.profile.into());
        Self {
            id,
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[derive(Debug)]
struct BinSessionInner {
    id: usize,

    session: Session,

    // State for received RTP streams
    rtp_recv_sinkpad: Option<gst::Pad>,
    rtp_recv_sink_group_id: Option<gst::GroupId>,
    rtp_recv_sink_caps: Option<gst::Caps>,
    rtp_recv_sink_segment: Option<gst::FormattedSegment<gst::ClockTime>>,
    rtp_recv_sink_seqnum: Option<gst::Seqnum>,

    caps_map: HashMap<u8, HashMap<u32, gst::Caps>>,
    recv_store: Vec<HeldRecvBuffer>,
    rtp_recv_srcpads: Vec<RtpRecvSrcPad>,
    recv_flow_combiner: Arc<Mutex<gst_base::UniqueFlowCombiner>>,

    // State for sending RTP streams
    rtp_send_sinkpad: Option<gst::Pad>,
    rtp_send_srcpad: Option<gst::Pad>,

    rtcp_recv_sinkpad: Option<gst::Pad>,
    rtcp_send_srcpad: Option<gst::Pad>,
}

impl BinSessionInner {
    fn new(id: usize) -> Self {
        Self {
            id,

            session: Session::new(),

            rtp_recv_sinkpad: None,
            rtp_recv_sink_group_id: None,
            rtp_recv_sink_caps: None,
            rtp_recv_sink_segment: None,
            rtp_recv_sink_seqnum: None,

            caps_map: HashMap::default(),
            recv_store: vec![],
            rtp_recv_srcpads: vec![],
            recv_flow_combiner: Arc::new(Mutex::new(gst_base::UniqueFlowCombiner::new())),

            rtp_send_sinkpad: None,
            rtp_send_srcpad: None,

            rtcp_recv_sinkpad: None,
            rtcp_send_srcpad: None,
        }
    }

    fn caps_from_pt_ssrc(&self, pt: u8, ssrc: u32) -> gst::Caps {
        self.caps_map
            .get(&pt)
            .and_then(|ssrc_map| ssrc_map.get(&ssrc))
            .cloned()
            .unwrap_or(
                gst::Caps::builder("application/x-rtp")
                    .field("payload", pt as i32)
                    .build(),
            )
    }

    fn get_or_create_rtp_recv_src(
        &mut self,
        rtpbin: &RtpBin2,
        pt: u8,
        ssrc: u32,
    ) -> (gst::Pad, bool) {
        if let Some(pad) = self
            .rtp_recv_srcpads
            .iter()
            .find(|&r| r.ssrc == ssrc && r.pt == pt)
        {
            (pad.pad.clone(), false)
        } else {
            let src_templ = rtpbin.obj().pad_template("rtp_recv_src_%u_%u_%u").unwrap();
            let srcpad = gst::Pad::builder_from_template(&src_templ)
                .iterate_internal_links_function(|pad, parent| {
                    RtpBin2::catch_panic_pad_function(
                        parent,
                        || gst::Iterator::from_vec(vec![]),
                        |this| this.iterate_internal_links(pad),
                    )
                })
                .query_function(|pad, parent, query| {
                    RtpBin2::catch_panic_pad_function(
                        parent,
                        || false,
                        |this| this.src_query(pad, query),
                    )
                })
                .name(format!("rtp_recv_src_{}_{}_{}", self.id, pt, ssrc))
                .build();
            srcpad.set_active(true).unwrap();
            let recv_pad = RtpRecvSrcPad {
                pt,
                ssrc,
                pad: srcpad.clone(),
            };

            let stream_id = format!("{pt}/{ssrc}");
            let mut stream_start = gst::event::StreamStart::builder(&stream_id);
            if let Some(group_id) = self
                .rtp_recv_sinkpad
                .as_ref()
                .unwrap()
                .sticky_event::<gst::event::StreamStart>(0)
                .and_then(|ss| ss.group_id())
            {
                stream_start = stream_start.group_id(group_id);
            }
            let stream_start = stream_start.build();
            let seqnum = stream_start.seqnum();
            let _ = srcpad.store_sticky_event(&stream_start);

            let caps = self.caps_from_pt_ssrc(pt, ssrc);
            let caps = gst::event::Caps::builder(&caps).seqnum(seqnum).build();
            let _ = srcpad.store_sticky_event(&caps);

            let segment = if let Some(segment) = self
                .rtp_recv_sinkpad
                .as_ref()
                .unwrap()
                .sticky_event::<gst::event::Segment>(0)
                .map(|s| s.segment().clone())
            {
                segment
            } else {
                let mut segment = gst::Segment::new();
                segment.set_format(gst::Format::Time);
                segment
            };
            let segment = gst::event::Segment::new(&segment);
            let _ = srcpad.store_sticky_event(&segment);

            self.recv_flow_combiner
                .lock()
                .unwrap()
                .add_pad(&recv_pad.pad);
            self.rtp_recv_srcpads.push(recv_pad);
            (srcpad, true)
        }
    }
}

#[derive(Debug, Default)]
struct State {
    sessions: Vec<BinSession>,
    rtcp_waker: Option<Waker>,
    max_session_id: usize,
    pads_session_id_map: HashMap<gst::Pad, usize>,
}

impl State {
    fn session_by_id(&self, id: usize) -> Option<&BinSession> {
        self.sessions.iter().find(|session| session.id == id)
    }

    fn stats(&self) -> gst::Structure {
        let mut ret = gst::Structure::builder("application/x-rtpbin2-stats");
        for session in self.sessions.iter() {
            let sess_id = session.id;
            let session = session.inner.lock().unwrap();
            let mut session_stats = gst::Structure::builder("application/x-rtp-session-stats");
            for ssrc in session.session.ssrcs() {
                if let Some(ls) = session.session.local_send_source_by_ssrc(ssrc) {
                    let mut source_stats =
                        gst::Structure::builder("application/x-rtp-source-stats")
                            .field("ssrc", ls.ssrc())
                            .field("sender", true)
                            .field("local", true)
                            .field("packets-sent", ls.packet_count())
                            .field("octets-sent", ls.octet_count())
                            .field("bitrate", ls.bitrate() as u64);
                    if let Some(pt) = ls.payload_type() {
                        if let Some(clock_rate) = session.session.clock_rate_from_pt(pt) {
                            source_stats = source_stats.field("clock-rate", clock_rate);
                        }
                    }
                    if let Some(sr) = ls.last_sent_sr() {
                        source_stats = source_stats
                            .field("sr-ntptime", sr.ntp_timestamp().as_u64())
                            .field("sr-rtptime", sr.rtp_timestamp())
                            .field("sr-octet-count", sr.octet_count())
                            .field("sr-packet-count", sr.packet_count());
                    }
                    let rbs = gst::List::new(ls.received_report_blocks().map(
                        |(sender_ssrc, ReceivedRb { rb, .. })| {
                            gst::Structure::builder("application/x-rtcp-report-block")
                                .field("sender-ssrc", sender_ssrc)
                                .field("rb-fraction-lost", rb.fraction_lost())
                                .field("rb-packets-lost", rb.cumulative_lost())
                                .field("rb-extended_sequence_number", rb.extended_sequence_number())
                                .field("rb-jitter", rb.jitter())
                                .field("rb-last-sr-ntp-time", rb.last_sr_ntp_time())
                                .field("rb-delay_since_last-sr-ntp-time", rb.delay_since_last_sr())
                                .build()
                        },
                    ));
                    match rbs.len() {
                        0 => (),
                        1 => {
                            source_stats =
                                source_stats.field("report-blocks", rbs.first().unwrap().clone());
                        }
                        _ => {
                            source_stats = source_stats.field("report-blocks", rbs);
                        }
                    }
                    // TODO: add jitter, packets-lost
                    session_stats =
                        session_stats.field(ls.ssrc().to_string(), source_stats.build());
                } else if let Some(lr) = session.session.local_receive_source_by_ssrc(ssrc) {
                    let mut source_stats =
                        gst::Structure::builder("application/x-rtp-source-stats")
                            .field("ssrc", lr.ssrc())
                            .field("sender", false)
                            .field("local", true);
                    if let Some(pt) = lr.payload_type() {
                        if let Some(clock_rate) = session.session.clock_rate_from_pt(pt) {
                            source_stats = source_stats.field("clock-rate", clock_rate);
                        }
                    }
                    // TODO: add rb stats
                    session_stats =
                        session_stats.field(lr.ssrc().to_string(), source_stats.build());
                } else if let Some(rs) = session.session.remote_send_source_by_ssrc(ssrc) {
                    let mut source_stats =
                        gst::Structure::builder("application/x-rtp-source-stats")
                            .field("ssrc", rs.ssrc())
                            .field("sender", true)
                            .field("local", false)
                            .field("octets-received", rs.octet_count())
                            .field("packets-received", rs.packet_count())
                            .field("bitrate", rs.bitrate() as u64)
                            .field("jitter", rs.jitter())
                            .field("packets-lost", rs.packets_lost());
                    if let Some(pt) = rs.payload_type() {
                        if let Some(clock_rate) = session.session.clock_rate_from_pt(pt) {
                            source_stats = source_stats.field("clock-rate", clock_rate);
                        }
                    }
                    if let Some(rtp_from) = rs.rtp_from() {
                        source_stats = source_stats.field("rtp-from", rtp_from.to_string());
                    }
                    if let Some(rtcp_from) = rs.rtcp_from() {
                        source_stats = source_stats.field("rtcp-from", rtcp_from.to_string());
                    }
                    if let Some(sr) = rs.last_received_sr() {
                        source_stats = source_stats
                            .field("sr-ntptime", sr.ntp_timestamp().as_u64())
                            .field("sr-rtptime", sr.rtp_timestamp())
                            .field("sr-octet-count", sr.octet_count())
                            .field("sr-packet-count", sr.packet_count());
                    }
                    if let Some(rb) = rs.last_sent_rb() {
                        source_stats = source_stats
                            .field("sent-rb-fraction-lost", rb.fraction_lost())
                            .field("sent-rb-packets-lost", rb.cumulative_lost())
                            .field(
                                "sent-rb-extended-sequence-number",
                                rb.extended_sequence_number(),
                            )
                            .field("sent-rb-jitter", rb.jitter())
                            .field("sent-rb-last-sr-ntp-time", rb.last_sr_ntp_time())
                            .field(
                                "sent-rb-delay-since-last-sr-ntp-time",
                                rb.delay_since_last_sr(),
                            );
                    }
                    let rbs = gst::List::new(rs.received_report_blocks().map(
                        |(sender_ssrc, ReceivedRb { rb, .. })| {
                            gst::Structure::builder("application/x-rtcp-report-block")
                                .field("sender-ssrc", sender_ssrc)
                                .field("rb-fraction-lost", rb.fraction_lost())
                                .field("rb-packets-lost", rb.cumulative_lost())
                                .field("rb-extended_sequence_number", rb.extended_sequence_number())
                                .field("rb-jitter", rb.jitter())
                                .field("rb-last-sr-ntp-time", rb.last_sr_ntp_time())
                                .field("rb-delay_since_last-sr-ntp-time", rb.delay_since_last_sr())
                                .build()
                        },
                    ));
                    match rbs.len() {
                        0 => (),
                        1 => {
                            source_stats =
                                source_stats.field("report-blocks", rbs.first().unwrap().clone());
                        }
                        _ => {
                            source_stats = source_stats.field("report-blocks", rbs);
                        }
                    }
                    session_stats =
                        session_stats.field(rs.ssrc().to_string(), source_stats.build());
                } else if let Some(rr) = session.session.remote_receive_source_by_ssrc(ssrc) {
                    let source_stats = gst::Structure::builder("application/x-rtp-source-stats")
                        .field("ssrc", rr.ssrc())
                        .field("sender", false)
                        .field("local", false)
                        .build();
                    session_stats = session_stats.field(rr.ssrc().to_string(), source_stats);
                }
            }
            ret = ret.field(sess_id.to_string(), session_stats.build());
        }
        ret.build()
    }
}

pub struct RtpBin2 {
    settings: Mutex<Settings>,
    state: Arc<Mutex<State>>,
    rtcp_task: Mutex<Option<RtcpTask>>,
}

struct RtcpTask {
    abort_handle: AbortHandle,
}

impl RtpBin2 {
    fn start_rtcp_task(&self) {
        let mut rtcp_task = self.rtcp_task.lock().unwrap();

        if rtcp_task.is_some() {
            return;
        }

        // run the runtime from another task to prevent the "start a runtime from within a runtime" panic
        // when the plugin is statically linked.
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let state = self.state.clone();
        RUNTIME.spawn(async move {
            let future = Abortable::new(Self::rtcp_task(state), abort_registration);
            future.await
        });

        rtcp_task.replace(RtcpTask { abort_handle });
    }

    async fn rtcp_task(state: Arc<Mutex<State>>) {
        let mut stream = RtcpSendStream::new(state.clone());
        while let Some((data, session_id)) = stream.next().await {
            let state = state.lock().unwrap();
            let Some(session) = state.session_by_id(session_id) else {
                continue;
            };
            let Some(rtcp_srcpad) = session.inner.lock().unwrap().rtcp_send_srcpad.clone() else {
                continue;
            };
            RUNTIME.spawn_blocking(move || {
                let buffer = gst::Buffer::from_mut_slice(data);
                if let Err(e) = rtcp_srcpad.push(buffer) {
                    gst::warning!(CAT, obj: rtcp_srcpad, "Failed to send rtcp data: flow return {e:?}");
                }
            });
        }
    }

    fn stop_rtcp_task(&self) {
        let mut rtcp_task = self.rtcp_task.lock().unwrap();

        if let Some(rtcp) = rtcp_task.take() {
            rtcp.abort_handle.abort();
        }
    }

    pub fn src_query(&self, pad: &gst::Pad, query: &mut gst::QueryRef) -> bool {
        gst::log!(CAT, obj: pad, "Handling query {query:?}");

        use gst::QueryViewMut::*;
        match query.view_mut() {
            Latency(q) => {
                let mut peer_query = gst::query::Latency::new();

                let ret = gst::Pad::query_default(pad, Some(&*self.obj()), &mut peer_query);
                let our_latency = self.settings.lock().unwrap().latency;

                let min = if ret {
                    let (_, min, _) = peer_query.result();

                    our_latency + min
                } else {
                    our_latency
                };

                gst::info!(CAT, obj: pad, "Handled latency query, our latency {our_latency}, minimum latency: {min}");
                q.set(true, min, gst::ClockTime::NONE);

                ret
            }
            _ => gst::Pad::query_default(pad, Some(pad), query),
        }
    }

    fn iterate_internal_links(&self, pad: &gst::Pad) -> gst::Iterator<gst::Pad> {
        let state = self.state.lock().unwrap();
        if let Some(&id) = state.pads_session_id_map.get(pad) {
            if let Some(session) = state.session_by_id(id) {
                let session = session.inner.lock().unwrap();
                if let Some(ref sinkpad) = session.rtp_recv_sinkpad {
                    if sinkpad == pad {
                        let pads = session
                            .rtp_recv_srcpads
                            .iter()
                            .map(|r| r.pad.clone())
                            .collect();
                        return gst::Iterator::from_vec(pads);
                    } else if session.rtp_recv_srcpads.iter().any(|r| &r.pad == pad) {
                        return gst::Iterator::from_vec(vec![sinkpad.clone()]);
                    }
                }
                if let Some(ref sinkpad) = session.rtp_send_sinkpad {
                    if let Some(ref srcpad) = session.rtp_send_srcpad {
                        if sinkpad == pad {
                            return gst::Iterator::from_vec(vec![srcpad.clone()]);
                        } else if srcpad == pad {
                            return gst::Iterator::from_vec(vec![sinkpad.clone()]);
                        }
                    }
                }
                // nothing to do for rtcp pads
            }
        }
        gst::Iterator::from_vec(vec![])
    }

    fn rtp_recv_sink_chain(
        &self,
        _pad: &gst::Pad,
        id: usize,
        buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let state = self.state.lock().unwrap();
        let Some(session) = state.session_by_id(id) else {
            return Err(gst::FlowError::Error);
        };

        let addr: Option<SocketAddr> =
            buffer
                .meta::<gst_net::NetAddressMeta>()
                .and_then(|net_meta| {
                    net_meta
                        .addr()
                        .dynamic_cast::<gio::InetSocketAddress>()
                        .map(|a| a.into())
                        .ok()
                });
        let mapped = buffer.map_readable().map_err(|e| {
            gst::error!(CAT, imp: self, "Failed to map input buffer {e:?}");
            gst::FlowError::Error
        })?;
        let rtp = match rtp_types::RtpPacket::parse(&mapped) {
            Ok(rtp) => rtp,
            Err(e) => {
                // TODO: handle if it's a valid rtcp-muxed RTCP packet
                gst::error!(CAT, imp: self, "Failed to parse input as valid rtp packet: {e:?}");
                return Ok(gst::FlowSuccess::Ok);
            }
        };

        let session = session.clone();
        let mut session = session.inner.lock().unwrap();
        drop(state);

        let now = Instant::now();
        let mut buffers_to_push = vec![];
        loop {
            match session.session.handle_recv(&rtp, addr, now) {
                RecvReply::SsrcCollision(_ssrc) => (), // TODO: handle ssrc collision
                RecvReply::NewSsrc(_ssrc, _pt) => (),  // TODO: signal new ssrc externally
                RecvReply::Hold(hold_id) => {
                    let pt = rtp.payload_type();
                    let ssrc = rtp.ssrc();
                    drop(mapped);
                    let (srcpad, new_pad) = session.get_or_create_rtp_recv_src(self, pt, ssrc);
                    session.recv_store.push(HeldRecvBuffer {
                        hold_id: Some(hold_id),
                        buffer,
                        srcpad,
                        new_pad,
                    });
                    break;
                }
                RecvReply::Drop(hold_id) => {
                    if let Some(pos) = session
                        .recv_store
                        .iter()
                        .position(|b| b.hold_id.unwrap() == hold_id)
                    {
                        session.recv_store.remove(pos);
                    }
                }
                RecvReply::Forward(hold_id) => {
                    if let Some(pos) = session
                        .recv_store
                        .iter()
                        .position(|b| b.hold_id.unwrap() == hold_id)
                    {
                        buffers_to_push.push(session.recv_store.remove(pos));
                    } else {
                        unreachable!();
                    }
                }
                RecvReply::Ignore => break,
                RecvReply::Passthrough => {
                    let pt = rtp.payload_type();
                    let ssrc = rtp.ssrc();
                    drop(mapped);
                    let (srcpad, new_pad) = session.get_or_create_rtp_recv_src(self, pt, ssrc);
                    buffers_to_push.push(HeldRecvBuffer {
                        hold_id: None,
                        buffer,
                        srcpad,
                        new_pad,
                    });
                    break;
                }
            }
        }
        let recv_flow_combiner = session.recv_flow_combiner.clone();
        drop(session);

        let mut recv_flow_combiner = recv_flow_combiner.lock().unwrap();
        for held in buffers_to_push {
            // TODO: handle other processing
            if held.new_pad {
                let mut state = self.state.lock().unwrap();
                state.pads_session_id_map.insert(held.srcpad.clone(), id);
                drop(state);
                self.obj().add_pad(&held.srcpad).unwrap();
            }
            recv_flow_combiner.update_pad_flow(&held.srcpad, held.srcpad.push(held.buffer))?;
        }
        Ok(gst::FlowSuccess::Ok)
    }

    fn rtp_send_sink_chain(
        &self,
        id: usize,
        buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let state = self.state.lock().unwrap();
        let Some(session) = state.session_by_id(id) else {
            gst::error!(CAT, "No session?");
            return Err(gst::FlowError::Error);
        };

        let mapped = buffer.map_readable().map_err(|e| {
            gst::error!(CAT, imp: self, "Failed to map input buffer {e:?}");
            gst::FlowError::Error
        })?;
        let rtp = match rtp_types::RtpPacket::parse(&mapped) {
            Ok(rtp) => rtp,
            Err(e) => {
                gst::error!(CAT, imp: self, "Failed to parse input as valid rtp packet: {e:?}");
                return Ok(gst::FlowSuccess::Ok);
            }
        };

        let session = session.clone();
        let mut session = session.inner.lock().unwrap();
        drop(state);

        let now = Instant::now();
        loop {
            match session.session.handle_send(&rtp, now) {
                SendReply::SsrcCollision(_ssrc) => (), // TODO: handle ssrc collision
                SendReply::NewSsrc(_ssrc, _pt) => (),  // TODO; signal ssrc externally
                SendReply::Passthrough => break,
                SendReply::Drop => return Ok(gst::FlowSuccess::Ok),
            }
        }
        // TODO: handle other processing
        drop(mapped);
        let srcpad = session.rtp_send_srcpad.clone().unwrap();
        drop(session);
        srcpad.push(buffer)
    }

    fn rtcp_recv_sink_chain(
        &self,
        id: usize,
        buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let state = self.state.lock().unwrap();
        let Some(session) = state.session_by_id(id) else {
            return Err(gst::FlowError::Error);
        };

        let addr: Option<SocketAddr> =
            buffer
                .meta::<gst_net::NetAddressMeta>()
                .and_then(|net_meta| {
                    net_meta
                        .addr()
                        .dynamic_cast::<gio::InetSocketAddress>()
                        .map(|a| a.into())
                        .ok()
                });
        let mapped = buffer.map_readable().map_err(|e| {
            gst::error!(CAT, imp: self, "Failed to map input buffer {e:?}");
            gst::FlowError::Error
        })?;
        let rtcp = match rtcp_types::Compound::parse(&mapped) {
            Ok(rtcp) => rtcp,
            Err(e) => {
                gst::error!(CAT, imp: self, "Failed to parse input as valid rtcp packet: {e:?}");
                return Ok(gst::FlowSuccess::Ok);
            }
        };

        let session = session.clone();
        let mut session = session.inner.lock().unwrap();
        let waker = state.rtcp_waker.clone();
        drop(state);

        let now = Instant::now();
        let ntp_now = SystemTime::now();
        let replies = session
            .session
            .handle_rtcp_recv(rtcp, mapped.len(), addr, now, ntp_now);
        for reply in replies {
            match reply {
                RtcpRecvReply::NewSsrc(_ssrc) => (), // TODO: handle new ssrc
                RtcpRecvReply::SsrcCollision(_ssrc) => (), // TODO: handle ssrc collision
                RtcpRecvReply::TimerReconsideration => {
                    if let Some(ref waker) = waker {
                        // reconsider timers means that we wake the rtcp task to get a new timeout
                        waker.wake_by_ref();
                    }
                }
            }
        }
        drop(mapped);

        Ok(gst::FlowSuccess::Ok)
    }

    fn rtp_send_sink_event(&self, pad: &gst::Pad, event: gst::Event, id: usize) -> bool {
        match event.view() {
            gst::EventView::Caps(caps) => {
                if let Some((pt, clock_rate)) = Self::pt_clock_rate_from_caps(caps.caps()) {
                    let state = self.state.lock().unwrap();
                    if let Some(session) = state.session_by_id(id) {
                        let mut session = session.inner.lock().unwrap();
                        session.session.set_pt_clock_rate(pt, clock_rate);
                    }
                }
                gst::Pad::event_default(pad, Some(&*self.obj()), event)
            }
            gst::EventView::Eos(_eos) => {
                let now = Instant::now();
                let mut state = self.state.lock().unwrap();
                if let Some(session) = state.session_by_id(id) {
                    let mut session = session.inner.lock().unwrap();
                    let ssrcs = session.session.ssrcs().collect::<Vec<_>>();
                    // We want to bye all relevant ssrc's here.
                    // Relevant means they will not be used by something else which means that any
                    // local send ssrc that is not being used for Sr/Rr reports (internal_ssrc) can
                    // have the Bye state applied.
                    let mut all_local = true;
                    let internal_ssrc = session.session.internal_ssrc();
                    for ssrc in ssrcs {
                        let Some(local_send) = session.session.mut_local_send_source_by_ssrc(ssrc)
                        else {
                            if let Some(local_recv) =
                                session.session.local_receive_source_by_ssrc(ssrc)
                            {
                                if local_recv.state() != SourceState::Bye
                                    && Some(ssrc) != internal_ssrc
                                {
                                    all_local = false;
                                }
                            }
                            continue;
                        };
                        if Some(ssrc) != internal_ssrc {
                            local_send.mark_bye("End of Stream")
                        }
                    }
                    if all_local {
                        // if there are no non-local send ssrc's, then we can Bye the entire
                        // session.
                        session.session.schedule_bye("End of Stream", now);
                    }
                    drop(session);
                    if let Some(waker) = state.rtcp_waker.take() {
                        waker.wake();
                    }
                }
                drop(state);
                gst::Pad::event_default(pad, Some(&*self.obj()), event)
            }
            _ => gst::Pad::event_default(pad, Some(&*self.obj()), event),
        }
    }

    fn rtp_recv_sink_event(&self, pad: &gst::Pad, event: gst::Event, id: usize) -> bool {
        match event.view() {
            gst::EventView::Caps(caps) => {
                if let Some((pt, clock_rate)) = Self::pt_clock_rate_from_caps(caps.caps()) {
                    let state = self.state.lock().unwrap();
                    if let Some(session) = state.session_by_id(id) {
                        let mut session = session.inner.lock().unwrap();
                        session.session.set_pt_clock_rate(pt, clock_rate);
                    }
                }
                true
            }
            gst::EventView::Eos(_eos) => {
                let now = Instant::now();
                let mut state = self.state.lock().unwrap();
                if let Some(session) = state.session_by_id(id) {
                    let mut session = session.inner.lock().unwrap();
                    let ssrcs = session.session.ssrcs().collect::<Vec<_>>();
                    // we can only Bye the entire session if we do not have any local send sources
                    // currently sending data
                    let mut all_remote = true;
                    let internal_ssrc = session.session.internal_ssrc();
                    for ssrc in ssrcs {
                        let Some(_local_recv) = session.session.local_receive_source_by_ssrc(ssrc)
                        else {
                            if let Some(local_send) =
                                session.session.local_send_source_by_ssrc(ssrc)
                            {
                                if local_send.state() != SourceState::Bye
                                    && Some(ssrc) != internal_ssrc
                                {
                                    all_remote = false;
                                    break;
                                }
                            }
                            continue;
                        };
                    }
                    if all_remote {
                        session.session.schedule_bye("End of stream", now);
                    }
                    drop(session);
                    if let Some(waker) = state.rtcp_waker.take() {
                        waker.wake();
                    }
                }
                // FIXME: may need to delay sending eos under some circumstances
                true
            }
            _ => gst::Pad::event_default(pad, Some(&*self.obj()), event),
        }
    }

    fn pt_clock_rate_from_caps(caps: &gst::CapsRef) -> Option<(u8, u32)> {
        let Some(s) = caps.structure(0) else {
            return None;
        };
        let Some((clock_rate, pt)) = Option::zip(
            s.get::<i32>("clock-rate").ok(),
            s.get::<i32>("payload").ok(),
        ) else {
            return None;
        };
        if (0..=127).contains(&pt) && clock_rate > 0 {
            Some((pt as u8, clock_rate as u32))
        } else {
            None
        }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for RtpBin2 {
    const NAME: &'static str = "GstRtpBin2";
    type Type = super::RtpBin2;
    type ParentType = gst::Element;

    fn new() -> Self {
        GstRustLogger::install();
        Self {
            settings: Default::default(),
            state: Default::default(),
            rtcp_task: Mutex::new(None),
        }
    }
}

impl ObjectImpl for RtpBin2 {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecUInt::builder("latency")
                    .nick("Buffer latency in ms")
                    .blurb("Amount of ms to buffer")
                    .default_value(DEFAULT_LATENCY.mseconds() as u32)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt::builder("min-rtcp-interval")
                    .nick("Minimum RTCP interval in ms")
                    .blurb("Minimum time (in ms) between RTCP reports")
                    .default_value(DEFAULT_MIN_RTCP_INTERVAL.as_millis() as u32)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt::builder("stats")
                    .nick("Statistics")
                    .blurb("Statistics about the session")
                    .read_only()
                    .build(),
                glib::ParamSpecEnum::builder::<Profile>("rtp-profile")
                    .nick("RTP Profile")
                    .blurb("RTP Profile to use")
                    .default_value(Profile::default())
                    .mutable_ready()
                    .build(),
            ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "latency" => {
                let _latency = {
                    let mut settings = self.settings.lock().unwrap();
                    settings.latency = gst::ClockTime::from_mseconds(
                        value.get::<u32>().expect("type checked upstream").into(),
                    );
                    settings.latency
                };

                let _ = self
                    .obj()
                    .post_message(gst::message::Latency::builder().src(&*self.obj()).build());
            }
            "min-rtcp-interval" => {
                let mut settings = self.settings.lock().unwrap();
                settings.min_rtcp_interval = Duration::from_millis(
                    value.get::<u32>().expect("type checked upstream").into(),
                );
            }
            "rtp-profile" => {
                let mut settings = self.settings.lock().unwrap();
                settings.profile = value.get::<Profile>().expect("Type checked upstream");
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        match pspec.name() {
            "latency" => {
                let settings = self.settings.lock().unwrap();
                (settings.latency.mseconds() as u32).to_value()
            }
            "min-rtcp-interval" => {
                let settings = self.settings.lock().unwrap();
                (settings.min_rtcp_interval.as_millis() as u32).to_value()
            }
            "stats" => {
                let state = self.state.lock().unwrap();
                state.stats().to_value()
            }
            "rtp-profile" => {
                let settings = self.settings.lock().unwrap();
                settings.profile.to_value()
            }
            _ => unimplemented!(),
        }
    }
}

impl GstObjectImpl for RtpBin2 {}

impl ElementImpl for RtpBin2 {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "RTP Bin",
                "Network/RTP/Filter",
                "RTP sessions management",
                "Matthew Waters <matthew@centricular.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: Lazy<Vec<gst::PadTemplate>> = Lazy::new(|| {
            let rtp_caps = gst::Caps::builder_full()
                .structure(gst::Structure::builder("application/x-rtp").build())
                .build();
            let rtcp_caps = gst::Caps::builder_full()
                .structure(gst::Structure::builder("application/x-rtcp").build())
                .build();

            vec![
                gst::PadTemplate::new(
                    "rtp_recv_sink_%u",
                    gst::PadDirection::Sink,
                    gst::PadPresence::Request,
                    &rtp_caps,
                )
                .unwrap(),
                gst::PadTemplate::new(
                    "rtcp_recv_sink_%u",
                    gst::PadDirection::Sink,
                    gst::PadPresence::Request,
                    &rtcp_caps,
                )
                .unwrap(),
                gst::PadTemplate::new(
                    "rtp_recv_src_%u_%u_%u",
                    gst::PadDirection::Src,
                    gst::PadPresence::Sometimes,
                    &rtp_caps,
                )
                .unwrap(),
                gst::PadTemplate::new(
                    "rtp_send_sink_%u",
                    gst::PadDirection::Sink,
                    gst::PadPresence::Request,
                    &rtp_caps,
                )
                .unwrap(),
                gst::PadTemplate::new(
                    "rtp_send_src_%u",
                    gst::PadDirection::Src,
                    gst::PadPresence::Sometimes,
                    &rtp_caps,
                )
                .unwrap(),
                gst::PadTemplate::new(
                    "rtcp_send_src_%u",
                    gst::PadDirection::Src,
                    gst::PadPresence::Request,
                    &rtcp_caps,
                )
                .unwrap(),
            ]
        });

        PAD_TEMPLATES.as_ref()
    }

    fn request_new_pad(
        &self,
        templ: &gst::PadTemplate,
        name: Option<&str>,
        _caps: Option<&gst::Caps>, // XXX: do something with caps?
    ) -> Option<gst::Pad> {
        let this = self.obj();
        let settings = self.settings.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();
        let max_session_id = state.max_session_id;

        // parse the possibly provided name into a session id or use the default
        let sess_parse = move |name: Option<&str>, prefix, default_id| -> Option<usize> {
            if let Some(name) = name {
                name.strip_prefix(prefix).and_then(|suffix| {
                    if suffix.starts_with("%u") {
                        Some(default_id)
                    } else {
                        suffix.parse::<usize>().ok()
                    }
                })
            } else {
                Some(default_id)
            }
        };

        match templ.name_template() {
            "rtp_send_sink_%u" => {
                sess_parse(name, "rtp_send_sink_", max_session_id).and_then(|id| {
                    let new_pad = move |session: &mut BinSessionInner| -> Option<(gst::Pad, Option<gst::Pad>, usize)> {
                        let sinkpad = gst::Pad::builder_from_template(templ)
                            .chain_function(move |_pad, parent, buffer| {
                                RtpBin2::catch_panic_pad_function(
                                    parent,
                                    || Err(gst::FlowError::Error),
                                    |this| this.rtp_send_sink_chain(id, buffer),
                                )
                            })
                            .iterate_internal_links_function(|pad, parent| {
                                RtpBin2::catch_panic_pad_function(parent, || gst::Iterator::from_vec(vec![]), |this| this.iterate_internal_links(pad))
                            })
                            .event_function(move |pad, parent, event|
                                RtpBin2::catch_panic_pad_function(parent, || false, |this| this.rtp_send_sink_event(pad, event, id))
                            )
                            .flags(gst::PadFlags::PROXY_CAPS)
                            .name(format!("rtp_send_sink_{}", id))
                            .build();
                        sinkpad.set_active(true).unwrap();
                        this.add_pad(&sinkpad).unwrap();
                        let src_templ = self.obj().pad_template("rtp_send_src_%u").unwrap();
                        let srcpad = gst::Pad::builder_from_template(&src_templ)
                            .iterate_internal_links_function(|pad, parent| {
                                RtpBin2::catch_panic_pad_function(parent, || gst::Iterator::from_vec(vec![]), |this| this.iterate_internal_links(pad))
                            })
                            .name(format!("rtp_send_src_{}", id))
                            .build();
                        srcpad.set_active(true).unwrap();
                        this.add_pad(&srcpad).unwrap();
                        session.rtp_send_sinkpad = Some(sinkpad.clone());
                        session.rtp_send_srcpad = Some(srcpad.clone());
                        Some((sinkpad, Some(srcpad), id))
                    };

                    let session = state.session_by_id(id);
                    if let Some(session) = session {
                        let mut session = session.inner.lock().unwrap();
                        if session.rtp_send_sinkpad.is_some() {
                            None
                        } else {
                            new_pad(&mut session)
                        }
                    } else {
                        let session = BinSession::new(id, &settings);
                        let mut inner = session.inner.lock().unwrap();
                        let ret = new_pad(&mut inner);
                        drop(inner);
                        state.sessions.push(session);
                        ret
                    }
                })
            }
            "rtp_recv_sink_%u" => {
                sess_parse(name, "rtp_recv_sink_", max_session_id).and_then(|id| {
                    let new_pad = move |session: &mut BinSessionInner| -> Option<(gst::Pad, Option<gst::Pad>, usize)> {
                        let sinkpad = gst::Pad::builder_from_template(templ)
                            .chain_function(move |pad, parent, buffer| {
                                RtpBin2::catch_panic_pad_function(
                                    parent,
                                    || Err(gst::FlowError::Error),
                                    |this| this.rtp_recv_sink_chain(pad, id, buffer),
                                )
                            })
                            .iterate_internal_links_function(|pad, parent| {
                                RtpBin2::catch_panic_pad_function(parent, || gst::Iterator::from_vec(vec![]), |this| this.iterate_internal_links(pad))
                            })
                            .event_function(move |pad, parent, event|
                                RtpBin2::catch_panic_pad_function(parent, || false, |this| this.rtp_recv_sink_event(pad, event, id))
                            )
                            .name(format!("rtp_recv_sink_{}", id))
                            .build();
                        sinkpad.set_active(true).unwrap();
                        this.add_pad(&sinkpad).unwrap();
                        session.rtp_recv_sinkpad = Some(sinkpad.clone());
                        Some((sinkpad, None, id))
                    };

                    let session = state.session_by_id(id);
                    if let Some(session) = session {
                        let mut session = session.inner.lock().unwrap();
                        if session.rtp_send_sinkpad.is_some() {
                            None
                        } else {
                            new_pad(&mut session)
                        }
                    } else {
                        let session = BinSession::new(id, &settings);
                        let mut inner = session.inner.lock().unwrap();
                        let ret = new_pad(&mut inner);
                        drop(inner);
                        state.sessions.push(session);
                        ret
                    }
                })
            }
            "rtcp_recv_sink_%u" => {
                sess_parse(name, "rtcp_recv_sink_", max_session_id).and_then(|id| {
                    state.session_by_id(id).and_then(|session| {
                        let mut session = session.inner.lock().unwrap();
                        if session.rtcp_recv_sinkpad.is_some() {
                            None
                        } else {
                            let sinkpad = gst::Pad::builder_from_template(templ)
                                .chain_function(move |_pad, parent, buffer| {
                                    RtpBin2::catch_panic_pad_function(
                                        parent,
                                        || Err(gst::FlowError::Error),
                                        |this| this.rtcp_recv_sink_chain(id, buffer),
                                    )
                                })
                                .iterate_internal_links_function(|pad, parent| {
                                    RtpBin2::catch_panic_pad_function(parent, || gst::Iterator::from_vec(vec![]), |this| this.iterate_internal_links(pad))
                                })
                                .name(format!("rtcp_recv_sink_{}", id))
                                .build();
                            sinkpad.set_active(true).unwrap();
                            this.add_pad(&sinkpad).unwrap();
                            session.rtcp_recv_sinkpad = Some(sinkpad.clone());
                            Some((sinkpad, None, id))
                        }
                    })
                })
            }
            "rtcp_send_src_%u" => {
                self.start_rtcp_task();
                sess_parse(name, "rtcp_send_src_", max_session_id).and_then(|id| {
                    state.session_by_id(id).and_then(|session| {
                        let mut session = session.inner.lock().unwrap();

                        if session.rtcp_send_srcpad.is_some() {
                            None
                        } else {
                            let this = self.obj();
                            let srcpad = gst::Pad::builder_from_template(templ)
                                .iterate_internal_links_function(|pad, parent| {
                                    RtpBin2::catch_panic_pad_function(parent, || gst::Iterator::from_vec(vec![]), |this| this.iterate_internal_links(pad))
                                })
                                .name(format!("rtcp_send_src_{}", id))
                                .build();

                            let stream_id = format!("{}/rtcp", id);
                            let stream_start = gst::event::StreamStart::builder(&stream_id).build();
                            let seqnum = stream_start.seqnum();

                            let caps = gst::Caps::new_empty_simple("application/x-rtcp");
                            let caps = gst::event::Caps::builder(&caps).seqnum(seqnum).build();

                            let segment = gst::FormattedSegment::<gst::ClockTime>::new();
                            let segment = gst::event::Segment::new(&segment);

                            srcpad.set_active(true).unwrap();

                            let _ = srcpad.store_sticky_event(&stream_start);
                            let _ = srcpad.store_sticky_event(&caps);
                            let _ = srcpad.store_sticky_event(&segment);

                            this.add_pad(&srcpad).unwrap();
                            session.rtcp_send_srcpad = Some(srcpad.clone());
                            Some((srcpad, None, id))
                        }
                    })
                })
            }
            _ => None,
        }
        .map(|(pad, otherpad, id)| {
            state.max_session_id = (id + 1).max(state.max_session_id);
            state.pads_session_id_map.insert(pad.clone(), id);
            if let Some(pad) = otherpad {
                state.pads_session_id_map.insert(pad, id);
            }
            pad
        })
    }

    fn release_pad(&self, pad: &gst::Pad) {
        let mut state = self.state.lock().unwrap();
        let mut removed_pads = vec![];
        if let Some(&id) = state.pads_session_id_map.get(pad) {
            removed_pads.push(pad.clone());
            if let Some(session) = state.session_by_id(id) {
                let mut session = session.inner.lock().unwrap();

                if Some(pad) == session.rtp_recv_sinkpad.as_ref() {
                    session.rtp_recv_sinkpad = None;
                    removed_pads.extend(session.rtp_recv_srcpads.iter().map(|r| r.pad.clone()));
                    session.recv_flow_combiner.lock().unwrap().clear();
                    session.rtp_recv_srcpads.clear();
                    session.recv_store.clear();
                }

                if Some(pad) == session.rtp_send_sinkpad.as_ref() {
                    session.rtp_send_sinkpad = None;
                    if let Some(srcpad) = session.rtp_send_srcpad.take() {
                        removed_pads.push(srcpad);
                    }
                }

                if Some(pad) == session.rtcp_send_srcpad.as_ref() {
                    session.rtcp_send_srcpad = None;
                }

                if Some(pad) == session.rtcp_recv_sinkpad.as_ref() {
                    session.rtcp_recv_sinkpad = None;
                }

                if session.rtp_recv_sinkpad.is_none()
                    && session.rtp_send_sinkpad.is_none()
                    && session.rtcp_recv_sinkpad.is_none()
                    && session.rtcp_send_srcpad.is_none()
                {
                    let id = session.id;
                    drop(session);
                    state.sessions.retain(|s| s.id != id);
                }
            }

            for pad in removed_pads.iter() {
                state.pads_session_id_map.remove(pad);
            }
        }
        drop(state);

        for pad in removed_pads {
            let _ = pad.set_active(false);
            // Pad might not have been added yet if it's a RTP recv srcpad
            if pad.has_as_parent(&*self.obj()) {
                let _ = self.obj().remove_pad(&pad);
            }
        }

        self.parent_release_pad(pad)
    }

    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        let mut success = self.parent_change_state(transition)?;

        match transition {
            gst::StateChange::ReadyToNull => {
                self.stop_rtcp_task();
            }
            gst::StateChange::ReadyToPaused => {
                success = gst::StateChangeSuccess::NoPreroll;
            }
            gst::StateChange::PlayingToPaused => {
                success = gst::StateChangeSuccess::NoPreroll;
            }
            gst::StateChange::PausedToReady => {
                let mut state = self.state.lock().unwrap();
                let mut removed_pads = vec![];
                for session in &state.sessions {
                    let mut session = session.inner.lock().unwrap();
                    removed_pads.extend(session.rtp_recv_srcpads.iter().map(|r| r.pad.clone()));
                    session.recv_flow_combiner.lock().unwrap().clear();
                    session.rtp_recv_srcpads.clear();
                    session.recv_store.clear();

                    session.rtp_recv_sink_caps = None;
                    session.rtp_recv_sink_segment = None;
                    session.rtp_recv_sink_seqnum = None;
                    session.rtp_recv_sink_group_id = None;

                    session.caps_map.clear();
                }
                for pad in removed_pads.iter() {
                    state.pads_session_id_map.remove(pad);
                }
                drop(state);

                for pad in removed_pads {
                    let _ = pad.set_active(false);
                    // Pad might not have been added yet if it's a RTP recv srcpad
                    if pad.has_as_parent(&*self.obj()) {
                        let _ = self.obj().remove_pad(&pad);
                    }
                }
            }
            _ => (),
        }
        Ok(success)
    }
}

static RUST_CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "rust-log",
        gst::DebugColorFlags::empty(),
        Some("Logs from rust crates"),
    )
});

static GST_RUST_LOGGER_ONCE: once_cell::sync::OnceCell<()> = once_cell::sync::OnceCell::new();
static GST_RUST_LOGGER: GstRustLogger = GstRustLogger {};

pub(crate) struct GstRustLogger {}

impl GstRustLogger {
    pub fn install() {
        GST_RUST_LOGGER_ONCE.get_or_init(|| {
            if log::set_logger(&GST_RUST_LOGGER).is_err() {
                gst::warning!(
                    RUST_CAT,
                    "Cannot install log->gst logger, already installed?"
                );
            } else {
                log::set_max_level(GstRustLogger::debug_level_to_log_level_filter(
                    RUST_CAT.threshold(),
                ));
                gst::info!(RUST_CAT, "installed log->gst logger");
            }
        });
    }

    fn debug_level_to_log_level_filter(level: gst::DebugLevel) -> log::LevelFilter {
        match level {
            gst::DebugLevel::None => log::LevelFilter::Off,
            gst::DebugLevel::Error => log::LevelFilter::Error,
            gst::DebugLevel::Warning => log::LevelFilter::Warn,
            gst::DebugLevel::Fixme | gst::DebugLevel::Info => log::LevelFilter::Info,
            gst::DebugLevel::Debug => log::LevelFilter::Debug,
            gst::DebugLevel::Log | gst::DebugLevel::Trace | gst::DebugLevel::Memdump => {
                log::LevelFilter::Trace
            }
            _ => log::LevelFilter::Trace,
        }
    }

    fn log_level_to_debug_level(level: log::Level) -> gst::DebugLevel {
        match level {
            log::Level::Error => gst::DebugLevel::Error,
            log::Level::Warn => gst::DebugLevel::Warning,
            log::Level::Info => gst::DebugLevel::Info,
            log::Level::Debug => gst::DebugLevel::Debug,
            log::Level::Trace => gst::DebugLevel::Trace,
        }
    }
}

impl log::Log for GstRustLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        RUST_CAT.above_threshold(GstRustLogger::log_level_to_debug_level(metadata.level()))
    }

    fn log(&self, record: &log::Record) {
        let gst_level = GstRustLogger::log_level_to_debug_level(record.metadata().level());
        let file = record
            .file()
            .map(glib::GString::from)
            .unwrap_or_else(|| glib::GString::from("rust-log"));
        let function = record.target();
        let line = record.line().unwrap_or(0);
        RUST_CAT.log(
            None::<&glib::Object>,
            gst_level,
            file.as_gstr(),
            function,
            line,
            *record.args(),
        );
    }

    fn flush(&self) {}
}