// Copyright (C) 2022 LTN Global Communications, Inc.
// Contact: Jan Alexander Steffens (heftig) <jan.steffens@ltnglobal.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::{
    glib::{self, translate::IntoGlib},
    prelude::*,
    subclass::prelude::*,
};
use once_cell::sync::Lazy;
use parking_lot::{Condvar, Mutex, MutexGuard};
use std::{collections::VecDeque, sync::mpsc};

/// Offset for the segment in single-segment mode, to handle negative DTS
const SEGMENT_OFFSET: gst::ClockTime = gst::ClockTime::from_seconds(60 * 60 * 1000);

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "livesync",
        gst::DebugColorFlags::empty(),
        Some("debug category for the livesync element"),
    )
});

fn audio_info_from_caps(
    caps: &gst::CapsRef,
) -> Result<Option<gst_audio::AudioInfo>, glib::BoolError> {
    caps.structure(0)
        .map_or(false, |s| s.has_name("audio/x-raw"))
        .then(|| gst_audio::AudioInfo::from_caps(caps))
        .transpose()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferLateness {
    OnTime,
    LateUnderThreshold,
    LateOverThreshold,
}

#[derive(Debug)]
enum Item {
    Buffer(gst::Buffer, BufferLateness),
    Event(gst::Event),
    // SAFETY: Item needs to wait until the query and the receiver has returned
    Query(std::ptr::NonNull<gst::QueryRef>, mpsc::SyncSender<bool>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Timestamps {
    start: gst::ClockTime,
    end: gst::ClockTime,
}

// SAFETY: Need to be able to pass *mut gst::QueryRef
unsafe impl Send for Item {}

#[derive(Debug)]
pub struct LiveSync {
    state: Mutex<State>,
    cond: Condvar,
    sinkpad: gst::Pad,
    srcpad: gst::Pad,
}

#[derive(Debug)]
struct State {
    latency: gst::ClockTime,
    late_threshold: Option<gst::ClockTime>,
    single_segment: bool,

    upstream_latency: Option<gst::ClockTime>,
    fallback_duration: gst::ClockTime,

    playing: bool,
    eos: bool,

    srcresult: Result<gst::FlowSuccess, gst::FlowError>,
    clock_id: Option<gst::SingleShotClockId>,

    in_segment: Option<gst::FormattedSegment<gst::ClockTime>>,
    pending_segment: Option<gst::FormattedSegment<gst::ClockTime>>,
    out_segment: Option<gst::FormattedSegment<gst::ClockTime>>,

    in_caps: Option<gst::Caps>,
    pending_caps: Option<gst::Caps>,
    in_audio_info: Option<gst_audio::AudioInfo>,
    out_audio_info: Option<gst_audio::AudioInfo>,

    queue: VecDeque<Item>,
    buffer_queued: bool,
    out_buffer: Option<gst::Buffer>,

    in_timestamp: Option<Timestamps>,
    out_timestamp: Option<Timestamps>,

    num_in: u64,
    num_drop: u64,
    num_out: u64,
    num_duplicate: u64,
}

const PROP_LATENCY: &str = "latency";
const PROP_LATE_THRESHOLD: &str = "late-threshold";
const PROP_SINGLE_SEGMENT: &str = "single-segment";

const PROP_IN: &str = "in";
const PROP_DROP: &str = "drop";
const PROP_OUT: &str = "out";
const PROP_DUPLICATE: &str = "duplicate";

const DEFAULT_LATENCY: gst::ClockTime = gst::ClockTime::ZERO;
const DEFAULT_DURATION: gst::ClockTime = gst::ClockTime::from_mseconds(100);
const MINIMUM_LATE_THRESHOLD: gst::ClockTime = gst::ClockTime::ZERO;
const DEFAULT_LATE_THRESHOLD: Option<gst::ClockTime> = Some(gst::ClockTime::from_seconds(2));

impl Default for State {
    fn default() -> Self {
        Self {
            latency: DEFAULT_LATENCY,
            late_threshold: DEFAULT_LATE_THRESHOLD,
            single_segment: false,
            upstream_latency: None,
            fallback_duration: DEFAULT_DURATION,
            playing: false,
            eos: false,
            srcresult: Err(gst::FlowError::Flushing),
            clock_id: None,
            in_segment: None,
            pending_segment: None,
            out_segment: None,
            in_caps: None,
            pending_caps: None,
            in_audio_info: None,
            out_audio_info: None,
            queue: VecDeque::with_capacity(32),
            buffer_queued: false,
            out_buffer: None,
            in_timestamp: None,
            out_timestamp: None,
            num_in: 0,
            num_drop: 0,
            num_out: 0,
            num_duplicate: 0,
        }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for LiveSync {
    const NAME: &'static str = "GstLiveSync";
    type Type = super::LiveSync;
    type ParentType = gst::Element;

    fn with_class(class: &Self::Class) -> Self {
        let sinkpad =
            gst::Pad::builder_with_template(&class.pad_template("sink").unwrap(), Some("sink"))
                .activatemode_function(|pad, parent, mode, active| {
                    Self::catch_panic_pad_function(
                        parent,
                        || Err(gst::loggable_error!(CAT, "sink_activate_mode panicked")),
                        |livesync| livesync.sink_activate_mode(pad, mode, active),
                    )
                })
                .event_function(|pad, parent, event| {
                    Self::catch_panic_pad_function(
                        parent,
                        || false,
                        |livesync| livesync.sink_event(pad, event),
                    )
                })
                .query_function(|pad, parent, query| {
                    Self::catch_panic_pad_function(
                        parent,
                        || false,
                        |livesync| livesync.sink_query(pad, query),
                    )
                })
                .chain_function(|pad, parent, buffer| {
                    Self::catch_panic_pad_function(
                        parent,
                        || Err(gst::FlowError::Error),
                        |livesync| livesync.sink_chain(pad, buffer),
                    )
                })
                .flags(
                    gst::PadFlags::PROXY_CAPS
                        | gst::PadFlags::PROXY_ALLOCATION
                        | gst::PadFlags::PROXY_SCHEDULING,
                )
                .build();

        let srcpad =
            gst::Pad::builder_with_template(&class.pad_template("src").unwrap(), Some("src"))
                .activatemode_function(|pad, parent, mode, active| {
                    Self::catch_panic_pad_function(
                        parent,
                        || Err(gst::loggable_error!(CAT, "src_activate_mode panicked")),
                        |livesync| livesync.src_activate_mode(pad, mode, active),
                    )
                })
                .event_function(|pad, parent, event| {
                    Self::catch_panic_pad_function(
                        parent,
                        || false,
                        |livesync| livesync.src_event(pad, event),
                    )
                })
                .query_function(|pad, parent, query| {
                    Self::catch_panic_pad_function(
                        parent,
                        || false,
                        |livesync| livesync.src_query(pad, query),
                    )
                })
                .flags(
                    gst::PadFlags::PROXY_CAPS
                        | gst::PadFlags::PROXY_ALLOCATION
                        | gst::PadFlags::PROXY_SCHEDULING,
                )
                .build();

        Self {
            state: Default::default(),
            cond: Condvar::new(),
            sinkpad,
            srcpad,
        }
    }
}

impl ObjectImpl for LiveSync {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<[glib::ParamSpec; 7]> = Lazy::new(|| {
            [
                glib::ParamSpecUInt64::builder(PROP_LATENCY)
                    .nick("Latency")
                    .blurb(
                        "Additional latency to allow upstream to take longer to \
                         produce buffers for the current position (in nanoseconds)",
                    )
                    .maximum(i64::MAX as u64)
                    .default_value(DEFAULT_LATENCY.into_glib())
                    .mutable_playing()
                    .build(),
                glib::ParamSpecUInt64::builder(PROP_LATE_THRESHOLD)
                    .nick("Late threshold")
                    .blurb(
                        "Maximum time spent (in nanoseconds) before \
                         accepting one late buffer; -1 = never",
                    )
                    .minimum(MINIMUM_LATE_THRESHOLD.into_glib())
                    .default_value(DEFAULT_LATE_THRESHOLD.into_glib())
                    .mutable_playing()
                    .build(),
                glib::ParamSpecBoolean::builder(PROP_SINGLE_SEGMENT)
                    .nick("Single segment")
                    .blurb("Timestamp buffers and eat segments so as to appear as one segment")
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt64::builder(PROP_IN)
                    .nick("Frames input")
                    .blurb("Number of incoming frames accepted")
                    .read_only()
                    .build(),
                glib::ParamSpecUInt64::builder(PROP_DROP)
                    .nick("Frames dropped")
                    .blurb("Number of incoming frames dropped")
                    .read_only()
                    .build(),
                glib::ParamSpecUInt64::builder(PROP_OUT)
                    .nick("Frames output")
                    .blurb("Number of outgoing frames produced")
                    .read_only()
                    .build(),
                glib::ParamSpecUInt64::builder(PROP_DUPLICATE)
                    .nick("Frames duplicated")
                    .blurb("Number of outgoing frames duplicated")
                    .read_only()
                    .build(),
            ]
        });

        PROPERTIES.as_ref()
    }

    fn constructed(&self) {
        self.parent_constructed();

        let obj = self.obj();
        obj.add_pad(&self.sinkpad).unwrap();
        obj.add_pad(&self.srcpad).unwrap();
        obj.set_element_flags(gst::ElementFlags::PROVIDE_CLOCK | gst::ElementFlags::REQUIRE_CLOCK);
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        let mut state = self.state.lock();
        match pspec.name() {
            PROP_LATENCY => {
                state.latency = value.get().unwrap();
                state.update_fallback_duration();
                let _ = self.obj().post_message(gst::message::Latency::new());
            }

            PROP_LATE_THRESHOLD => {
                state.late_threshold = value.get().unwrap();
            }

            PROP_SINGLE_SEGMENT => {
                state.single_segment = value.get().unwrap();
            }

            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        let state = self.state.lock();
        match pspec.name() {
            PROP_LATENCY => state.latency.to_value(),
            PROP_LATE_THRESHOLD => state.late_threshold.to_value(),
            PROP_SINGLE_SEGMENT => state.single_segment.to_value(),
            PROP_IN => state.num_in.to_value(),
            PROP_DROP => state.num_drop.to_value(),
            PROP_OUT => state.num_out.to_value(),
            PROP_DUPLICATE => state.num_duplicate.to_value(),
            _ => unimplemented!(),
        }
    }
}

impl GstObjectImpl for LiveSync {}

impl ElementImpl for LiveSync {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "Live Synchronizer",
                "Filter",
                "Outputs livestream, inserting gap frames when input lags",
                "Jan Alexander Steffens (heftig) <jan.steffens@ltnglobal.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: Lazy<[gst::PadTemplate; 2]> = Lazy::new(|| {
            let caps = gst::Caps::new_any();

            [
                gst::PadTemplate::new(
                    "sink",
                    gst::PadDirection::Sink,
                    gst::PadPresence::Always,
                    &caps,
                )
                .unwrap(),
                gst::PadTemplate::new(
                    "src",
                    gst::PadDirection::Src,
                    gst::PadPresence::Always,
                    &caps,
                )
                .unwrap(),
            ]
        });

        PAD_TEMPLATES.as_ref()
    }

    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        gst::trace!(CAT, imp: self, "Changing state {:?}", transition);

        if transition == gst::StateChange::PausedToPlaying {
            let mut state = self.state.lock();
            state.playing = true;
            self.cond.notify_all();
        }

        let success = self.parent_change_state(transition)?;

        if transition == gst::StateChange::PlayingToPaused {
            let mut state = self.state.lock();
            state.playing = false;
        }

        match (transition, success) {
            (
                gst::StateChange::ReadyToPaused | gst::StateChange::PlayingToPaused,
                gst::StateChangeSuccess::Success,
            ) => Ok(gst::StateChangeSuccess::NoPreroll),
            (_, s) => Ok(s),
        }
    }

    fn provide_clock(&self) -> Option<gst::Clock> {
        Some(gst::SystemClock::obtain())
    }
}

impl State {
    /// Calculate the running time the buffer covers, including latency
    fn ts_range(
        &self,
        buf: &gst::BufferRef,
        segment: &gst::FormattedSegment<gst::ClockTime>,
    ) -> Option<Timestamps> {
        let mut timestamp_start = buf.dts_or_pts()?;

        if !self.single_segment {
            timestamp_start = segment
                .to_running_time(timestamp_start)
                .unwrap_or(gst::ClockTime::ZERO);
            timestamp_start += self.latency + self.upstream_latency.unwrap();
        } else {
            timestamp_start += self.upstream_latency.unwrap();
            timestamp_start = timestamp_start.saturating_sub(SEGMENT_OFFSET);
        }

        Some(Timestamps {
            start: timestamp_start,
            end: timestamp_start + buf.duration().unwrap(),
        })
    }

    fn update_fallback_duration(&mut self) {
        self.fallback_duration = self
            // First, try 1/framerate from the caps
            .in_caps
            .as_ref()
            .and_then(|c| c.structure(0))
            .filter(|s| s.name().starts_with("video/"))
            .and_then(|s| s.get::<gst::Fraction>("framerate").ok())
            .and_then(|framerate| {
                gst::ClockTime::SECOND
                    .mul_div_round(framerate.numer() as u64, framerate.denom() as u64)
            })
            .filter(|&dur| dur > 8.mseconds() && dur < 10.seconds())
            // Otherwise, half the configured latency
            .or_else(|| Some(self.latency / 2))
            // In any case, don't allow a zero duration
            .filter(|&dur| dur > gst::ClockTime::ZERO)
            // Safe default
            .unwrap_or(DEFAULT_DURATION);
    }
}

impl LiveSync {
    fn sink_activate_mode(
        &self,
        pad: &gst::Pad,
        mode: gst::PadMode,
        active: bool,
    ) -> Result<(), gst::LoggableError> {
        if mode != gst::PadMode::Push {
            return Err(gst::loggable_error!(CAT, "Wrong scheduling mode"));
        }

        if active {
            let mut state = self.state.lock();
            state.srcresult = Ok(gst::FlowSuccess::Ok);
            state.eos = false;
            state.in_timestamp = None;
            state.num_in = 0;
            state.num_drop = 0;
            state.in_segment = None;
        } else {
            {
                let mut state = self.state.lock();
                state.srcresult = Err(gst::FlowError::Flushing);
                if let Some(clock_id) = state.clock_id.take() {
                    clock_id.unschedule();
                }
                state.pending_caps = None;
                state.out_audio_info = None;
                state.out_buffer = None;
                self.cond.notify_all();
            }

            let lock = pad.stream_lock();
            {
                let mut state = self.state.lock();
                state.in_caps = None;
                state.in_audio_info = None;
                state.queue.clear();
                state.buffer_queued = false;
                state.update_fallback_duration();
            }
            drop(lock);
        }

        Ok(())
    }

    fn src_activate_mode(
        &self,
        pad: &gst::Pad,
        mode: gst::PadMode,
        active: bool,
    ) -> Result<(), gst::LoggableError> {
        if mode != gst::PadMode::Push {
            return Err(gst::loggable_error!(CAT, "Wrong scheduling mode"));
        }

        if active {
            let ret;

            {
                let mut state = self.state.lock();

                state.srcresult = Ok(gst::FlowSuccess::Ok);
                state.pending_segment = None;
                state.out_segment = None;
                state.out_timestamp = None;
                state.num_out = 0;
                state.num_duplicate = 0;

                ret = self.start_src_task().map_err(Into::into);
            }

            ret
        } else {
            {
                let mut state = self.state.lock();
                state.srcresult = Err(gst::FlowError::Flushing);
                if let Some(clock_id) = state.clock_id.take() {
                    clock_id.unschedule();
                }
                state.pending_caps = None;
                state.out_audio_info = None;
                state.out_buffer = None;
                self.cond.notify_all();
            }

            pad.stop_task().map_err(Into::into)
        }
    }

    fn sink_event(&self, pad: &gst::Pad, mut event: gst::Event) -> bool {
        {
            let state = self.state.lock();
            if state.single_segment {
                let event = event.make_mut();
                let latency = state.latency.nseconds() as i64;
                event.set_running_time_offset(event.running_time_offset() + latency);
            }
        }

        match event.view() {
            gst::EventView::FlushStart(_) => {
                let ret = self.srcpad.push_event(event);

                {
                    let mut state = self.state.lock();
                    state.srcresult = Err(gst::FlowError::Flushing);
                    if let Some(clock_id) = state.clock_id.take() {
                        clock_id.unschedule();
                    }
                    self.cond.notify_all();
                }

                let _ = self.srcpad.pause_task();
                return ret;
            }

            gst::EventView::FlushStop(_) => {
                let ret = self.srcpad.push_event(event);

                let mut state = self.state.lock();
                state.srcresult = Ok(gst::FlowSuccess::Ok);
                state.eos = false;
                state.in_segment = None;
                state.pending_segment = None;
                state.out_segment = None;
                state.in_caps = None;
                state.pending_caps = None;
                state.in_audio_info = None;
                state.out_audio_info = None;
                state.queue.clear();
                state.buffer_queued = false;
                state.out_buffer = None;
                state.update_fallback_duration();

                let _ = self.start_src_task();
                return ret;
            }

            gst::EventView::StreamStart(_) => {
                let mut state = self.state.lock();
                state.srcresult = Ok(gst::FlowSuccess::Ok);
                state.eos = false;
            }

            gst::EventView::Segment(e) => {
                let segment = match e.segment().downcast_ref() {
                    Some(s) => s,
                    None => {
                        gst::error!(CAT, imp: self, "Got non-TIME segment");
                        return false;
                    }
                };

                let mut state = self.state.lock();
                state.in_segment = Some(segment.clone());
            }

            gst::EventView::Gap(_) => {
                gst::debug!(CAT, imp: self, "Got gap event");
                return true;
            }

            gst::EventView::Eos(_) => {
                let mut state = self.state.lock();

                if let Err(err) = state.srcresult {
                    if matches!(err, gst::FlowError::Flushing | gst::FlowError::Eos) {
                        self.flow_error(err);
                    }
                }

                state.eos = true;
            }

            gst::EventView::Caps(c) => {
                let caps = c.caps_owned();

                let audio_info = match audio_info_from_caps(&caps) {
                    Ok(ai) => ai,
                    Err(e) => {
                        gst::error!(CAT, imp: self, "Failed to parse audio caps: {}", e);
                        return false;
                    }
                };

                let mut state = self.state.lock();
                state.in_caps = Some(caps);
                state.in_audio_info = audio_info;
                state.update_fallback_duration();
            }

            _ => {}
        }

        if !event.is_serialized() {
            return gst::Pad::event_default(pad, Some(&*self.obj()), event);
        }

        let mut state = self.state.lock();
        if state.srcresult.is_err() {
            return false;
        }

        gst::trace!(CAT, imp: self, "Queueing {:?}", event);
        state.queue.push_back(Item::Event(event));
        self.cond.notify_all();

        true
    }

    fn src_event(&self, pad: &gst::Pad, mut event: gst::Event) -> bool {
        {
            let state = self.state.lock();
            if state.single_segment {
                let event = event.make_mut();
                let latency = state.latency.nseconds() as i64;
                event.set_running_time_offset(event.running_time_offset() - latency);
            }
        }

        match event.view() {
            gst::EventView::Reconfigure(_) => {
                {
                    let mut state = self.state.lock();
                    if state.srcresult == Err(gst::FlowError::NotLinked) {
                        state.srcresult = Ok(gst::FlowSuccess::Ok);
                        let _ = self.start_src_task();
                    }
                }
                self.sinkpad.push_event(event)
            }

            _ => gst::Pad::event_default(pad, Some(&*self.obj()), event),
        }
    }

    fn sink_query(&self, pad: &gst::Pad, query: &mut gst::QueryRef) -> bool {
        if query.is_serialized() {
            let (sender, receiver) = mpsc::sync_channel(1);

            let mut state = self.state.lock();
            if state.srcresult.is_err() {
                return false;
            }

            gst::trace!(CAT, imp: self, "Queueing {:?}", query);
            state
                .queue
                .push_back(Item::Query(std::ptr::NonNull::from(query), sender));
            self.cond.notify_all();
            drop(state);

            receiver.recv().unwrap_or(false)
        } else {
            gst::Pad::query_default(pad, Some(&*self.obj()), query)
        }
    }

    fn src_query(&self, pad: &gst::Pad, query: &mut gst::QueryRef) -> bool {
        match query.view_mut() {
            gst::QueryViewMut::Latency(_) => {
                if !gst::Pad::query_default(pad, Some(&*self.obj()), query) {
                    return false;
                }

                let q = match query.view_mut() {
                    gst::QueryViewMut::Latency(q) => q,
                    _ => unreachable!(),
                };

                let mut state = self.state.lock();
                let latency = state.latency;

                let (_live, min, max) = q.result();
                q.set(true, min + latency, max.map(|max| max + latency));

                state.upstream_latency = Some(min);
                true
            }

            _ => gst::Pad::query_default(pad, Some(&*self.obj()), query),
        }
    }

    fn sink_chain(
        &self,
        _pad: &gst::Pad,
        mut buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        gst::trace!(CAT, imp: self, "incoming {:?}", buffer);

        let mut state = self.state.lock();

        if state.upstream_latency.is_none() {
            gst::debug!(CAT, imp: self, "Have no upstream latency yet, querying");
            let mut q = gst::query::Latency::new();
            if MutexGuard::unlocked(&mut state, || self.sinkpad.peer_query(&mut q)) {
                let (live, min, max) = q.result();

                gst::debug!(
                    CAT,
                    imp: self,
                    "Latency query response: live {} min {} max {}",
                    live,
                    min,
                    max.display()
                );

                state.upstream_latency = Some(min);
            } else {
                gst::warning!(
                    CAT,
                    imp: self,
                    "Can't query upstream latency -- assuming zero"
                );
            }
        }

        while state.srcresult.is_ok() && state.buffer_queued {
            self.cond.wait(&mut state);
        }
        state.srcresult?;

        let buf_mut = buffer.make_mut();

        if buf_mut.pts().is_none() {
            gst::warning!(CAT, imp: self, "incoming buffer has no timestamps");
        }

        if let Some(audio_info) = &state.in_audio_info {
            let buf_duration = buf_mut.duration().unwrap_or_default();
            if let Some(calc_duration) = audio_info
                .convert::<Option<gst::ClockTime>>(Some(gst::format::Bytes::from_usize(
                    buf_mut.size(),
                )))
                .flatten()
            {
                let diff = if buf_duration < calc_duration {
                    calc_duration - buf_duration
                } else {
                    buf_duration - calc_duration
                };

                if diff.nseconds() > 1 {
                    gst::warning!(
                        CAT,
                        imp: self,
                        "Correcting duration on audio buffer from {} to {}",
                        buf_duration,
                        calc_duration,
                    );
                    buf_mut.set_duration(calc_duration);
                }
            } else {
                gst::debug!(
                    CAT,
                    imp: self,
                    "Failed to calculate duration of {:?}",
                    buf_mut,
                );
            }
        }

        // At this stage we should really really have a segment
        let segment = state.in_segment.as_ref().ok_or(gst::FlowError::Error)?;

        if state.single_segment {
            let dts = segment
                .to_running_time_full(buf_mut.dts())
                .map(|r| r + SEGMENT_OFFSET)
                .and_then(|r| r.positive());
            let pts = segment
                .to_running_time_full(buf_mut.pts())
                .map(|r| r + SEGMENT_OFFSET)
                .and_then(|r| r.positive())
                .or_else(|| {
                    self.obj()
                        .current_running_time()
                        .map(|r| r + SEGMENT_OFFSET)
                });

            buf_mut.set_dts(dts.map(|t| t + state.latency));
            buf_mut.set_pts(pts.map(|t| t + state.latency));
        }

        if buf_mut.duration().is_none() {
            gst::debug!(CAT, imp: self, "incoming buffer without duration");
            buf_mut.set_duration(Some(state.fallback_duration));
        }

        if state
            .out_buffer
            .as_ref()
            .map_or(false, |b| b.flags().contains(gst::BufferFlags::GAP))
        {
            // We are done bridging a gap, so mark it as DISCONT instead
            buf_mut.unset_flags(gst::BufferFlags::GAP);
            buf_mut.set_flags(gst::BufferFlags::DISCONT);
        }

        let mut timestamp = state.ts_range(buf_mut, segment);
        let lateness = self.buffer_is_backwards(&state, timestamp);
        match lateness {
            BufferLateness::OnTime => {}

            BufferLateness::LateUnderThreshold => {
                gst::debug!(CAT, imp: self, "discarding late {:?}", buf_mut);
                state.num_drop += 1;
                return Ok(gst::FlowSuccess::Ok);
            }

            BufferLateness::LateOverThreshold => {
                gst::debug!(CAT, imp: self, "accepting late {:?}", buf_mut);

                let prev = state.out_buffer.as_ref().unwrap();
                let prev_duration = prev.duration().unwrap();

                if let Some(audio_info) = &state.in_audio_info {
                    let mut map_info = buf_mut.map_writable().map_err(|e| {
                        gst::error!(CAT, imp: self, "Failed to map buffer: {}", e);
                        gst::FlowError::Error
                    })?;

                    audio_info
                        .format_info()
                        .fill_silence(map_info.as_mut_slice());
                } else {
                    buf_mut.set_duration(Some(state.fallback_duration));
                }

                buf_mut.set_dts(prev.dts().map(|t| t + prev_duration));
                buf_mut.set_pts(prev.pts().map(|t| t + prev_duration));
                buf_mut.set_flags(gst::BufferFlags::GAP);

                timestamp = state.ts_range(buf_mut, state.out_segment.as_ref().unwrap());
            }
        }

        gst::trace!(CAT, imp: self, "Queueing {:?} ({:?})", buffer, lateness);
        state.queue.push_back(Item::Buffer(buffer, lateness));
        state.buffer_queued = true;
        state.in_timestamp = timestamp;
        state.num_in += 1;
        self.cond.notify_all();

        Ok(gst::FlowSuccess::Ok)
    }

    fn start_src_task(&self) -> Result<(), glib::BoolError> {
        self.srcpad.start_task({
            let pad = self.srcpad.downgrade();
            move || {
                let pad = pad.upgrade().unwrap();
                let parent = pad.parent_element().unwrap();
                let livesync = parent.downcast_ref::<super::LiveSync>().unwrap();
                let ret = livesync.imp().src_loop(&pad);

                if !ret {
                    gst::log!(CAT, obj: &parent, "Loop stopping");
                    let _ = pad.pause_task();
                }
            }
        })
    }

    fn src_loop(&self, pad: &gst::Pad) -> bool {
        let mut err = match self.src_loop_inner() {
            Ok(_) => return true,
            Err(e) => e,
        };
        let eos;

        {
            let mut state = self.state.lock();

            match state.srcresult {
                // Can be set to Flushing by another thread
                Err(e) => err = e,

                // Communicate our flow return
                Ok(_) => state.srcresult = Err(err),
            }
            eos = state.eos;
            state.clock_id = None;

            self.cond.notify_all();
        }

        if eos && !matches!(err, gst::FlowError::Flushing | gst::FlowError::Eos) {
            self.flow_error(err);
            pad.push_event(gst::event::Eos::new());
        }

        false
    }

    fn src_loop_inner(&self) -> Result<gst::FlowSuccess, gst::FlowError> {
        let mut state = self.state.lock();
        while state.srcresult.is_ok()
            && (!state.playing || (state.queue.is_empty() && state.out_buffer.is_none()))
        {
            self.cond.wait(&mut state);
        }
        state.srcresult?;

        let in_item = state.queue.pop_front();
        gst::trace!(CAT, imp: self, "Unqueueing {:?}", in_item);

        let in_buffer = match in_item {
            None => None,

            Some(Item::Buffer(buffer, lateness)) => {
                if self.buffer_is_early(&state, state.in_timestamp) {
                    // Try this buffer again on the next iteration
                    state.queue.push_front(Item::Buffer(buffer, lateness));
                    None
                } else {
                    state.buffer_queued = false;
                    Some((buffer, lateness))
                }
            }

            Some(Item::Event(event)) => {
                let mut push = true;

                match event.view() {
                    gst::EventView::Segment(e) => {
                        let segment = e.segment().downcast_ref().unwrap();
                        state.pending_segment = Some(segment.clone());
                        push = false;
                    }

                    gst::EventView::Caps(e) => {
                        state.pending_caps = Some(e.caps_owned());
                        state.update_fallback_duration();
                        push = false;
                    }

                    _ => {}
                }

                self.cond.notify_all();
                drop(state);

                if push {
                    self.srcpad.push_event(event);
                }

                return Ok(gst::FlowSuccess::Ok);
            }

            Some(Item::Query(mut query, sender)) => {
                self.cond.notify_all();
                drop(state);

                // SAFETY: The other thread is waiting for us to handle the query
                let res = self.srcpad.peer_query(unsafe { query.as_mut() });
                sender.send(res).ok();

                return Ok(gst::FlowSuccess::Ok);
            }
        };

        let duplicate;
        let mut caps = None;
        let mut segment = None;
        if let Some((buffer, lateness)) = in_buffer {
            state.out_buffer = Some(buffer);
            state.out_timestamp = state.in_timestamp;

            caps = state.pending_caps.take();
            segment = state.pending_segment.take();

            duplicate = lateness != BufferLateness::OnTime;
            self.cond.notify_all();
        } else {
            // Work around borrow checker
            let State {
                fallback_duration,
                out_buffer: ref mut buffer,
                out_audio_info: ref audio_info,
                ..
            } = *state;
            gst::debug!(CAT, imp: self, "repeating {:?}", buffer);

            let buffer = buffer.as_mut().unwrap().make_mut();
            let prev_duration = buffer.duration().unwrap();

            if let Some(audio_info) = audio_info {
                if !buffer.flags().contains(gst::BufferFlags::GAP) {
                    let mut map_info = buffer.map_writable().map_err(|e| {
                        gst::error!(CAT, imp: self, "Failed to map buffer: {}", e);
                        gst::FlowError::Error
                    })?;

                    audio_info
                        .format_info()
                        .fill_silence(map_info.as_mut_slice());
                }
            } else {
                buffer.set_duration(Some(fallback_duration));
            }

            buffer.set_dts(buffer.dts().map(|t| t + prev_duration));
            buffer.set_pts(buffer.pts().map(|t| t + prev_duration));
            buffer.set_flags(gst::BufferFlags::GAP);
            buffer.unset_flags(gst::BufferFlags::DISCONT);

            state.out_timestamp = state.ts_range(
                state.out_buffer.as_ref().unwrap(),
                state.out_segment.as_ref().unwrap(),
            );
            duplicate = true;
        };

        let buffer = state.out_buffer.clone().unwrap();
        let sync_ts = state
            .out_timestamp
            .map_or(gst::ClockTime::ZERO, |t| t.start);

        if let Some(caps) = caps {
            gst::debug!(CAT, imp: self, "Sending new caps: {}", caps);

            let event = gst::event::Caps::new(&caps);
            MutexGuard::unlocked(&mut state, || self.srcpad.push_event(event));
            state.srcresult?;

            state.out_audio_info = audio_info_from_caps(&caps).unwrap();
        }

        if let Some(segment) = segment {
            if !state.single_segment {
                gst::debug!(CAT, imp: self, "Forwarding segment: {:?}", segment);

                let event = gst::event::Segment::new(&segment);
                MutexGuard::unlocked(&mut state, || self.srcpad.push_event(event));
                state.srcresult?;
            } else if state.out_segment.is_none() {
                // Create live segment
                let mut live_segment = gst::FormattedSegment::<gst::ClockTime>::new();
                live_segment.set_start(sync_ts + SEGMENT_OFFSET);
                live_segment.set_base(sync_ts);
                live_segment.set_time(sync_ts);
                live_segment.set_position(sync_ts + SEGMENT_OFFSET);

                gst::debug!(CAT, imp: self, "Sending new segment: {:?}", live_segment);

                let event = gst::event::Segment::new(&live_segment);
                MutexGuard::unlocked(&mut state, || self.srcpad.push_event(event));
                state.srcresult?;
            }

            state.out_segment = Some(segment);
        }

        {
            let element = self.obj();

            let base_time = element.base_time().ok_or_else(|| {
                gst::error!(CAT, imp: self, "Missing base time");
                gst::FlowError::Flushing
            })?;

            let clock = element.clock().ok_or_else(|| {
                gst::error!(CAT, imp: self, "Missing clock");
                gst::FlowError::Flushing
            })?;

            let clock_id = clock.new_single_shot_id(base_time + sync_ts);
            state.clock_id = Some(clock_id.clone());

            gst::trace!(
                CAT,
                imp: self,
                "Waiting for clock to reach {}",
                clock_id.time(),
            );

            let (res, _) = MutexGuard::unlocked(&mut state, || clock_id.wait());
            gst::trace!(CAT, imp: self, "Clock returned {res:?}",);

            if res == Err(gst::ClockError::Unscheduled) {
                return Err(gst::FlowError::Flushing);
            }

            state.srcresult?;
            state.clock_id = None;
        }

        state.num_out += 1;
        if duplicate {
            state.num_duplicate += 1;
        }

        drop(state);

        gst::trace!(CAT, imp: self, "Pushing {buffer:?}");
        self.srcpad.push(buffer)
    }

    fn buffer_is_backwards(&self, state: &State, timestamp: Option<Timestamps>) -> BufferLateness {
        let timestamp = match timestamp {
            Some(t) => t,
            None => return BufferLateness::OnTime,
        };

        let out_timestamp = match state.out_timestamp {
            Some(t) => t,
            None => return BufferLateness::OnTime,
        };

        if timestamp.end > out_timestamp.end {
            return BufferLateness::OnTime;
        }

        gst::debug!(
            CAT,
            imp: self,
            "Timestamp regresses: buffer ends at {}, expected {}",
            timestamp.end,
            out_timestamp.end,
        );

        let late_threshold = match state.late_threshold {
            Some(gst::ClockTime::ZERO) => return BufferLateness::LateOverThreshold,
            Some(t) => t,
            None => return BufferLateness::LateUnderThreshold,
        };

        let in_timestamp = match state.in_timestamp {
            Some(t) => t,
            None => return BufferLateness::LateUnderThreshold,
        };

        if timestamp.start > in_timestamp.end + late_threshold {
            BufferLateness::LateOverThreshold
        } else {
            BufferLateness::LateUnderThreshold
        }
    }

    fn buffer_is_early(&self, state: &State, timestamp: Option<Timestamps>) -> bool {
        let timestamp = match timestamp {
            Some(t) => t,
            None => return false,
        };

        let out_timestamp = match state.out_timestamp {
            Some(t) => t,
            None => return false,
        };

        let slack = state
            .out_buffer
            .as_deref()
            .map_or(gst::ClockTime::ZERO, |b| b.duration().unwrap());

        if timestamp.start < out_timestamp.end + slack {
            return false;
        }

        gst::debug!(
            CAT,
            imp: self,
            "Timestamp is too early: buffer starts at {}, expected {}",
            timestamp.start,
            out_timestamp.end,
        );

        true
    }

    /// Produces a message like GST_ELEMENT_FLOW_ERROR does
    fn flow_error(&self, err: gst::FlowError) {
        let details = gst::Structure::builder("details")
            .field("flow-return", err.into_glib())
            .build();
        gst::element_imp_error!(
            self,
            gst::StreamError::Failed,
            ("Internal data flow error."),
            ["streaming task paused, reason {} ({:?})", err, err],
            details: details
        );
    }
}
