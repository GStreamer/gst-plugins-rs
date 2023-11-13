// SPDX-License-Identifier: MPL-2.0

use atomic_refcell::AtomicRefCell;
use gst::glib::once_cell::sync::Lazy;
use gst::prelude::*;
use gst::subclass::prelude::*;
use gst_video::prelude::*;

use std::{cmp, collections::VecDeque, sync::Mutex};

use byte_slice_cast::*;

use crate::{
    ndi_cc_meta::NDICCMetaDecoder,
    ndisrcmeta::{self, Buffer},
    ndisys, TimestampMode,
};

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "ndisrcdemux",
        gst::DebugColorFlags::empty(),
        Some("NewTek NDI Source Demuxer"),
    )
});

struct State {
    combiner: gst_base::UniqueFlowCombiner,
    video_pad: Option<gst::Pad>,
    video_info: Option<VideoInfo>,
    video_caps: Option<gst::Caps>,
    video_buffer_pool: Option<gst::BufferPool>,

    audio_pad: Option<gst::Pad>,
    audio_info: Option<AudioInfo>,
    audio_caps: Option<gst::Caps>,
    // Only set for raw audio
    audio_info_non_interleaved: Option<gst_audio::AudioInfo>,
    audio_caps_non_interleaved: Option<gst::Caps>,
    audio_non_interleaved: bool,

    ndi_cc_decoder: Option<NDICCMetaDecoder>,
    pending_metadata: Vec<crate::ndi::MetadataFrame>,

    // Audio/video time observations
    timestamp_mode: TimestampMode,
    observations_timestamp: [Observations; 2],
    observations_timecode: [Observations; 2],
}

impl Default for State {
    fn default() -> State {
        State {
            combiner: gst_base::UniqueFlowCombiner::new(),

            video_pad: None,
            video_info: None,
            video_caps: None,
            video_buffer_pool: None,

            audio_pad: None,
            audio_info: None,
            audio_caps: None,
            audio_info_non_interleaved: None,
            audio_caps_non_interleaved: None,
            audio_non_interleaved: false,

            ndi_cc_decoder: None,
            pending_metadata: Vec::new(),

            timestamp_mode: TimestampMode::Auto,
            observations_timestamp: [Observations::default(), Observations::default()],
            observations_timecode: [Observations::default(), Observations::default()],
        }
    }
}

pub struct NdiSrcDemux {
    sinkpad: gst::Pad,
    state: Mutex<State>,
}

#[glib::object_subclass]
impl ObjectSubclass for NdiSrcDemux {
    const NAME: &'static str = "GstNdiSrcDemux";
    type Type = super::NdiSrcDemux;
    type ParentType = gst::Element;

    fn with_class(klass: &Self::Class) -> Self {
        let templ = klass.pad_template("sink").unwrap();
        let sinkpad = gst::Pad::builder_from_template(&templ)
            .flags(gst::PadFlags::FIXED_CAPS)
            .chain_function(|pad, parent, buffer| {
                NdiSrcDemux::catch_panic_pad_function(
                    parent,
                    || Err(gst::FlowError::Error),
                    |self_| self_.sink_chain(pad, buffer),
                )
            })
            .event_function(|pad, parent, event| {
                NdiSrcDemux::catch_panic_pad_function(
                    parent,
                    || false,
                    |self_| self_.sink_event(pad, event),
                )
            })
            .build();

        Self {
            sinkpad,
            state: Mutex::new(State::default()),
        }
    }
}

impl ObjectImpl for NdiSrcDemux {
    fn constructed(&self) {
        self.parent_constructed();

        self.obj().add_pad(&self.sinkpad).unwrap();
    }
}

impl GstObjectImpl for NdiSrcDemux {}

impl ElementImpl for NdiSrcDemux {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "NewTek NDI Source Demuxer",
                "Demuxer/Audio/Video",
                "NewTek NDI source demuxer",
                "Sebastian Dröge <sebastian@centricular.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: Lazy<Vec<gst::PadTemplate>> = Lazy::new(|| {
            let sink_pad_template = gst::PadTemplate::new(
                "sink",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &gst::Caps::builder("application/x-ndi").build(),
            )
            .unwrap();

            let audio_src_pad_template = gst::PadTemplate::new(
                "audio",
                gst::PadDirection::Src,
                gst::PadPresence::Sometimes,
                &gst::Caps::new_any(),
            )
            .unwrap();

            let video_src_pad_template = gst::PadTemplate::new(
                "video",
                gst::PadDirection::Src,
                gst::PadPresence::Sometimes,
                &gst::Caps::new_any(),
            )
            .unwrap();

            vec![
                sink_pad_template,
                audio_src_pad_template,
                video_src_pad_template,
            ]
        });

        PAD_TEMPLATES.as_ref()
    }

    #[allow(clippy::single_match)]
    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        let res = self.parent_change_state(transition)?;

        match transition {
            gst::StateChange::PausedToReady => {
                let mut state = self.state.lock().unwrap();

                for pad in [state.audio_pad.take(), state.video_pad.take()]
                    .iter()
                    .flatten()
                {
                    self.obj().remove_pad(pad).unwrap();
                }

                if let Some(pool) = state.video_buffer_pool.take() {
                    let _ = pool.set_active(false);
                }

                *state = State::default();
            }
            _ => (),
        }

        Ok(res)
    }
}

impl NdiSrcDemux {
    fn sink_chain(
        &self,
        _pad: &gst::Pad,
        mut buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        gst::log!(CAT, imp: self, "Handling buffer {:?}", buffer);

        let mut meta = buffer
            .make_mut()
            .meta_mut::<ndisrcmeta::NdiSrcMeta>()
            .ok_or_else(|| {
                gst::error!(CAT, imp: self, "Buffer without NDI source meta");
                gst::FlowError::Error
            })?;

        let mut state = self.state.lock().unwrap();
        let ndi_buffer = meta.take_ndi_buffer();

        match ndi_buffer {
            Buffer::Audio { ref frame, .. } => {
                gst::debug!(CAT, imp: self, "Received audio frame {:?}", frame);

                let mut reconfigure = false;
                let info = self.create_audio_info(frame)?;
                if Some(&info) != state.audio_info.as_ref() {
                    let caps = info.to_caps().map_err(|_| {
                        gst::element_imp_error!(
                            self,
                            gst::ResourceError::Settings,
                            ["Invalid audio info received: {:?}", info]
                        );
                        gst::FlowError::NotNegotiated
                    })?;

                    gst::debug!(CAT, imp: self, "Audio caps changed to {}", caps);

                    #[allow(irrefutable_let_patterns)]
                    if let AudioInfo::Audio(ref info) = info {
                        let mut builder = gst_audio::AudioInfo::builder(
                            info.format(),
                            info.rate(),
                            info.channels(),
                        )
                        .layout(gst_audio::AudioLayout::NonInterleaved);

                        if let Some(positions) = info.positions() {
                            builder = builder.positions(positions);
                        }

                        let non_interleaved_info = builder.build().unwrap();
                        state.audio_caps_non_interleaved =
                            Some(non_interleaved_info.to_caps().unwrap());
                        state.audio_info_non_interleaved = Some(non_interleaved_info);
                    } else {
                        state.audio_non_interleaved = false;
                        state.audio_caps_non_interleaved = None;
                        state.audio_info_non_interleaved = None;
                    }

                    state.audio_info = Some(info);
                    state.audio_caps = Some(caps);
                    reconfigure = true;
                }

                let srcpad;
                if let Some(ref pad) = state.audio_pad {
                    srcpad = pad.clone();
                    reconfigure |= pad.check_reconfigure();
                } else {
                    gst::debug!(CAT, imp: self, "Adding audio pad");

                    let templ = self.obj().element_class().pad_template("audio").unwrap();
                    let pad = gst::Pad::builder_from_template(&templ)
                        .flags(gst::PadFlags::FIXED_CAPS)
                        .build();

                    state.audio_pad = Some(pad.clone());

                    let _ = pad.set_active(true);
                    state.combiner.add_pad(&pad);

                    let mut stored_caps = false;
                    self.sinkpad.sticky_events_foreach(|ev| {
                        if let gst::EventView::StreamStart(ev) = ev.view() {
                            let stream_start = gst::event::StreamStart::builder(&format!(
                                "{}/audio",
                                ev.stream_id()
                            ))
                            .seqnum(ev.seqnum())
                            .flags(ev.stream_flags())
                            .group_id(ev.group_id().unwrap_or_else(|| {
                                // This can't really happen as ndisrc would provide one!
                                gst::error!(CAT, imp: self, "Upstream provided no group id");
                                gst::GroupId::next()
                            }))
                            .build();

                            let _ = pad.store_sticky_event(&stream_start);
                        } else if ev.type_() < gst::EventType::Caps {
                            let _ = pad.store_sticky_event(ev);
                        } else if ev.type_() > gst::EventType::Caps {
                            // We store the interleaved caps for starters
                            let caps =
                                gst::event::Caps::builder(state.audio_caps.as_ref().unwrap())
                                    .build();
                            let _ = pad.store_sticky_event(&caps);
                            stored_caps = true;
                            let _ = pad.store_sticky_event(ev);
                        }

                        std::ops::ControlFlow::Continue(gst::EventForeachAction::Keep)
                    });

                    if !stored_caps {
                        // We store the interleaved caps for starters
                        let caps =
                            gst::event::Caps::builder(state.audio_caps.as_ref().unwrap()).build();
                        let _ = pad.store_sticky_event(&caps);
                    }

                    drop(state);

                    self.obj().add_pad(&pad).unwrap();
                    if self.obj().num_src_pads() == 2 {
                        self.obj().no_more_pads();
                    }

                    state = self.state.lock().unwrap();

                    srcpad = pad;
                    // No need to check for non-interleaved caps support below or update the caps
                    // because the same caps were already set above
                    reconfigure = state.audio_caps_non_interleaved.is_some();
                }

                if reconfigure {
                    // FIXME: As this is a demuxer we can't unfortunately do an allocation query
                    // downstream without risking deadlocks.

                    // Check if there's a peer downstream and if it supports the non-interleaved
                    // caps, otherwise fall back to the normal caps.
                    if let Some(caps) = state.audio_caps_non_interleaved.clone() {
                        drop(state);
                        let allowed_caps = srcpad.peer().map(|peer| peer.query_caps(Some(&caps)));
                        state = self.state.lock().unwrap();

                        gst::info!(CAT, imp: self, "Allowed audio caps {allowed_caps:?}");

                        state.audio_non_interleaved = allowed_caps
                            .map_or(false, |allowed_caps| allowed_caps.can_intersect(&caps));

                        gst::info!(
                            CAT,
                            imp: self,
                            "Non-interleaved caps{} supported",
                            if state.audio_non_interleaved { "" } else { "not" },
                        );
                    }

                    let caps = gst::event::Caps::builder(if state.audio_non_interleaved {
                        state.audio_caps_non_interleaved.as_ref().unwrap()
                    } else {
                        state.audio_caps.as_ref().unwrap()
                    })
                    .build();

                    let _ = srcpad.store_sticky_event(&caps);
                }
            }
            Buffer::Video { ref frame, .. } => {
                gst::debug!(CAT, imp: self, "Received video frame {:?}", frame);

                let mut reconfigure = false;
                let info = self.create_video_info(frame)?;
                if Some(&info) != state.video_info.as_ref() {
                    let caps = info.to_caps().map_err(|_| {
                        gst::element_imp_error!(
                            self,
                            gst::ResourceError::Settings,
                            ["Invalid video info received: {:?}", info]
                        );
                        gst::FlowError::NotNegotiated
                    })?;

                    if state.ndi_cc_decoder.is_none() {
                        state.ndi_cc_decoder = Some(NDICCMetaDecoder::new(info.width()));
                    }

                    gst::debug!(CAT, imp: self, "Video caps changed to {}", caps);
                    state.video_info = Some(info);
                    state.video_caps = Some(caps);
                    state.video_buffer_pool = None;
                    reconfigure = true;
                }

                let srcpad;
                if let Some(ref pad) = state.video_pad {
                    srcpad = pad.clone();
                    reconfigure |= pad.check_reconfigure();
                } else {
                    gst::debug!(CAT, imp: self, "Adding video pad");

                    let templ = self.obj().element_class().pad_template("video").unwrap();
                    let pad = gst::Pad::builder_from_template(&templ)
                        .flags(gst::PadFlags::FIXED_CAPS)
                        .build();

                    state.video_pad = Some(pad.clone());

                    let _ = pad.set_active(true);
                    state.combiner.add_pad(&pad);

                    let mut stored_caps = false;
                    self.sinkpad.sticky_events_foreach(|ev| {
                        if let gst::EventView::StreamStart(ev) = ev.view() {
                            let stream_start = gst::event::StreamStart::builder(&format!(
                                "{}/video",
                                ev.stream_id()
                            ))
                            .seqnum(ev.seqnum())
                            .flags(ev.stream_flags())
                            .group_id(ev.group_id().unwrap_or_else(|| {
                                // This can't really happen as ndisrc would provide one!
                                gst::error!(CAT, imp: self, "Upstream provided no group id");
                                gst::GroupId::next()
                            }))
                            .build();

                            let _ = pad.store_sticky_event(&stream_start);
                        } else if ev.type_() < gst::EventType::Caps {
                            let _ = pad.store_sticky_event(ev);
                        } else if ev.type_() > gst::EventType::Caps {
                            let caps =
                                gst::event::Caps::builder(state.video_caps.as_ref().unwrap())
                                    .build();
                            let _ = pad.store_sticky_event(&caps);
                            stored_caps = true;
                            let _ = pad.store_sticky_event(ev);
                        }

                        std::ops::ControlFlow::Continue(gst::EventForeachAction::Keep)
                    });

                    if !stored_caps {
                        let caps =
                            gst::event::Caps::builder(state.video_caps.as_ref().unwrap()).build();
                        let _ = pad.store_sticky_event(&caps);
                    }

                    drop(state);

                    self.obj().add_pad(&pad).unwrap();
                    if self.obj().num_src_pads() == 2 {
                        self.obj().no_more_pads();
                    }

                    state = self.state.lock().unwrap();

                    srcpad = pad;

                    // New caps were already stored above
                    reconfigure = false;
                }

                if reconfigure {
                    // FIXME: As this is a demuxer we can't unfortunately do an allocation query
                    // downstream without risking deadlocks.
                    let caps =
                        gst::event::Caps::builder(state.video_caps.as_ref().unwrap()).build();

                    let _ = srcpad.store_sticky_event(&caps);
                }
            }
            Buffer::Metadata { .. } => {
                // Nothing to be done here
            }
        }

        let srcpad;
        let buffer;
        match ndi_buffer {
            Buffer::Audio {
                frame,
                discont,
                receive_time_gst,
                receive_time_real,
            } => {
                srcpad = state.audio_pad.clone().unwrap();
                let (pts, duration, resync) = self
                    .calculate_audio_timestamp(
                        &mut state,
                        receive_time_gst,
                        receive_time_real,
                        &frame,
                    )
                    .ok_or_else(|| {
                        gst::debug!(CAT, imp: self, "Flushing, dropping buffer");
                        gst::FlowError::Flushing
                    })?;

                buffer = self.create_audio_buffer(&state, pts, duration, discont, resync, frame)?;

                gst::log!(CAT, imp: self, "Produced audio buffer {:?}", buffer);
            }
            Buffer::Video {
                frame,
                discont,
                receive_time_gst,
                receive_time_real,
            } => {
                srcpad = state.video_pad.clone().unwrap();
                let (pts, duration, resync) = self
                    .calculate_video_timestamp(
                        &mut state,
                        receive_time_gst,
                        receive_time_real,
                        &frame,
                    )
                    .ok_or_else(|| {
                        gst::debug!(CAT, imp: self, "Flushing, dropping buffer");
                        gst::FlowError::Flushing
                    })?;

                buffer =
                    self.create_video_buffer(&mut state, pts, duration, discont, resync, frame)?;

                gst::log!(CAT, imp: self, "Produced video buffer {:?}", buffer);
            }
            Buffer::Metadata { frame, .. } => {
                // Only closed caption meta are supported,
                // once parsed, they will be attached to the next video buffer
                if state.video_info.is_some() {
                    state.pending_metadata.push(frame);
                }
                return Ok(gst::FlowSuccess::Ok);
            }
        };
        drop(state);

        let res = srcpad.push(buffer);

        let mut state = self.state.lock().unwrap();
        state.combiner.update_pad_flow(&srcpad, res)
    }

    fn sink_event(&self, pad: &gst::Pad, event: gst::Event) -> bool {
        use gst::EventView;

        gst::log!(CAT, imp: self, "Handling event {:?}", event);
        match event.view() {
            EventView::StreamStart(ev) => {
                let state = self.state.lock().unwrap();
                let pads = [
                    ("audio", state.audio_pad.clone()),
                    ("video", state.video_pad.clone()),
                ];
                drop(state);

                for (stream_name, srcpad) in pads {
                    let Some(srcpad) = srcpad else {
                        continue;
                    };

                    let stream_start = gst::event::StreamStart::builder(&format!(
                        "{}/{stream_name}",
                        ev.stream_id()
                    ))
                    .seqnum(ev.seqnum())
                    .flags(ev.stream_flags())
                    .group_id(ev.group_id().unwrap_or_else(|| {
                        // This can't really happen as ndisrc would provide one!
                        gst::error!(CAT, imp: self, "Upstream provided no group id");
                        gst::GroupId::next()
                    }))
                    .build();

                    let _ = srcpad.push_event(stream_start);
                }

                return true;
            }
            EventView::Caps(_) => {
                return true;
            }
            EventView::Eos(_) => {
                if self.obj().num_src_pads() == 0 {
                    // error out on EOS if no src pad are available
                    gst::element_imp_error!(
                        self,
                        gst::StreamError::Demux,
                        ["EOS without available srcpad(s)"]
                    );
                }
            }
            _ => (),
        }
        gst::Pad::event_default(pad, Some(&*self.obj()), event)
    }
}

impl NdiSrcDemux {
    #[allow(clippy::too_many_arguments)]
    fn calculate_timestamp(
        &self,
        state: &mut State,
        is_audio: bool,
        receive_time_gst: gst::ClockTime,
        receive_time_real: gst::ClockTime,
        timestamp: i64,
        timecode: i64,
        duration: Option<gst::ClockTime>,
    ) -> Option<(gst::ClockTime, Option<gst::ClockTime>, bool)> {
        let timestamp = if timestamp == ndisys::NDIlib_recv_timestamp_undefined {
            gst::ClockTime::NONE
        } else {
            Some((timestamp as u64 * 100).nseconds())
        };
        let timecode = (timecode as u64 * 100).nseconds();

        gst::log!(
            CAT,
            imp: self,
            "Received frame with timecode {}, timestamp {}, duration {}, receive time {}, local time now {}",
            timecode,
            timestamp.display(),
            duration.display(),
            receive_time_gst.display(),
            receive_time_real,
        );

        let res_timestamp = state.observations_timestamp[usize::from(!is_audio)].process(
            self.obj().upcast_ref(),
            timestamp,
            receive_time_gst,
            duration,
        );

        let res_timecode = state.observations_timecode[usize::from(!is_audio)].process(
            self.obj().upcast_ref(),
            Some(timecode),
            receive_time_gst,
            duration,
        );

        let (pts, duration, discont) = match state.timestamp_mode {
            TimestampMode::ReceiveTimeTimecode => match res_timecode {
                Some((pts, duration, discont)) => (pts, duration, discont),
                None => {
                    gst::warning!(CAT, imp: self, "Can't calculate timestamp");
                    (receive_time_gst, duration, false)
                }
            },
            TimestampMode::ReceiveTimeTimestamp => match res_timestamp {
                Some((pts, duration, discont)) => (pts, duration, discont),
                None => {
                    if timestamp.is_some() {
                        gst::warning!(CAT, imp: self, "Can't calculate timestamp");
                    }

                    (receive_time_gst, duration, false)
                }
            },
            TimestampMode::Timecode => (timecode, duration, false),
            TimestampMode::Timestamp if timestamp.is_none() => (receive_time_gst, duration, false),
            TimestampMode::Timestamp => {
                // Timestamps are relative to the UNIX epoch
                let timestamp = timestamp?;
                if receive_time_real > timestamp {
                    let diff = receive_time_real - timestamp;
                    if diff > receive_time_gst {
                        (gst::ClockTime::ZERO, duration, false)
                    } else {
                        (receive_time_gst - diff, duration, false)
                    }
                } else {
                    let diff = timestamp - receive_time_real;
                    (receive_time_gst + diff, duration, false)
                }
            }
            TimestampMode::ReceiveTime => (receive_time_gst, duration, false),
            TimestampMode::Auto => {
                res_timecode
                    .or(res_timestamp)
                    .unwrap_or((receive_time_gst, duration, false))
            }
        };

        gst::log!(
            CAT,
            imp: self,
            "Calculated PTS {}, duration {}",
            pts.display(),
            duration.display(),
        );

        Some((pts, duration, discont))
    }

    fn calculate_video_timestamp(
        &self,
        state: &mut State,
        receive_time_gst: gst::ClockTime,
        receive_time_real: gst::ClockTime,
        video_frame: &crate::ndi::VideoFrame,
    ) -> Option<(gst::ClockTime, Option<gst::ClockTime>, bool)> {
        let duration = gst::ClockTime::SECOND.mul_div_floor(
            video_frame.frame_rate().1 as u64,
            video_frame.frame_rate().0 as u64,
        );

        self.calculate_timestamp(
            state,
            false,
            receive_time_gst,
            receive_time_real,
            video_frame.timestamp(),
            video_frame.timecode(),
            duration,
        )
    }

    fn create_video_buffer_pool(&self, video_info: &gst_video::VideoInfo) -> gst::BufferPool {
        let pool = gst_video::VideoBufferPool::new();
        let mut config = pool.config();
        config.set_params(
            Some(&video_info.to_caps().unwrap()),
            video_info.size() as u32,
            0,
            0,
        );
        pool.set_config(config).unwrap();
        pool.set_active(true).unwrap();

        pool.upcast()
    }

    fn create_video_info(
        &self,
        video_frame: &crate::ndi::VideoFrame,
    ) -> Result<VideoInfo, gst::FlowError> {
        let fourcc = video_frame.fourcc();

        let par = gst::Fraction::approximate_f32(video_frame.picture_aspect_ratio())
            .unwrap_or_else(|| gst::Fraction::new(1, 1))
            * gst::Fraction::new(video_frame.yres(), video_frame.xres());
        let interlace_mode = match video_frame.frame_format_type() {
            ndisys::NDIlib_frame_format_type_e::NDIlib_frame_format_type_progressive => {
                gst_video::VideoInterlaceMode::Progressive
            }
            ndisys::NDIlib_frame_format_type_e::NDIlib_frame_format_type_interleaved => {
                gst_video::VideoInterlaceMode::Interleaved
            }
            _ => gst_video::VideoInterlaceMode::Alternate,
        };

        if [
            ndisys::NDIlib_FourCC_video_type_UYVY,
            ndisys::NDIlib_FourCC_video_type_UYVA,
            ndisys::NDIlib_FourCC_video_type_YV12,
            ndisys::NDIlib_FourCC_video_type_NV12,
            ndisys::NDIlib_FourCC_video_type_I420,
            ndisys::NDIlib_FourCC_video_type_BGRA,
            ndisys::NDIlib_FourCC_video_type_BGRX,
            ndisys::NDIlib_FourCC_video_type_RGBA,
            ndisys::NDIlib_FourCC_video_type_BGRX,
        ]
        .contains(&fourcc)
        {
            // YV12 and I420 are swapped in the NDI SDK compared to GStreamer
            let format = match video_frame.fourcc() {
                ndisys::NDIlib_FourCC_video_type_UYVY => gst_video::VideoFormat::Uyvy,
                // FIXME: This drops the alpha plane!
                ndisys::NDIlib_FourCC_video_type_UYVA => gst_video::VideoFormat::Uyvy,
                ndisys::NDIlib_FourCC_video_type_YV12 => gst_video::VideoFormat::I420,
                ndisys::NDIlib_FourCC_video_type_NV12 => gst_video::VideoFormat::Nv12,
                ndisys::NDIlib_FourCC_video_type_I420 => gst_video::VideoFormat::Yv12,
                ndisys::NDIlib_FourCC_video_type_BGRA => gst_video::VideoFormat::Bgra,
                ndisys::NDIlib_FourCC_video_type_BGRX => gst_video::VideoFormat::Bgrx,
                ndisys::NDIlib_FourCC_video_type_RGBA => gst_video::VideoFormat::Rgba,
                ndisys::NDIlib_FourCC_video_type_RGBX => gst_video::VideoFormat::Rgbx,
                _ => {
                    gst::element_imp_error!(
                        self,
                        gst::StreamError::Format,
                        ["Unsupported video fourcc {:08x}", video_frame.fourcc()]
                    );

                    return Err(gst::FlowError::NotNegotiated);
                } // TODO: NDIlib_FourCC_video_type_P216 and NDIlib_FourCC_video_type_PA16 not
                  // supported by GStreamer
            };

            let mut builder = gst_video::VideoInfo::builder(
                format,
                video_frame.xres() as u32,
                video_frame.yres() as u32,
            )
            .fps(gst::Fraction::from(video_frame.frame_rate()))
            .par(par)
            .interlace_mode(interlace_mode);

            if video_frame.frame_format_type()
                == ndisys::NDIlib_frame_format_type_e::NDIlib_frame_format_type_interleaved
            {
                builder = builder.field_order(gst_video::VideoFieldOrder::TopFieldFirst);
            }

            return Ok(VideoInfo::Video(builder.build().map_err(|_| {
                gst::element_imp_error!(
                    self,
                    gst::StreamError::Format,
                    ["Invalid video format configuration"]
                );

                gst::FlowError::NotNegotiated
            })?));
        }

        #[cfg(feature = "advanced-sdk")]
        if [
            ndisys::NDIlib_FourCC_video_type_ex_SHQ0_highest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_SHQ2_highest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_SHQ7_highest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_SHQ0_lowest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_SHQ2_lowest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_SHQ7_lowest_bandwidth,
        ]
        .contains(&fourcc)
        {
            let variant = match fourcc {
                ndisys::NDIlib_FourCC_video_type_ex_SHQ0_highest_bandwidth
                | ndisys::NDIlib_FourCC_video_type_ex_SHQ0_lowest_bandwidth => String::from("SHQ0"),
                ndisys::NDIlib_FourCC_video_type_ex_SHQ2_highest_bandwidth
                | ndisys::NDIlib_FourCC_video_type_ex_SHQ2_lowest_bandwidth => String::from("SHQ2"),
                ndisys::NDIlib_FourCC_video_type_ex_SHQ7_highest_bandwidth
                | ndisys::NDIlib_FourCC_video_type_ex_SHQ7_lowest_bandwidth => String::from("SHQ7"),
                _ => {
                    gst::element_imp_error!(
                        self,
                        gst::StreamError::Format,
                        [
                            "Unsupported SpeedHQ video fourcc {:08x}",
                            video_frame.fourcc()
                        ]
                    );

                    return Err(gst::FlowError::NotNegotiated);
                }
            };

            return Ok(VideoInfo::SpeedHQInfo {
                variant,
                xres: video_frame.xres(),
                yres: video_frame.yres(),
                fps_n: video_frame.frame_rate().0,
                fps_d: video_frame.frame_rate().1,
                par_n: par.numer(),
                par_d: par.denom(),
                interlace_mode,
            });
        }

        #[cfg(feature = "advanced-sdk")]
        if [
            ndisys::NDIlib_FourCC_video_type_ex_H264_highest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_H264_lowest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_H264_alpha_highest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_H264_alpha_lowest_bandwidth,
        ]
        .contains(&fourcc)
        {
            let compressed_packet = video_frame.compressed_packet().ok_or_else(|| {
                gst::error!(
                    CAT,
                    imp: self,
                    "Video packet doesn't have compressed packet start"
                );
                gst::element_imp_error!(self, gst::StreamError::Format, ["Invalid video packet"]);

                gst::FlowError::Error
            })?;

            if compressed_packet.fourcc != ndisys::NDIlib_compressed_FourCC_type_H264 {
                gst::error!(CAT, imp: self, "Non-H264 video packet");
                gst::element_imp_error!(self, gst::StreamError::Format, ["Invalid video packet"]);

                return Err(gst::FlowError::Error);
            }

            return Ok(VideoInfo::H264 {
                xres: video_frame.xres(),
                yres: video_frame.yres(),
                fps_n: video_frame.frame_rate().0,
                fps_d: video_frame.frame_rate().1,
                par_n: par.numer(),
                par_d: par.denom(),
                interlace_mode,
            });
        }

        #[cfg(feature = "advanced-sdk")]
        if [
            ndisys::NDIlib_FourCC_video_type_ex_HEVC_highest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_HEVC_lowest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_HEVC_alpha_highest_bandwidth,
            ndisys::NDIlib_FourCC_video_type_ex_HEVC_alpha_lowest_bandwidth,
        ]
        .contains(&fourcc)
        {
            let compressed_packet = video_frame.compressed_packet().ok_or_else(|| {
                gst::error!(
                    CAT,
                    imp: self,
                    "Video packet doesn't have compressed packet start"
                );
                gst::element_imp_error!(self, gst::StreamError::Format, ["Invalid video packet"]);

                gst::FlowError::Error
            })?;

            if compressed_packet.fourcc != ndisys::NDIlib_compressed_FourCC_type_HEVC {
                gst::error!(CAT, imp: self, "Non-H265 video packet");
                gst::element_imp_error!(self, gst::StreamError::Format, ["Invalid video packet"]);

                return Err(gst::FlowError::Error);
            }

            return Ok(VideoInfo::H265 {
                xres: video_frame.xres(),
                yres: video_frame.yres(),
                fps_n: video_frame.frame_rate().0,
                fps_d: video_frame.frame_rate().1,
                par_n: par.numer(),
                par_d: par.denom(),
                interlace_mode,
            });
        }

        gst::element_imp_error!(
            self,
            gst::StreamError::Format,
            ["Unsupported video fourcc {:08x}", video_frame.fourcc()]
        );
        Err(gst::FlowError::NotNegotiated)
    }

    fn create_video_buffer(
        &self,
        state: &mut State,
        pts: gst::ClockTime,
        duration: Option<gst::ClockTime>,
        discont: bool,
        resync: bool,
        video_frame: crate::ndi::VideoFrame,
    ) -> Result<gst::Buffer, gst::FlowError> {
        let timecode = video_frame.timecode();
        let timestamp = video_frame.timestamp();
        let frame_format_type = video_frame.frame_format_type();

        let mut captions = Vec::new();

        {
            let ndi_cc_decoder = state.ndi_cc_decoder.as_mut().unwrap();
            // handle potential width change (also needed for standalone metadata)
            ndi_cc_decoder.set_width(state.video_info.as_ref().unwrap().width());

            for metadata in state.pending_metadata.drain(..) {
                if let Some(meta) = metadata.metadata() {
                    let res = ndi_cc_decoder.decode(meta);
                    if let Err(err) = res {
                        gst::debug!(CAT, imp: self, "Failed to parse NDI metadata: {err}");
                    }
                }
            }

            if let Some(metadata) = video_frame.metadata() {
                let res = ndi_cc_decoder.decode(metadata);
                match res {
                    Ok(c) => {
                        captions.extend_from_slice(&c);
                    }
                    Err(err) => {
                        gst::debug!(CAT, imp: self, "Failed to parse NDI video frame metadata: {err}");
                    }
                }
            }
        }

        let mut buffer = self.wrap_or_copy_video_frame(state, video_frame)?;
        {
            let buffer = buffer.get_mut().unwrap();
            buffer.set_pts(pts);
            buffer.set_duration(duration);

            if resync {
                buffer.set_flags(gst::BufferFlags::RESYNC);
            }

            if discont {
                buffer.set_flags(gst::BufferFlags::DISCONT);
            }

            gst::ReferenceTimestampMeta::add(
                buffer,
                &crate::TIMECODE_CAPS,
                (timecode as u64 * 100).nseconds(),
                gst::ClockTime::NONE,
            );
            if timestamp != ndisys::NDIlib_recv_timestamp_undefined {
                gst::ReferenceTimestampMeta::add(
                    buffer,
                    &crate::TIMESTAMP_CAPS,
                    (timestamp as u64 * 100).nseconds(),
                    gst::ClockTime::NONE,
                );
            }

            for caption in captions {
                match caption.did16() {
                    gst_video::VideoAncillaryDID16::S334Eia608 => {
                        gst_video::VideoCaptionMeta::add(
                            buffer,
                            gst_video::VideoCaptionType::Cea608S3341a,
                            caption.data(),
                        );
                    }
                    gst_video::VideoAncillaryDID16::S334Eia708 => {
                        gst_video::VideoCaptionMeta::add(
                            buffer,
                            gst_video::VideoCaptionType::Cea708Cdp,
                            caption.data(),
                        );
                    }
                    _ => (),
                }
            }

            match frame_format_type {
                ndisys::NDIlib_frame_format_type_e::NDIlib_frame_format_type_interleaved => {
                    buffer.set_video_flags(
                        gst_video::VideoBufferFlags::INTERLACED | gst_video::VideoBufferFlags::TFF,
                    );
                }
                ndisys::NDIlib_frame_format_type_e::NDIlib_frame_format_type_field_0 => {
                    buffer.set_video_flags(
                        gst_video::VideoBufferFlags::INTERLACED
                            | gst_video::VideoBufferFlags::TOP_FIELD,
                    );
                }
                ndisys::NDIlib_frame_format_type_e::NDIlib_frame_format_type_field_1 => {
                    buffer.set_video_flags(
                        gst_video::VideoBufferFlags::INTERLACED
                            | gst_video::VideoBufferFlags::BOTTOM_FIELD,
                    );
                }
                _ => (),
            }
        }

        Ok(buffer)
    }

    fn wrap_or_copy_video_frame(
        &self,
        state: &mut State,
        video_frame: crate::ndi::VideoFrame,
    ) -> Result<gst::Buffer, gst::FlowError> {
        struct WrappedVideoFrame(crate::ndi::VideoFrame);

        impl AsRef<[u8]> for WrappedVideoFrame {
            fn as_ref(&self) -> &[u8] {
                self.0.data().unwrap_or(&[])
            }
        }

        match state.video_info.as_ref().unwrap() {
            VideoInfo::Video(ref info) => {
                match info.format() {
                    gst_video::VideoFormat::Uyvy
                    | gst_video::VideoFormat::Bgra
                    | gst_video::VideoFormat::Bgrx
                    | gst_video::VideoFormat::Rgba
                    | gst_video::VideoFormat::Rgbx => {
                        let src_stride = video_frame.line_stride_or_data_size_in_bytes() as usize;

                        if src_stride == info.stride()[0] as usize {
                            Ok(gst::Buffer::from_slice(WrappedVideoFrame(video_frame)))
                        } else {
                            gst::debug!(gst::CAT_PERFORMANCE, imp: self, "Copying raw video frame");

                            let src = video_frame.data().ok_or(gst::FlowError::Error)?;

                            if state.video_buffer_pool.is_none() {
                                state.video_buffer_pool = Some(self.create_video_buffer_pool(info));
                            };
                            let pool = state.video_buffer_pool.as_ref().unwrap();
                            let buffer = pool.acquire_buffer(None)?;

                            let mut vframe =
                                gst_video::VideoFrame::from_buffer_writable(buffer, info).unwrap();

                            let line_bytes = if info.format() == gst_video::VideoFormat::Uyvy {
                                2 * vframe.width() as usize
                            } else {
                                4 * vframe.width() as usize
                            };

                            let dest_stride = vframe.plane_stride()[0] as usize;
                            let dest = vframe.plane_data_mut(0).unwrap();
                            let plane_size = video_frame.yres() as usize * src_stride;

                            if src.len() < plane_size || src_stride < line_bytes {
                                gst::error!(CAT, imp: self, "Video packet has wrong stride or size");
                                gst::element_imp_error!(
                                    self,
                                    gst::StreamError::Format,
                                    ["Video packet has wrong stride or size"]
                                );
                                return Err(gst::FlowError::Error);
                            }

                            for (dest, src) in dest
                                .chunks_exact_mut(dest_stride)
                                .zip(src.chunks_exact(src_stride))
                            {
                                dest[..line_bytes].copy_from_slice(&src[..line_bytes]);
                            }

                            Ok(vframe.into_buffer())
                        }
                    }
                    gst_video::VideoFormat::Nv12 => {
                        let src_stride = video_frame.line_stride_or_data_size_in_bytes() as usize;

                        if src_stride == info.stride()[0] as usize {
                            Ok(gst::Buffer::from_slice(WrappedVideoFrame(video_frame)))
                        } else {
                            gst::debug!(gst::CAT_PERFORMANCE, imp: self, "Copying raw video frame");

                            let src = video_frame.data().ok_or(gst::FlowError::Error)?;

                            if state.video_buffer_pool.is_none() {
                                state.video_buffer_pool = Some(self.create_video_buffer_pool(info));
                            };
                            let pool = state.video_buffer_pool.as_ref().unwrap();
                            let buffer = pool.acquire_buffer(None)?;

                            let mut vframe =
                                gst_video::VideoFrame::from_buffer_writable(buffer, info).unwrap();

                            let line_bytes = vframe.width() as usize;
                            let plane_size = video_frame.yres() as usize * src_stride;

                            if src.len() < 2 * plane_size || src_stride < line_bytes {
                                gst::error!(CAT, imp: self, "Video packet has wrong stride or size");
                                gst::element_imp_error!(
                                    self,
                                    gst::StreamError::Format,
                                    ["Video packet has wrong stride or size"]
                                );
                                return Err(gst::FlowError::Error);
                            }

                            // First plane
                            {
                                let dest_stride = vframe.plane_stride()[0] as usize;
                                let dest = vframe.plane_data_mut(0).unwrap();
                                let src = &src[..plane_size];

                                for (dest, src) in dest
                                    .chunks_exact_mut(dest_stride)
                                    .zip(src.chunks_exact(src_stride))
                                {
                                    dest[..line_bytes].copy_from_slice(&src[..line_bytes]);
                                }
                            }

                            // Second plane
                            {
                                let dest_stride = vframe.plane_stride()[1] as usize;
                                let dest = vframe.plane_data_mut(1).unwrap();
                                let src = &src[plane_size..];

                                for (dest, src) in dest
                                    .chunks_exact_mut(dest_stride)
                                    .zip(src.chunks_exact(src_stride))
                                {
                                    dest[..line_bytes].copy_from_slice(&src[..line_bytes]);
                                }
                            }

                            Ok(vframe.into_buffer())
                        }
                    }
                    gst_video::VideoFormat::Yv12 | gst_video::VideoFormat::I420 => {
                        let src_stride = video_frame.line_stride_or_data_size_in_bytes() as usize;
                        let src_stride1 = (src_stride + 1) / 2;

                        if src_stride == info.stride()[0] as usize
                            && src_stride1 == info.stride()[1] as usize
                        {
                            Ok(gst::Buffer::from_slice(WrappedVideoFrame(video_frame)))
                        } else {
                            gst::debug!(gst::CAT_PERFORMANCE, imp: self, "Copying raw video frame");

                            let src = video_frame.data().ok_or(gst::FlowError::Error)?;

                            if state.video_buffer_pool.is_none() {
                                state.video_buffer_pool = Some(self.create_video_buffer_pool(info));
                            };
                            let pool = state.video_buffer_pool.as_ref().unwrap();
                            let buffer = pool.acquire_buffer(None)?;

                            let mut vframe =
                                gst_video::VideoFrame::from_buffer_writable(buffer, info).unwrap();

                            let line_bytes = vframe.width() as usize;
                            let line_bytes1 = (line_bytes + 1) / 2;

                            let plane_size = video_frame.yres() as usize * src_stride;
                            let plane_size1 = ((video_frame.yres() as usize + 1) / 2) * src_stride1;

                            if src.len() < plane_size + 2 * plane_size1 || src_stride < line_bytes {
                                gst::error!(CAT, imp: self, "Video packet has wrong stride or size");
                                gst::element_imp_error!(
                                    self,
                                    gst::StreamError::Format,
                                    ["Video packet has wrong stride or size"]
                                );
                                return Err(gst::FlowError::Error);
                            }

                            // First plane
                            {
                                let dest_stride = vframe.plane_stride()[0] as usize;
                                let dest = vframe.plane_data_mut(0).unwrap();
                                let src = &src[..plane_size];

                                for (dest, src) in dest
                                    .chunks_exact_mut(dest_stride)
                                    .zip(src.chunks_exact(src_stride))
                                {
                                    dest[..line_bytes].copy_from_slice(&src[..line_bytes]);
                                }
                            }

                            // Second plane
                            {
                                let dest_stride = vframe.plane_stride()[1] as usize;
                                let dest = vframe.plane_data_mut(1).unwrap();
                                let src = &src[plane_size..][..plane_size1];

                                for (dest, src) in dest
                                    .chunks_exact_mut(dest_stride)
                                    .zip(src.chunks_exact(src_stride1))
                                {
                                    dest[..line_bytes1].copy_from_slice(&src[..line_bytes1]);
                                }
                            }

                            // Third plane
                            {
                                let dest_stride = vframe.plane_stride()[2] as usize;
                                let dest = vframe.plane_data_mut(2).unwrap();
                                let src = &src[plane_size + plane_size1..][..plane_size1];

                                for (dest, src) in dest
                                    .chunks_exact_mut(dest_stride)
                                    .zip(src.chunks_exact(src_stride1))
                                {
                                    dest[..line_bytes1].copy_from_slice(&src[..line_bytes1]);
                                }
                            }

                            Ok(vframe.into_buffer())
                        }
                    }
                    _ => unreachable!(),
                }
            }
            #[cfg(feature = "advanced-sdk")]
            VideoInfo::SpeedHQInfo { .. } => {
                Ok(gst::Buffer::from_slice(WrappedVideoFrame(video_frame)))
            }
            #[cfg(feature = "advanced-sdk")]
            VideoInfo::H264 { .. } | VideoInfo::H265 { .. } => {
                let compressed_packet = video_frame.compressed_packet().ok_or_else(|| {
                    gst::error!(
                        CAT,
                        imp: self,
                        "Video packet doesn't have compressed packet start"
                    );
                    gst::element_imp_error!(
                        self,
                        gst::StreamError::Format,
                        ["Invalid video packet"]
                    );

                    gst::FlowError::Error
                })?;

                // FIXME: Copy to a new vec for now. This can be optimized, especially if there is
                // no extra data attached to the frame
                let mut buffer = Vec::new();
                if let Some(extra_data) = compressed_packet.extra_data {
                    buffer.extend_from_slice(extra_data);
                }
                buffer.extend_from_slice(compressed_packet.data);
                let mut buffer = gst::Buffer::from_mut_slice(buffer);
                if !compressed_packet.key_frame {
                    let buffer = buffer.get_mut().unwrap();
                    buffer.set_flags(gst::BufferFlags::DELTA_UNIT);
                }

                Ok(buffer)
            }
        }
    }

    fn calculate_audio_timestamp(
        &self,
        state: &mut State,
        receive_time_gst: gst::ClockTime,
        receive_time_real: gst::ClockTime,
        audio_frame: &crate::ndi::AudioFrame,
    ) -> Option<(gst::ClockTime, Option<gst::ClockTime>, bool)> {
        let duration = gst::ClockTime::SECOND.mul_div_floor(
            audio_frame.no_samples() as u64,
            audio_frame.sample_rate() as u64,
        );

        self.calculate_timestamp(
            state,
            true,
            receive_time_gst,
            receive_time_real,
            audio_frame.timestamp(),
            audio_frame.timecode(),
            duration,
        )
    }

    fn create_audio_info(
        &self,
        audio_frame: &crate::ndi::AudioFrame,
    ) -> Result<AudioInfo, gst::FlowError> {
        let fourcc = audio_frame.fourcc();

        if [ndisys::NDIlib_FourCC_audio_type_FLTp].contains(&fourcc) {
            let channels = audio_frame.no_channels() as u32;
            let mut positions = [gst_audio::AudioChannelPosition::None; 64];
            if channels <= 8 {
                let _ = gst_audio::AudioChannelPosition::positions_from_mask(
                    gst_audio::AudioChannelPosition::fallback_mask(channels),
                    &mut positions[..channels as usize],
                );
            }

            let builder = gst_audio::AudioInfo::builder(
                gst_audio::AUDIO_FORMAT_F32,
                audio_frame.sample_rate() as u32,
                channels,
            )
            .positions(&positions[..channels as usize]);

            let info = builder.build().map_err(|_| {
                gst::element_imp_error!(
                    self,
                    gst::StreamError::Format,
                    ["Invalid audio format configuration"]
                );

                gst::FlowError::NotNegotiated
            })?;

            return Ok(AudioInfo::Audio(info));
        }

        #[cfg(feature = "advanced-sdk")]
        if [ndisys::NDIlib_FourCC_audio_type_AAC].contains(&fourcc) {
            let compressed_packet = audio_frame.compressed_packet().ok_or_else(|| {
                gst::error!(
                    CAT,
                    imp: self,
                    "Audio packet doesn't have compressed packet start"
                );
                gst::element_imp_error!(self, gst::StreamError::Format, ["Invalid audio packet"]);

                gst::FlowError::Error
            })?;

            if compressed_packet.fourcc != ndisys::NDIlib_compressed_FourCC_type_AAC {
                gst::error!(CAT, imp: self, "Non-AAC audio packet");
                gst::element_imp_error!(self, gst::StreamError::Format, ["Invalid audio packet"]);

                return Err(gst::FlowError::Error);
            }

            return Ok(AudioInfo::Aac {
                sample_rate: audio_frame.sample_rate(),
                no_channels: audio_frame.no_channels(),
                codec_data: compressed_packet
                    .extra_data
                    .ok_or(gst::FlowError::NotNegotiated)?
                    .try_into()
                    .map_err(|_| gst::FlowError::NotNegotiated)?,
            });
        }

        // FIXME: Needs testing with an actual stream to understand how it works
        // #[cfg(feature = "advanced-sdk")]
        // if [NDIlib_FourCC_audio_type_Opus].contains(&fourcc) {}

        gst::element_imp_error!(
            self,
            gst::StreamError::Format,
            ["Unsupported audio fourcc {:08x}", audio_frame.fourcc()]
        );
        Err(gst::FlowError::NotNegotiated)
    }

    fn create_audio_buffer(
        &self,
        state: &State,
        pts: gst::ClockTime,
        duration: Option<gst::ClockTime>,
        discont: bool,
        resync: bool,
        audio_frame: crate::ndi::AudioFrame,
    ) -> Result<gst::Buffer, gst::FlowError> {
        struct WrappedAudioFrame(crate::ndi::AudioFrame);

        impl AsRef<[u8]> for WrappedAudioFrame {
            fn as_ref(&self) -> &[u8] {
                self.0.data().unwrap_or(&[])
            }
        }

        match state.audio_info.as_ref().unwrap() {
            AudioInfo::Audio(ref info) => {
                let no_samples = audio_frame.no_samples();
                let timecode = audio_frame.timecode();
                let timestamp = audio_frame.timestamp();
                let buff_size = (no_samples as u32 * info.bpf()) as usize;

                let mut buffer = if state.audio_non_interleaved {
                    let info = state.audio_info_non_interleaved.as_ref().unwrap();
                    let mut buffer = gst::Buffer::from_slice(WrappedAudioFrame(audio_frame));

                    {
                        let buffer = buffer.get_mut().unwrap();

                        gst_audio::AudioMeta::add(buffer, info, no_samples as usize, &[]).unwrap();
                    }

                    buffer
                } else {
                    gst::debug!(gst::CAT_PERFORMANCE, imp: self, "Copying raw audio frame");

                    let src = audio_frame.data().ok_or(gst::FlowError::Error)?;
                    let mut buffer = gst::Buffer::with_size(buff_size).unwrap();

                    {
                        let buffer = buffer.get_mut().unwrap();
                        let mut dest = buffer.map_writable().unwrap();
                        let dest = dest
                            .as_mut_slice_of::<f32>()
                            .map_err(|_| gst::FlowError::NotNegotiated)?;
                        assert!(
                            dest.len()
                                == audio_frame.no_samples() as usize
                                    * audio_frame.no_channels() as usize
                        );

                        for (channel, samples) in src
                            .chunks_exact(
                                audio_frame.channel_stride_or_data_size_in_bytes() as usize
                            )
                            .enumerate()
                        {
                            let samples = samples
                                .as_slice_of::<f32>()
                                .map_err(|_| gst::FlowError::NotNegotiated)?;

                            for (i, sample) in samples[..audio_frame.no_samples() as usize]
                                .iter()
                                .enumerate()
                            {
                                dest[i * (audio_frame.no_channels() as usize) + channel] = *sample;
                            }
                        }
                    }

                    buffer
                };

                {
                    let buffer = buffer.get_mut().unwrap();

                    buffer.set_pts(pts);
                    buffer.set_duration(duration);

                    if resync {
                        buffer.set_flags(gst::BufferFlags::RESYNC);
                    }

                    if discont {
                        buffer.set_flags(gst::BufferFlags::DISCONT);
                    }

                    gst::ReferenceTimestampMeta::add(
                        buffer,
                        &crate::TIMECODE_CAPS,
                        (timecode as u64 * 100).nseconds(),
                        gst::ClockTime::NONE,
                    );
                    if timestamp != ndisys::NDIlib_recv_timestamp_undefined {
                        gst::ReferenceTimestampMeta::add(
                            buffer,
                            &crate::TIMESTAMP_CAPS,
                            (timestamp as u64 * 100).nseconds(),
                            gst::ClockTime::NONE,
                        );
                    }
                }

                Ok(buffer)
            }
            #[cfg(feature = "advanced-sdk")]
            AudioInfo::Opus { .. } => {
                let data = audio_frame.data().ok_or_else(|| {
                    gst::error!(CAT, imp: self, "Audio packet has no data");
                    gst::element_imp_error!(
                        self,
                        gst::StreamError::Format,
                        ["Invalid audio packet"]
                    );

                    gst::FlowError::Error
                })?;

                Ok(gst::Buffer::from_mut_slice(Vec::from(data)))
            }
            #[cfg(feature = "advanced-sdk")]
            AudioInfo::Aac { .. } => {
                let compressed_packet = audio_frame.compressed_packet().ok_or_else(|| {
                    gst::error!(
                        CAT,
                        imp: self,
                        "Audio packet doesn't have compressed packet start"
                    );
                    gst::element_imp_error!(
                        self,
                        gst::StreamError::Format,
                        ["Invalid audio packet"]
                    );

                    gst::FlowError::Error
                })?;

                Ok(gst::Buffer::from_mut_slice(Vec::from(
                    compressed_packet.data,
                )))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum AudioInfo {
    Audio(gst_audio::AudioInfo),
    #[cfg(feature = "advanced-sdk")]
    #[allow(dead_code)]
    Opus {
        sample_rate: i32,
        no_channels: i32,
    },
    #[cfg(feature = "advanced-sdk")]
    Aac {
        sample_rate: i32,
        no_channels: i32,
        codec_data: [u8; 2],
    },
}

impl AudioInfo {
    pub fn to_caps(&self) -> Result<gst::Caps, glib::BoolError> {
        match self {
            AudioInfo::Audio(ref info) => info.to_caps(),
            #[cfg(feature = "advanced-sdk")]
            AudioInfo::Opus {
                sample_rate,
                no_channels,
            } => Ok(gst::Caps::builder("audio/x-opus")
                .field("channels", *no_channels)
                .field("rate", *sample_rate)
                .field("channel-mapping-family", 0i32)
                .build()),
            #[cfg(feature = "advanced-sdk")]
            AudioInfo::Aac {
                sample_rate,
                no_channels,
                codec_data,
            } => Ok(gst::Caps::builder("audio/mpeg")
                .field("channels", *no_channels)
                .field("rate", *sample_rate)
                .field("mpegversion", 4i32)
                .field("stream-format", "raw")
                .field("codec_data", gst::Buffer::from_mut_slice(*codec_data))
                .build()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VideoInfo {
    Video(gst_video::VideoInfo),
    #[cfg(feature = "advanced-sdk")]
    SpeedHQInfo {
        variant: String,
        xres: i32,
        yres: i32,
        fps_n: i32,
        fps_d: i32,
        par_n: i32,
        par_d: i32,
        interlace_mode: gst_video::VideoInterlaceMode,
    },
    #[cfg(feature = "advanced-sdk")]
    H264 {
        xres: i32,
        yres: i32,
        fps_n: i32,
        fps_d: i32,
        par_n: i32,
        par_d: i32,
        interlace_mode: gst_video::VideoInterlaceMode,
    },
    #[cfg(feature = "advanced-sdk")]
    H265 {
        xres: i32,
        yres: i32,
        fps_n: i32,
        fps_d: i32,
        par_n: i32,
        par_d: i32,
        interlace_mode: gst_video::VideoInterlaceMode,
    },
}

impl VideoInfo {
    pub fn to_caps(&self) -> Result<gst::Caps, glib::BoolError> {
        match self {
            VideoInfo::Video(ref info) => info.to_caps(),
            #[cfg(feature = "advanced-sdk")]
            VideoInfo::SpeedHQInfo {
                ref variant,
                xres,
                yres,
                fps_n,
                fps_d,
                par_n,
                par_d,
                interlace_mode,
            } => Ok(gst::Caps::builder("video/x-speedhq")
                .field("width", *xres)
                .field("height", *yres)
                .field("framerate", gst::Fraction::new(*fps_n, *fps_d))
                .field("pixel-aspect-ratio", gst::Fraction::new(*par_n, *par_d))
                .field("interlace-mode", interlace_mode.to_str())
                .field("variant", variant)
                .build()),
            #[cfg(feature = "advanced-sdk")]
            VideoInfo::H264 {
                xres,
                yres,
                fps_n,
                fps_d,
                par_n,
                par_d,
                interlace_mode,
                ..
            } => Ok(gst::Caps::builder("video/x-h264")
                .field("width", *xres)
                .field("height", *yres)
                .field("framerate", gst::Fraction::new(*fps_n, *fps_d))
                .field("pixel-aspect-ratio", gst::Fraction::new(*par_n, *par_d))
                .field("interlace-mode", interlace_mode.to_str())
                .field("stream-format", "byte-stream")
                .field("alignment", "au")
                .build()),
            #[cfg(feature = "advanced-sdk")]
            VideoInfo::H265 {
                xres,
                yres,
                fps_n,
                fps_d,
                par_n,
                par_d,
                interlace_mode,
                ..
            } => Ok(gst::Caps::builder("video/x-h265")
                .field("width", *xres)
                .field("height", *yres)
                .field("framerate", gst::Fraction::new(*fps_n, *fps_d))
                .field("pixel-aspect-ratio", gst::Fraction::new(*par_n, *par_d))
                .field("interlace-mode", interlace_mode.to_str())
                .field("stream-format", "byte-stream")
                .field("alignment", "au")
                .build()),
        }
    }

    pub fn width(&self) -> u32 {
        match self {
            VideoInfo::Video(ref info) => info.width(),
            #[cfg(feature = "advanced-sdk")]
            VideoInfo::SpeedHQInfo { xres, .. }
            | VideoInfo::H264 { xres, .. }
            | VideoInfo::H265 { xres, .. } => *xres as u32,
        }
    }
}

const PREFILL_WINDOW_LENGTH: usize = 12;
const WINDOW_LENGTH: u64 = 512;
const WINDOW_DURATION: u64 = 2_000_000_000;

#[derive(Default)]
struct Observations(AtomicRefCell<ObservationsInner>);

struct ObservationsInner {
    base_remote_time: Option<u64>,
    base_local_time: Option<u64>,
    deltas: VecDeque<i64>,
    min_delta: i64,
    skew: i64,
    filling: bool,
    window_size: usize,

    // Remote/local times for workaround around fundamentally wrong slopes
    // This is not reset below and has a bigger window.
    times: VecDeque<(u64, u64)>,
    slope_correction: (u64, u64),
}

impl Default for ObservationsInner {
    fn default() -> ObservationsInner {
        ObservationsInner {
            base_local_time: None,
            base_remote_time: None,
            deltas: VecDeque::new(),
            min_delta: 0,
            skew: 0,
            filling: true,
            window_size: 0,
            times: VecDeque::new(),
            slope_correction: (1, 1),
        }
    }
}

impl ObservationsInner {
    fn reset(&mut self) {
        self.base_local_time = None;
        self.base_remote_time = None;
        self.deltas = VecDeque::new();
        self.min_delta = 0;
        self.skew = 0;
        self.filling = true;
        self.window_size = 0;
    }
}

impl Observations {
    // Based on the algorithm used in GStreamer's rtpjitterbuffer, which comes from
    // Fober, Orlarey and Letz, 2005, "Real Time Clock Skew Estimation over Network Delays":
    // http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.102.1546
    fn process(
        &self,
        element: &gst::Element,
        remote_time: Option<gst::ClockTime>,
        local_time: gst::ClockTime,
        duration: Option<gst::ClockTime>,
    ) -> Option<(gst::ClockTime, Option<gst::ClockTime>, bool)> {
        let remote_time = remote_time?.nseconds();
        let local_time = local_time.nseconds();

        let mut inner = self.0.borrow_mut();

        gst::trace!(
            CAT,
            obj: element,
            "Local time {}, remote time {}, slope correct {}/{}",
            local_time.nseconds(),
            remote_time.nseconds(),
            inner.slope_correction.0,
            inner.slope_correction.1,
        );

        inner.times.push_back((remote_time, local_time));
        while inner
            .times
            .back()
            .unwrap()
            .1
            .saturating_sub(inner.times.front().unwrap().1)
            > WINDOW_DURATION
        {
            let _ = inner.times.pop_front();
        }

        // Static remote times
        if inner.slope_correction.1 == 0 {
            return None;
        }

        let remote_time =
            remote_time.mul_div_round(inner.slope_correction.0, inner.slope_correction.1)?;

        let (base_remote_time, base_local_time) =
            match (inner.base_remote_time, inner.base_local_time) {
                (Some(remote), Some(local)) => (remote, local),
                _ => {
                    gst::debug!(
                        CAT,
                        obj: element,
                        "Initializing base time: local {}, remote {}",
                        local_time.nseconds(),
                        remote_time.nseconds(),
                    );
                    inner.base_remote_time = Some(remote_time);
                    inner.base_local_time = Some(local_time);

                    return Some((local_time.nseconds(), duration, true));
                }
            };

        if inner.times.len() < PREFILL_WINDOW_LENGTH {
            return Some((local_time.nseconds(), duration, false));
        }

        // Check if the slope is simply wrong and try correcting
        {
            let local_diff = inner
                .times
                .back()
                .unwrap()
                .1
                .saturating_sub(inner.times.front().unwrap().1);
            let remote_diff = inner
                .times
                .back()
                .unwrap()
                .0
                .saturating_sub(inner.times.front().unwrap().0);

            if remote_diff == 0 {
                inner.reset();
                inner.base_remote_time = Some(remote_time);
                inner.base_local_time = Some(local_time);

                // Static remote times
                inner.slope_correction = (0, 0);
                return None;
            } else {
                let slope = local_diff as f64 / remote_diff as f64;
                let scaled_slope =
                    slope * (inner.slope_correction.1 as f64) / (inner.slope_correction.0 as f64);

                // Check for some obviously wrong slopes and try to correct for that
                if !(0.5..1.5).contains(&scaled_slope) {
                    gst::warning!(
                        CAT,
                        obj: element,
                        "Too small/big slope {}, resetting",
                        scaled_slope
                    );

                    let discont = !inner.deltas.is_empty();
                    inner.reset();

                    if (0.0005..0.0015).contains(&slope) {
                        // Remote unit was actually 0.1ns
                        inner.slope_correction = (1, 1000);
                    } else if (0.005..0.015).contains(&slope) {
                        // Remote unit was actually 1ns
                        inner.slope_correction = (1, 100);
                    } else if (0.05..0.15).contains(&slope) {
                        // Remote unit was actually 10ns
                        inner.slope_correction = (1, 10);
                    } else if (5.0..15.0).contains(&slope) {
                        // Remote unit was actually 1us
                        inner.slope_correction = (10, 1);
                    } else if (50.0..150.0).contains(&slope) {
                        // Remote unit was actually 10us
                        inner.slope_correction = (100, 1);
                    } else if (50.0..150.0).contains(&slope) {
                        // Remote unit was actually 100us
                        inner.slope_correction = (1000, 1);
                    } else if (50.0..150.0).contains(&slope) {
                        // Remote unit was actually 1ms
                        inner.slope_correction = (10000, 1);
                    } else {
                        inner.slope_correction = (1, 1);
                    }

                    let remote_time = inner
                        .times
                        .back()
                        .unwrap()
                        .0
                        .mul_div_round(inner.slope_correction.0, inner.slope_correction.1)?;
                    gst::debug!(
                        CAT,
                        obj: element,
                        "Initializing base time: local {}, remote {}, slope correction {}/{}",
                        local_time.nseconds(),
                        remote_time.nseconds(),
                        inner.slope_correction.0,
                        inner.slope_correction.1,
                    );
                    inner.base_remote_time = Some(remote_time);
                    inner.base_local_time = Some(local_time);

                    return Some((local_time.nseconds(), duration, discont));
                }
            }
        }

        let remote_diff = remote_time.saturating_sub(base_remote_time);
        let local_diff = local_time.saturating_sub(base_local_time);
        let delta = (local_diff as i64) - (remote_diff as i64);

        gst::trace!(
            CAT,
            obj: element,
            "Local diff {}, remote diff {}, delta {}",
            local_diff.nseconds(),
            remote_diff.nseconds(),
            delta,
        );

        if (delta > inner.skew && delta - inner.skew > 1_000_000_000)
            || (delta < inner.skew && inner.skew - delta > 1_000_000_000)
        {
            gst::warning!(
                CAT,
                obj: element,
                "Delta {} too far from skew {}, resetting",
                delta,
                inner.skew
            );

            let discont = !inner.deltas.is_empty();

            gst::debug!(
                CAT,
                obj: element,
                "Initializing base time: local {}, remote {}",
                local_time.nseconds(),
                remote_time.nseconds(),
            );

            inner.reset();
            inner.base_remote_time = Some(remote_time);
            inner.base_local_time = Some(local_time);

            return Some((local_time.nseconds(), duration, discont));
        }

        if inner.filling {
            if inner.deltas.is_empty() || delta < inner.min_delta {
                inner.min_delta = delta;
            }
            inner.deltas.push_back(delta);

            if remote_diff > WINDOW_DURATION || inner.deltas.len() as u64 == WINDOW_LENGTH {
                inner.window_size = inner.deltas.len();
                inner.skew = inner.min_delta;
                inner.filling = false;
            } else {
                let perc_time = remote_diff.mul_div_floor(100, WINDOW_DURATION).unwrap() as i64;
                let perc_window = (inner.deltas.len() as u64)
                    .mul_div_floor(100, WINDOW_LENGTH)
                    .unwrap() as i64;
                let perc = cmp::max(perc_time, perc_window);

                inner.skew = (perc * inner.min_delta + ((10_000 - perc) * inner.skew)) / 10_000;
            }
        } else {
            let old = inner.deltas.pop_front().unwrap();
            inner.deltas.push_back(delta);

            if delta <= inner.min_delta {
                inner.min_delta = delta;
            } else if old == inner.min_delta {
                inner.min_delta = inner.deltas.iter().copied().min().unwrap();
            }

            inner.skew = (inner.min_delta + (124 * inner.skew)) / 125;
        }

        let out_time = base_local_time + remote_diff;
        let out_time = if inner.skew < 0 {
            out_time.saturating_sub((-inner.skew) as u64)
        } else {
            out_time + (inner.skew as u64)
        };

        gst::trace!(
            CAT,
            obj: element,
            "Skew {}, min delta {}",
            inner.skew,
            inner.min_delta
        );
        gst::trace!(CAT, obj: element, "Outputting {}", out_time.nseconds());

        Some((out_time.nseconds(), duration, false))
    }
}
