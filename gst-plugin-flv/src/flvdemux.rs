// Copyright (C) 2016-2018 Sebastian Dröge <sebastian@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp;
use std::sync::Mutex;

use nom;

// FIXME: rustfmt removes the :: but they're required here
#[rustfmt::skip]
use ::flavors::parser as flavors;

use crate::gst;
use crate::gst::prelude::*;
use crate::gst::subclass::prelude::*;
use crate::gst_base;
use glib;
use glib::subclass;

use num_rational::Rational32;

use smallvec::SmallVec;

lazy_static! {
    static ref CAT: gst::DebugCategory = {
        gst::DebugCategory::new(
            "rsflvdemux",
            gst::DebugColorFlags::empty(),
            Some("Rust FLV demuxer"),
        )
    };
}

#[derive(Debug)]
struct FlvDemux {
    sinkpad: gst::Pad,
    audio_srcpad: Mutex<Option<gst::Pad>>,
    video_srcpad: Mutex<Option<gst::Pad>>,
    adapter: Mutex<gst_base::UniqueAdapter>,
    flow_combiner: Mutex<gst_base::UniqueFlowCombiner>,
    state: Mutex<State>,
}

#[derive(Debug)]
enum State {
    Stopped,
    NeedHeader,
    Skipping {
        audio: bool,
        video: bool,
        skip_left: u32,
    },
    Streaming(StreamingState),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stream {
    Audio,
    Video,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    StreamChanged(Stream, gst::Caps),
    Buffer(Stream, gst::Buffer),
    HaveAllStreams,
}

#[derive(Debug)]
struct StreamingState {
    audio: Option<AudioFormat>,
    expect_audio: bool,
    video: Option<VideoFormat>,
    expect_video: bool,
    got_all_streams: bool,
    last_position: gst::ClockTime,

    metadata: Option<Metadata>,

    aac_sequence_header: Option<gst::Buffer>,
    avc_sequence_header: Option<gst::Buffer>,
}

#[derive(Debug, Eq, Clone)]
struct AudioFormat {
    format: flavors::SoundFormat,
    rate: u16,
    width: u8,
    channels: u8,
    bitrate: Option<u32>,
    aac_sequence_header: Option<gst::Buffer>,
}

#[derive(Debug, Eq, Clone)]
struct VideoFormat {
    format: flavors::CodecId,
    width: Option<u32>,
    height: Option<u32>,
    pixel_aspect_ratio: Option<Rational32>,
    framerate: Option<Rational32>,
    bitrate: Option<u32>,
    avc_sequence_header: Option<gst::Buffer>,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
struct Metadata {
    duration: gst::ClockTime,

    creation_date: Option<String>,
    creator: Option<String>,
    title: Option<String>,
    metadata_creator: Option<String>, /* TODO: seek_table: _,
                                       * filepositions / times metadata arrays */

    audio_bitrate: Option<u32>,

    video_width: Option<u32>,
    video_height: Option<u32>,
    video_pixel_aspect_ratio: Option<Rational32>,
    video_framerate: Option<Rational32>,
    video_bitrate: Option<u32>,
}

impl ObjectSubclass for FlvDemux {
    const NAME: &'static str = "RsFlvDemux";
    type ParentType = gst::Element;
    type Instance = gst::subclass::ElementInstanceStruct<Self>;
    type Class = subclass::simple::ClassStruct<Self>;

    glib_object_subclass!();

    fn new_with_class(klass: &subclass::simple::ClassStruct<Self>) -> Self {
        let templ = klass.get_pad_template("sink").unwrap();
        let sinkpad = gst::Pad::new_from_template(&templ, Some("sink"));

        sinkpad.set_activate_function(|pad, parent| {
            FlvDemux::catch_panic_pad_function(
                parent,
                || Err(gst_loggable_error!(CAT, "Panic activating sink pad")),
                |demux, element| demux.sink_activate(pad, element),
            )
        });

        sinkpad.set_activatemode_function(|pad, parent, mode, active| {
            FlvDemux::catch_panic_pad_function(
                parent,
                || {
                    Err(gst_loggable_error!(
                        CAT,
                        "Panic activating sink pad with mode"
                    ))
                },
                |demux, element| demux.sink_activatemode(pad, element, mode, active),
            )
        });

        sinkpad.set_chain_function(|pad, parent, buffer| {
            FlvDemux::catch_panic_pad_function(
                parent,
                || Err(gst::FlowError::Error),
                |demux, element| demux.sink_chain(pad, element, buffer),
            )
        });
        sinkpad.set_event_function(|pad, parent, event| {
            FlvDemux::catch_panic_pad_function(
                parent,
                || false,
                |demux, element| demux.sink_event(pad, element, event),
            )
        });

        FlvDemux {
            sinkpad,
            audio_srcpad: Mutex::new(None),
            video_srcpad: Mutex::new(None),
            state: Mutex::new(State::Stopped),
            adapter: Mutex::new(gst_base::UniqueAdapter::new()),
            flow_combiner: Mutex::new(gst_base::UniqueFlowCombiner::new()),
        }
    }

    fn class_init(klass: &mut subclass::simple::ClassStruct<Self>) {
        klass.set_metadata(
            "FLV Demuxer",
            "Codec/Demuxer",
            "Demuxes FLV Streams",
            "Sebastian Dröge <sebastian@centricular.com>",
        );

        let mut caps = gst::Caps::new_empty();
        {
            let caps = caps.get_mut().unwrap();

            caps.append(
                gst::Caps::builder("audio/mpeg")
                    .field("mpegversion", &1i32)
                    .build(),
            );
            caps.append(
                gst::Caps::builder("audio/x-raw")
                    .field("layout", &"interleaved")
                    .field("format", &gst::List::new(&[&"U8", &"S16LE"]))
                    .build(),
            );
            caps.append(
                gst::Caps::builder("audio/x-adpcm")
                    .field("layout", &"swf")
                    .build(),
            );
            caps.append(gst::Caps::builder("audio/x-nellymoser").build());
            caps.append(gst::Caps::builder("audio/x-alaw").build());
            caps.append(gst::Caps::builder("audio/x-mulaw").build());
            caps.append(
                gst::Caps::builder("audio/mpeg")
                    .field("mpegversion", &4i32)
                    .field("framed", &true)
                    .field("stream-format", &"raw")
                    .build(),
            );
            caps.append(gst::Caps::builder("audio/x-speex").build());
        }
        let audiosrc_pad_template = gst::PadTemplate::new(
            "audio",
            gst::PadDirection::Src,
            gst::PadPresence::Sometimes,
            &caps,
        )
        .unwrap();
        klass.add_pad_template(audiosrc_pad_template);

        let mut caps = gst::Caps::new_empty();
        {
            let caps = caps.get_mut().unwrap();

            caps.append(
                gst::Caps::builder("video/x-flash-video")
                    .field("flvversion", &1i32)
                    .build(),
            );
            caps.append(gst::Caps::builder("video/x-flash-screen").build());
            caps.append(gst::Caps::builder("video/x-vp6-flash").build());
            caps.append(gst::Caps::builder("video/x-vp6-flash-alpha").build());
            caps.append(gst::Caps::builder("video/x-flash-screen2").build());
            caps.append(
                gst::Caps::builder("video/x-h264")
                    .field("stream-format", &"avc")
                    .build(),
            );
            caps.append(gst::Caps::builder("video/x-h263").build());
            caps.append(
                gst::Caps::builder("video/mpeg")
                    .field("mpegversion", &4i32)
                    .build(),
            );
        }
        let videosrc_pad_template = gst::PadTemplate::new(
            "video",
            gst::PadDirection::Src,
            gst::PadPresence::Sometimes,
            &caps,
        )
        .unwrap();
        klass.add_pad_template(videosrc_pad_template);

        let caps = gst::Caps::builder("video/x-flv").build();
        let sink_pad_template = gst::PadTemplate::new(
            "sink",
            gst::PadDirection::Sink,
            gst::PadPresence::Always,
            &caps,
        )
        .unwrap();
        klass.add_pad_template(sink_pad_template);
    }
}

impl ObjectImpl for FlvDemux {
    glib_object_impl!();

    fn constructed(&self, obj: &glib::Object) {
        self.parent_constructed(obj);

        let element = obj.downcast_ref::<gst::Element>().unwrap();
        element.add_pad(&self.sinkpad).unwrap();
    }
}

impl ElementImpl for FlvDemux {}

impl FlvDemux {
    fn sink_activate(
        &self,
        pad: &gst::Pad,
        _element: &gst::Element,
    ) -> Result<(), gst::LoggableError> {
        let mode = {
            let mut query = gst::Query::new_scheduling();
            if !pad.peer_query(&mut query) {
                return Err(gst_loggable_error!(CAT, "Scheduling query failed on peer"));
            }

            // TODO: pull mode
            // if query.has_scheduling_mode_with_flags(
            //         gst::PadMode::Pull,
            //         gst::SchedulingFlags::SEEKABLE,
            //     )
            // {
            //     gst_debug!(CAT, obj: pad, "Activating in Pull mode");
            //     gst::PadMode::Pull
            // } else {
            gst_debug!(CAT, obj: pad, "Activating in Push mode");
            gst::PadMode::Push
            // }
        };

        pad.activate_mode(mode, true)?;
        Ok(())
    }

    fn sink_activatemode(
        &self,
        _pad: &gst::Pad,
        element: &gst::Element,
        mode: gst::PadMode,
        active: bool,
    ) -> Result<(), gst::LoggableError> {
        if active {
            self.start(element, mode).map_err(|err| {
                element.post_error_message(&err);
                gst_loggable_error!(CAT, "Failed to start element with mode {:?}", mode)
            })?;

            if mode == gst::PadMode::Pull {
                // TODO implement pull mode
                // self.sinkpad.start_task(...)
                unimplemented!();
            }
        } else {
            if mode == gst::PadMode::Pull {
                let _ = self.sinkpad.stop_task();
            }

            self.stop(element).map_err(|err| {
                element.post_error_message(&err);
                gst_loggable_error!(CAT, "Failed to stop element")
            })?;
        }

        Ok(())
    }

    fn start(&self, _element: &gst::Element, _mode: gst::PadMode) -> Result<(), gst::ErrorMessage> {
        *self.state.lock().unwrap() = State::NeedHeader;

        Ok(())
    }

    fn stop(&self, element: &gst::Element) -> Result<(), gst::ErrorMessage> {
        *self.state.lock().unwrap() = State::Stopped;
        self.adapter.lock().unwrap().clear();

        let mut flow_combiner = self.flow_combiner.lock().unwrap();
        if let Some(pad) = self.audio_srcpad.lock().unwrap().take() {
            element.remove_pad(&pad).unwrap();
            flow_combiner.remove_pad(&pad);
        }

        if let Some(pad) = self.video_srcpad.lock().unwrap().take() {
            element.remove_pad(&pad).unwrap();
            flow_combiner.remove_pad(&pad);
        }

        flow_combiner.reset();

        Ok(())
    }

    fn sink_event(&self, pad: &gst::Pad, element: &gst::Element, event: gst::Event) -> bool {
        use crate::gst::EventView;

        gst_log!(CAT, obj: pad, "Handling event {:?}", event);
        match event.view() {
            EventView::Eos(..) => {
                // TODO implement
                pad.event_default(Some(element), event)
            }
            EventView::Segment(..) => {
                // TODO implement
                pad.event_default(Some(element), event)
            }
            EventView::FlushStart(..) => {
                // TODO implement
                pad.event_default(Some(element), event)
            }
            EventView::FlushStop(..) => {
                // TODO implement
                pad.event_default(Some(element), event)
            }
            _ => pad.event_default(Some(element), event),
        }
    }

    fn src_query(&self, pad: &gst::Pad, element: &gst::Element, query: &mut gst::QueryRef) -> bool {
        use crate::gst::QueryView;

        match query.view_mut() {
            QueryView::Position(ref mut q) => {
                let fmt = q.get_format();
                if fmt == gst::Format::Time {
                    if self.sinkpad.peer_query(q.get_mut_query()) {
                        return true;
                    }

                    if let State::Streaming(StreamingState { last_position, .. }) =
                        *self.state.lock().unwrap()
                    {
                        q.set(last_position);
                        return true;
                    }

                    false
                } else {
                    false
                }
            }
            QueryView::Duration(ref mut q) => {
                let fmt = q.get_format();
                if fmt == gst::Format::Time {
                    if self.sinkpad.peer_query(q.get_mut_query()) {
                        return true;
                    }

                    if let State::Streaming(StreamingState {
                        metadata: Some(Metadata { duration, .. }),
                        ..
                    }) = *self.state.lock().unwrap()
                    {
                        q.set(duration);
                        return true;
                    }

                    false
                } else {
                    false
                }
            }
            _ => pad.query_default(Some(element), query),
        }
    }

    fn src_event(&self, pad: &gst::Pad, element: &gst::Element, event: gst::Event) -> bool {
        use crate::gst::EventView;

        match event.view() {
            EventView::Seek(..) => {
                // TODO: Implement
                false
            }
            _ => pad.event_default(Some(element), event),
        }
    }

    fn sink_chain(
        &self,
        pad: &gst::Pad,
        element: &gst::Element,
        buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        gst_log!(CAT, obj: pad, "Handling buffer {:?}", buffer);

        let mut adapter = self.adapter.lock().unwrap();
        adapter.push(buffer);

        let mut state = self.state.lock().unwrap();
        loop {
            match *state {
                State::Stopped => unreachable!(),
                State::NeedHeader => {
                    let header = match self.find_header(element, &mut *adapter) {
                        Ok(header) => header,
                        Err(_) => {
                            gst_trace!(CAT, obj: element, "Need more data");
                            return Ok(gst::FlowSuccess::Ok);
                        }
                    };

                    let skip = if header.offset < 9 {
                        0
                    } else {
                        header.offset - 9
                    };

                    *state = State::Skipping {
                        audio: header.audio,
                        video: header.video,
                        skip_left: skip,
                    };
                }
                State::Skipping {
                    audio,
                    video,
                    skip_left: 0,
                } => {
                    *state = State::Streaming(StreamingState::new(audio, video));
                }
                State::Skipping {
                    ref mut skip_left, ..
                } => {
                    let avail = adapter.available();
                    if avail == 0 {
                        gst_trace!(CAT, obj: element, "Need more data");
                        return Ok(gst::FlowSuccess::Ok);
                    }
                    let skip = cmp::min(avail, *skip_left as usize);
                    adapter.flush(skip);
                    *skip_left -= skip as u32;
                }
                State::Streaming(ref mut sstate) => {
                    let res = sstate.handle_tag(element, &mut *adapter);

                    match res {
                        Ok(None) => {
                            gst_trace!(CAT, obj: element, "Need more data");
                            return Ok(gst::FlowSuccess::Ok);
                        }
                        Ok(Some(events)) => {
                            drop(state);
                            drop(adapter);

                            self.handle_events(element, events)?;

                            adapter = self.adapter.lock().unwrap();
                            state = self.state.lock().unwrap();
                        }
                        Err(err) => {
                            element.post_error_message(&err);
                            return Err(gst::FlowError::Error);
                        }
                    }
                }
            }
        }
    }

    fn find_header(
        &self,
        element: &gst::Element,
        adapter: &mut gst_base::UniqueAdapter,
    ) -> Result<flavors::Header, ()> {
        while adapter.available() >= 9 {
            let data = adapter.map(9).unwrap();

            if let Ok((_, header)) = flavors::header(&*data) {
                gst_debug!(CAT, obj: element, "Found FLV header: {:?}", header);
                drop(data);
                adapter.flush(9);

                return Ok(header);
            }

            drop(data);
            adapter.flush(1);
        }

        Err(())
    }

    fn handle_events(
        &self,
        element: &gst::Element,
        events: SmallVec<[Event; 4]>,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        for event in events {
            match event {
                Event::StreamChanged(stream, caps) => {
                    let pad = match stream {
                        Stream::Audio => {
                            let mut audio_srcpad = self.audio_srcpad.lock().unwrap();
                            if let Some(ref srcpad) = *audio_srcpad {
                                srcpad.clone()
                            } else {
                                let srcpad = self.create_srcpad(element, "audio", &caps);
                                *audio_srcpad = Some(srcpad.clone());

                                srcpad
                            }
                        }
                        Stream::Video => {
                            let mut video_srcpad = self.video_srcpad.lock().unwrap();
                            if let Some(ref srcpad) = *video_srcpad {
                                srcpad.clone()
                            } else {
                                let srcpad = self.create_srcpad(element, "video", &caps);

                                *video_srcpad = Some(srcpad.clone());

                                srcpad
                            }
                        }
                    };

                    pad.push_event(gst::Event::new_caps(&caps).build());
                }
                Event::Buffer(stream, buffer) => {
                    let pad = match stream {
                        Stream::Audio => {
                            self.audio_srcpad.lock().unwrap().as_ref().map(Clone::clone)
                        }
                        Stream::Video => {
                            self.video_srcpad.lock().unwrap().as_ref().map(Clone::clone)
                        }
                    };

                    if let Some(pad) = pad {
                        let res = pad.push(buffer);
                        gst_trace!(
                            CAT,
                            obj: element,
                            "Pushing buffer for stream {:?} returned {:?}",
                            stream,
                            res
                        );

                        self.flow_combiner
                            .lock()
                            .unwrap()
                            .update_pad_flow(&pad, res)?;
                    }
                }
                Event::HaveAllStreams => {
                    element.no_more_pads();
                }
            }
        }

        Ok(gst::FlowSuccess::Ok)
    }

    fn create_srcpad(&self, element: &gst::Element, name: &str, caps: &gst::Caps) -> gst::Pad {
        let templ = element.get_element_class().get_pad_template(name).unwrap();
        let srcpad = gst::Pad::new_from_template(&templ, Some(name));

        srcpad.set_event_function(|pad, parent, event| {
            FlvDemux::catch_panic_pad_function(
                parent,
                || false,
                |demux, element| demux.src_event(pad, element, event),
            )
        });

        srcpad.set_query_function(|pad, parent, query| {
            FlvDemux::catch_panic_pad_function(
                parent,
                || false,
                |demux, element| demux.src_query(pad, element, query),
            )
        });

        srcpad.set_active(true).unwrap();

        let full_stream_id = srcpad.create_stream_id(element, Some(name)).unwrap();
        // FIXME group id
        srcpad.push_event(gst::Event::new_stream_start(&full_stream_id).build());
        srcpad.push_event(gst::Event::new_caps(&caps).build());

        // FIXME proper segment handling
        let segment = gst::FormattedSegment::<gst::ClockTime>::default();
        srcpad.push_event(gst::Event::new_segment(&segment).build());

        self.flow_combiner.lock().unwrap().add_pad(&srcpad);

        element.add_pad(&srcpad).unwrap();

        srcpad
    }
}

impl StreamingState {
    fn new(audio: bool, video: bool) -> StreamingState {
        StreamingState {
            audio: None,
            expect_audio: audio,
            video: None,
            expect_video: video,
            got_all_streams: false,
            last_position: gst::CLOCK_TIME_NONE,
            metadata: None,
            aac_sequence_header: None,
            avc_sequence_header: None,
        }
    }

    fn handle_tag(
        &mut self,
        element: &gst::Element,
        adapter: &mut gst_base::UniqueAdapter,
    ) -> Result<Option<SmallVec<[Event; 4]>>, gst::ErrorMessage> {
        if adapter.available() < 15 {
            return Ok(None);
        }

        let data = adapter.map(15).unwrap();

        match nom::be_u32(&data[0..4]) {
            Err(_) => unreachable!(),
            Ok((_, previous_size)) => {
                gst_trace!(CAT, obj: element, "Previous tag size {}", previous_size);
                // Nothing to do here, we just consume it for now
            }
        }

        let tag_header = match flavors::tag_header(&data[4..]) {
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
                return Err(gst_error_msg!(
                    gst::StreamError::Demux,
                    ["Invalid tag header: {:?}", err]
                ));
            }
            Err(nom::Err::Incomplete(_)) => unreachable!(),
            Ok((_, tag_header)) => tag_header,
        };

        gst_trace!(CAT, obj: element, "Parsed tag header {:?}", tag_header);

        drop(data);

        if adapter.available() < (15 + tag_header.data_size) as usize {
            return Ok(None);
        }

        adapter.flush(15);

        match tag_header.tag_type {
            flavors::TagType::Script => {
                gst_trace!(CAT, obj: element, "Found script tag");

                self.handle_script_tag(element, &tag_header, adapter)
            }
            flavors::TagType::Audio => {
                gst_trace!(CAT, obj: element, "Found audio tag");

                self.handle_audio_tag(element, &tag_header, adapter)
            }
            flavors::TagType::Video => {
                gst_trace!(CAT, obj: element, "Found video tag");

                self.handle_video_tag(element, &tag_header, adapter)
            }
        }
        .map(Option::Some)
    }

    fn handle_script_tag(
        &mut self,
        element: &gst::Element,
        tag_header: &flavors::TagHeader,
        adapter: &mut gst_base::UniqueAdapter,
    ) -> Result<SmallVec<[Event; 4]>, gst::ErrorMessage> {
        assert!(adapter.available() >= tag_header.data_size as usize);

        let mut events = SmallVec::new();

        let data = adapter.map(tag_header.data_size as usize).unwrap();

        match flavors::script_data(&*data) {
            Ok((_, ref script_data)) if script_data.name == "onMetaData" => {
                gst_trace!(CAT, obj: element, "Got script tag: {:?}", script_data);

                let metadata = Metadata::new(script_data);
                gst_debug!(CAT, obj: element, "Got metadata: {:?}", metadata);

                let audio_changed = self
                    .audio
                    .as_mut()
                    .map(|a| a.update_with_metadata(&metadata))
                    .unwrap_or(false);
                let video_changed = self
                    .video
                    .as_mut()
                    .map(|v| v.update_with_metadata(&metadata))
                    .unwrap_or(false);
                self.metadata = Some(metadata);

                if audio_changed || video_changed {
                    if audio_changed {
                        if let Some(caps) = self.audio.as_ref().and_then(|a| a.to_caps()) {
                            events.push(Event::StreamChanged(Stream::Audio, caps));
                        }
                    }
                    if video_changed {
                        if let Some(caps) = self.video.as_ref().and_then(|v| v.to_caps()) {
                            events.push(Event::StreamChanged(Stream::Video, caps));
                        }
                    }
                }
            }
            Ok((_, ref script_data)) => {
                gst_trace!(CAT, obj: element, "Got script tag: {:?}", script_data);
            }
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
                gst_error!(CAT, obj: element, "Error parsing script tag: {:?}", err);
            }
            Err(nom::Err::Incomplete(_)) => {
                // ignore
            }
        }

        drop(data);
        adapter.flush(tag_header.data_size as usize);

        Ok(events)
    }

    fn update_audio_stream(
        &mut self,
        element: &gst::Element,
        data_header: &flavors::AudioDataHeader,
    ) -> Result<SmallVec<[Event; 4]>, gst::ErrorMessage> {
        let mut events = SmallVec::new();

        gst_trace!(
            CAT,
            obj: element,
            "Got audio data header: {:?}",
            data_header
        );

        let new_audio_format =
            AudioFormat::new(data_header, &self.metadata, &self.aac_sequence_header);

        if self.audio.as_ref() != Some(&new_audio_format) {
            gst_debug!(
                CAT,
                obj: element,
                "Got new audio format: {:?}",
                new_audio_format
            );

            let caps = new_audio_format.to_caps();
            if let Some(caps) = caps {
                self.audio = Some(new_audio_format);
                events.push(Event::StreamChanged(Stream::Audio, caps));
            } else {
                self.audio = None;
            }
        }

        if (!self.expect_video || self.video != None) && self.audio != None && !self.got_all_streams
        {
            gst_debug!(CAT, obj: element, "Have all expected streams now");
            self.got_all_streams = true;
            events.push(Event::HaveAllStreams);
        }

        Ok(events)
    }

    fn handle_aac_audio_packet_header(
        &mut self,
        element: &gst::Element,
        tag_header: &flavors::TagHeader,
        adapter: &mut gst_base::UniqueAdapter,
    ) -> Result<bool, gst::ErrorMessage> {
        // Not big enough for the AAC packet header, ship!
        if tag_header.data_size < 1 + 1 {
            adapter.flush((tag_header.data_size - 1) as usize);
            gst_warning!(
                CAT,
                obj: element,
                "Too small packet for AAC packet header {}",
                tag_header.data_size
            );
            return Ok(true);
        }

        let data = adapter.map(1).unwrap();

        match flavors::aac_audio_packet_header(&*data) {
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
                gst_error!(
                    CAT,
                    obj: element,
                    "Invalid AAC audio packet header: {:?}",
                    err
                );
                drop(data);
                adapter.flush((tag_header.data_size - 1) as usize);
                Ok(true)
            }
            Err(nom::Err::Incomplete(_)) => unreachable!(),
            Ok((_, header)) => {
                gst_trace!(CAT, obj: element, "Got AAC packet header {:?}", header);
                match header.packet_type {
                    flavors::AACPacketType::SequenceHeader => {
                        drop(data);
                        adapter.flush(1);
                        let buffer = adapter
                            .take_buffer((tag_header.data_size - 1 - 1) as usize)
                            .unwrap();
                        gst_debug!(CAT, obj: element, "Got AAC sequence header {:?}", buffer,);

                        self.aac_sequence_header = Some(buffer);
                        Ok(true)
                    }
                    flavors::AACPacketType::Raw => {
                        drop(data);
                        adapter.flush(1);
                        Ok(false)
                    }
                }
            }
        }
    }

    fn handle_audio_tag(
        &mut self,
        element: &gst::Element,
        tag_header: &flavors::TagHeader,
        adapter: &mut gst_base::UniqueAdapter,
    ) -> Result<SmallVec<[Event; 4]>, gst::ErrorMessage> {
        assert!(adapter.available() >= tag_header.data_size as usize);

        let data = adapter.map(1).unwrap();
        let data_header = match flavors::audio_data_header(&*data) {
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
                gst_error!(CAT, obj: element, "Invalid audio data header: {:?}", err);
                drop(data);
                adapter.flush(tag_header.data_size as usize);
                return Ok(SmallVec::new());
            }
            Err(nom::Err::Incomplete(_)) => unreachable!(),
            Ok((_, data_header)) => data_header,
        };
        drop(data);
        adapter.flush(1);

        let mut events = self.update_audio_stream(element, &data_header)?;

        // AAC special case
        if data_header.sound_format == flavors::SoundFormat::AAC
            && self.handle_aac_audio_packet_header(element, &tag_header, adapter)?
        {
            return Ok(events);
        }

        let offset = match data_header.sound_format {
            flavors::SoundFormat::AAC => 2,
            _ => 1,
        };

        if tag_header.data_size == offset {
            return Ok(events);
        }

        if self.audio == None {
            adapter.flush((tag_header.data_size - offset) as usize);
            return Ok(events);
        }

        let mut buffer = adapter
            .take_buffer((tag_header.data_size - offset) as usize)
            .unwrap();

        {
            let buffer = buffer.get_mut().unwrap();
            buffer.set_pts(gst::ClockTime::from_mseconds(tag_header.timestamp as u64));
        }

        gst_trace!(
            CAT,
            obj: element,
            "Outputting audio buffer {:?} for tag {:?}",
            buffer,
            tag_header,
        );

        self.update_position(&buffer);

        events.push(Event::Buffer(Stream::Audio, buffer));

        Ok(events)
    }

    fn update_video_stream(
        &mut self,
        element: &gst::Element,
        data_header: &flavors::VideoDataHeader,
    ) -> Result<SmallVec<[Event; 4]>, gst::ErrorMessage> {
        let mut events = SmallVec::new();

        gst_trace!(
            CAT,
            obj: element,
            "Got video data header: {:?}",
            data_header
        );

        let new_video_format =
            VideoFormat::new(data_header, &self.metadata, &self.avc_sequence_header);

        if self.video.as_ref() != Some(&new_video_format) {
            gst_debug!(
                CAT,
                obj: element,
                "Got new video format: {:?}",
                new_video_format
            );

            let caps = new_video_format.to_caps();
            if let Some(caps) = caps {
                self.video = Some(new_video_format);
                events.push(Event::StreamChanged(Stream::Video, caps));
            } else {
                self.video = None;
            }
        }

        if (!self.expect_audio || self.audio != None) && self.video != None && !self.got_all_streams
        {
            gst_debug!(CAT, obj: element, "Have all expected streams now");
            self.got_all_streams = true;
            events.push(Event::HaveAllStreams);
        }

        Ok(events)
    }

    fn handle_avc_video_packet_header(
        &mut self,
        element: &gst::Element,
        tag_header: &flavors::TagHeader,
        adapter: &mut gst_base::UniqueAdapter,
    ) -> Result<Option<i32>, gst::ErrorMessage> {
        // Not big enough for the AVC packet header, skip!
        if tag_header.data_size < 1 + 4 {
            adapter.flush((tag_header.data_size - 1) as usize);
            gst_warning!(
                CAT,
                obj: element,
                "Too small packet for AVC packet header {}",
                tag_header.data_size
            );
            return Ok(None);
        }

        let data = adapter.map(4).unwrap();
        match flavors::avc_video_packet_header(&*data) {
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
                gst_error!(
                    CAT,
                    obj: element,
                    "Invalid AVC video packet header: {:?}",
                    err
                );
                drop(data);
                adapter.flush((tag_header.data_size - 1) as usize);
                Ok(None)
            }
            Err(nom::Err::Incomplete(_)) => unreachable!(),
            Ok((_, header)) => {
                gst_trace!(CAT, obj: element, "Got AVC packet header {:?}", header);
                match header.packet_type {
                    flavors::AVCPacketType::SequenceHeader => {
                        drop(data);
                        adapter.flush(4);
                        let buffer = adapter
                            .take_buffer((tag_header.data_size - 1 - 4) as usize)
                            .unwrap();
                        gst_debug!(
                            CAT,
                            obj: element,
                            "Got AVC sequence header {:?} of size {}",
                            buffer,
                            tag_header.data_size - 1 - 4
                        );

                        self.avc_sequence_header = Some(buffer);
                        Ok(None)
                    }
                    flavors::AVCPacketType::NALU => {
                        drop(data);
                        adapter.flush(4);
                        Ok(Some(header.composition_time))
                    }
                    flavors::AVCPacketType::EndOfSequence => {
                        // Skip
                        drop(data);
                        adapter.flush((tag_header.data_size - 1) as usize);
                        Ok(None)
                    }
                }
            }
        }
    }

    fn handle_video_tag(
        &mut self,
        element: &gst::Element,
        tag_header: &flavors::TagHeader,
        adapter: &mut gst_base::UniqueAdapter,
    ) -> Result<SmallVec<[Event; 4]>, gst::ErrorMessage> {
        assert!(adapter.available() >= tag_header.data_size as usize);

        let data = adapter.map(1).unwrap();
        let data_header = match flavors::video_data_header(&*data) {
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
                gst_error!(CAT, obj: element, "Invalid video data header: {:?}", err);
                drop(data);
                adapter.flush(tag_header.data_size as usize);
                return Ok(SmallVec::new());
            }
            Err(nom::Err::Incomplete(_)) => unreachable!(),
            Ok((_, data_header)) => data_header,
        };
        drop(data);
        adapter.flush(1);

        let mut events = self.update_video_stream(element, &data_header)?;

        // AVC/H264 special case
        let cts = if data_header.codec_id == flavors::CodecId::H264 {
            match self.handle_avc_video_packet_header(element, tag_header, adapter)? {
                Some(cts) => cts,
                None => {
                    return Ok(events);
                }
            }
        } else {
            0
        };

        let offset = match data_header.codec_id {
            flavors::CodecId::H264 => 5,
            _ => 1,
        };

        if tag_header.data_size == offset {
            return Ok(events);
        }

        if self.video == None {
            adapter.flush((tag_header.data_size - offset) as usize);
            return Ok(events);
        }

        let is_keyframe = data_header.frame_type == flavors::FrameType::Key;

        let skip = match data_header.codec_id {
            flavors::CodecId::VP6 | flavors::CodecId::VP6A => 1,
            _ => 0,
        };

        if skip > 0 {
            adapter.flush(skip as usize);
        }

        if tag_header.data_size == offset + skip {
            return Ok(events);
        }

        let mut buffer = adapter
            .take_buffer((tag_header.data_size - offset - skip) as usize)
            .unwrap();

        {
            let buffer = buffer.get_mut().unwrap();
            if !is_keyframe {
                buffer.set_flags(gst::BufferFlags::DELTA_UNIT);
            }
            buffer.set_dts(gst::ClockTime::from_mseconds(tag_header.timestamp as u64));

            // Prevent negative numbers
            let pts = if cts < 0 && tag_header.timestamp < (-cts) as u32 {
                0
            } else {
                ((tag_header.timestamp as i64) + (cts as i64)) as u64
            };
            buffer.set_pts(gst::ClockTime::from_mseconds(pts));
        }

        gst_trace!(
            CAT,
            obj: element,
            "Outputting video buffer {:?} for tag {:?}, keyframe: {}",
            buffer,
            tag_header,
            is_keyframe
        );

        self.update_position(&buffer);

        events.push(Event::Buffer(Stream::Video, buffer));

        Ok(events)
    }

    fn update_position(&mut self, buffer: &gst::Buffer) {
        if buffer.get_pts() != gst::CLOCK_TIME_NONE {
            let pts = buffer.get_pts();
            self.last_position = self
                .last_position
                .map(|last| cmp::max(last.into(), pts))
                .unwrap_or(pts);
        } else if buffer.get_dts() != gst::CLOCK_TIME_NONE {
            let dts = buffer.get_dts();
            self.last_position = self
                .last_position
                .map(|last| cmp::max(last.into(), dts))
                .unwrap_or(dts);
        }
    }
}

// Ignores bitrate
impl PartialEq for AudioFormat {
    fn eq(&self, other: &Self) -> bool {
        self.format.eq(&other.format)
            && self.rate.eq(&other.rate)
            && self.width.eq(&other.width)
            && self.channels.eq(&other.channels)
            && self.aac_sequence_header.eq(&other.aac_sequence_header)
    }
}

impl AudioFormat {
    fn new(
        data_header: &flavors::AudioDataHeader,
        metadata: &Option<Metadata>,
        aac_sequence_header: &Option<gst::Buffer>,
    ) -> AudioFormat {
        let numeric_rate = match (data_header.sound_format, data_header.sound_rate) {
            (flavors::SoundFormat::NELLYMOSER_16KHZ_MONO, _) => 16_000,
            (flavors::SoundFormat::NELLYMOSER_8KHZ_MONO, _)
            | (flavors::SoundFormat::PCM_ALAW, _)
            | (flavors::SoundFormat::PCM_ULAW, _)
            | (flavors::SoundFormat::MP3_8KHZ, _) => 8_000,
            (flavors::SoundFormat::SPEEX, _) => 16_000,
            (_, flavors::SoundRate::_5_5KHZ) => 5_512,
            (_, flavors::SoundRate::_11KHZ) => 11_025,
            (_, flavors::SoundRate::_22KHZ) => 22_050,
            (_, flavors::SoundRate::_44KHZ) => 44_100,
        };

        let numeric_width = match data_header.sound_size {
            flavors::SoundSize::Snd8bit => 8,
            flavors::SoundSize::Snd16bit => 16,
        };

        let numeric_channels = match data_header.sound_type {
            flavors::SoundType::SndMono => 1,
            flavors::SoundType::SndStereo => 2,
        };

        AudioFormat {
            format: data_header.sound_format,
            rate: numeric_rate,
            width: numeric_width,
            channels: numeric_channels,
            bitrate: metadata.as_ref().and_then(|m| m.audio_bitrate),
            aac_sequence_header: aac_sequence_header.clone(),
        }
    }

    fn update_with_metadata(&mut self, metadata: &Metadata) -> bool {
        if self.bitrate != metadata.audio_bitrate {
            self.bitrate = metadata.audio_bitrate;
            true
        } else {
            false
        }
    }

    fn to_caps(&self) -> Option<gst::Caps> {
        let mut caps = match self.format {
            flavors::SoundFormat::MP3 | flavors::SoundFormat::MP3_8KHZ => Some(
                gst::Caps::new_simple("audio/mpeg", &[("mpegversion", &1i32), ("layer", &3i32)]),
            ),
            flavors::SoundFormat::PCM_NE | flavors::SoundFormat::PCM_LE => {
                if self.rate != 0 && self.channels != 0 {
                    // Assume little-endian for "PCM_NE", it's probably more common and we have no
                    // way to know what the endianness of the system creating the stream was
                    Some(gst::Caps::new_simple(
                        "audio/x-raw",
                        &[
                            ("layout", &"interleaved"),
                            ("format", &if self.width == 8 { "U8" } else { "S16LE" }),
                        ],
                    ))
                } else {
                    None
                }
            }
            flavors::SoundFormat::ADPCM => Some(gst::Caps::new_simple(
                "audio/x-adpcm",
                &[("layout", &"swf")],
            )),
            flavors::SoundFormat::NELLYMOSER_16KHZ_MONO
            | flavors::SoundFormat::NELLYMOSER_8KHZ_MONO
            | flavors::SoundFormat::NELLYMOSER => {
                Some(gst::Caps::new_simple("audio/x-nellymoser", &[]))
            }
            flavors::SoundFormat::PCM_ALAW => Some(gst::Caps::new_simple("audio/x-alaw", &[])),
            flavors::SoundFormat::PCM_ULAW => Some(gst::Caps::new_simple("audio/x-mulaw", &[])),
            flavors::SoundFormat::AAC => self.aac_sequence_header.as_ref().map(|header| {
                gst::Caps::new_simple(
                    "audio/mpeg",
                    &[
                        ("mpegversion", &4i32),
                        ("framed", &true),
                        ("stream-format", &"raw"),
                        ("codec_data", &header),
                    ],
                )
            }),
            flavors::SoundFormat::SPEEX => {
                use crate::bytes::*;
                use std::io::{Cursor, Write};

                let header = {
                    let header_size = 80;
                    let mut data = Cursor::new(Vec::with_capacity(header_size));
                    data.write_all(b"Speex   1.1.12").unwrap();
                    data.write_all(&[0; 14]).unwrap();
                    data.write_u32le(1).unwrap(); // version
                    data.write_u32le(80).unwrap(); // header size
                    data.write_u32le(16_000).unwrap(); // sample rate
                    data.write_u32le(1).unwrap(); // mode = wideband
                    data.write_u32le(4).unwrap(); // mode bitstream version
                    data.write_u32le(1).unwrap(); // channels
                    data.write_i32le(-1).unwrap(); // bitrate
                    data.write_u32le(0x50).unwrap(); // frame size
                    data.write_u32le(0).unwrap(); // VBR
                    data.write_u32le(1).unwrap(); // frames per packet
                    data.write_u32le(0).unwrap(); // extra headers
                    data.write_u32le(0).unwrap(); // reserved 1
                    data.write_u32le(0).unwrap(); // reserved 2

                    assert_eq!(data.position() as usize, header_size);

                    data.into_inner()
                };
                let header = gst::Buffer::from_mut_slice(header);

                let comment = {
                    let comment_size = 4 + 7 /* nothing */ + 4 + 1;
                    let mut data = Cursor::new(Vec::with_capacity(comment_size));
                    data.write_u32le(7).unwrap(); // length of "nothing"
                    data.write_all(b"nothing").unwrap(); // "vendor" string
                    data.write_u32le(0).unwrap(); // number of elements
                    data.write_u8(1).unwrap();

                    assert_eq!(data.position() as usize, comment_size);

                    data.into_inner()
                };
                let comment = gst::Buffer::from_mut_slice(comment);

                Some(gst::Caps::new_simple(
                    "audio/x-speex",
                    &[("streamheader", &gst::Array::new(&[&header, &comment]))],
                ))
            }
            flavors::SoundFormat::DEVICE_SPECIFIC => {
                // Nobody knows
                None
            }
        };

        if self.rate != 0 {
            if let Some(ref mut caps) = caps.as_mut() {
                caps.get_mut()
                    .unwrap()
                    .set_simple(&[("rate", &(self.rate as i32))])
            }
        }
        if self.channels != 0 {
            if let Some(ref mut caps) = caps.as_mut() {
                caps.get_mut()
                    .unwrap()
                    .set_simple(&[("channels", &(self.channels as i32))])
            }
        }

        caps
    }
}

// Ignores bitrate
impl PartialEq for VideoFormat {
    fn eq(&self, other: &Self) -> bool {
        self.format.eq(&other.format)
            && self.width.eq(&other.width)
            && self.height.eq(&other.height)
            && self.pixel_aspect_ratio.eq(&other.pixel_aspect_ratio)
            && self.framerate.eq(&other.framerate)
            && self.avc_sequence_header.eq(&other.avc_sequence_header)
    }
}

impl VideoFormat {
    fn new(
        data_header: &flavors::VideoDataHeader,
        metadata: &Option<Metadata>,
        avc_sequence_header: &Option<gst::Buffer>,
    ) -> VideoFormat {
        VideoFormat {
            format: data_header.codec_id,
            width: metadata.as_ref().and_then(|m| m.video_width),
            height: metadata.as_ref().and_then(|m| m.video_height),
            pixel_aspect_ratio: metadata.as_ref().and_then(|m| m.video_pixel_aspect_ratio),
            framerate: metadata.as_ref().and_then(|m| m.video_framerate),
            bitrate: metadata.as_ref().and_then(|m| m.video_bitrate),
            avc_sequence_header: avc_sequence_header.clone(),
        }
    }

    fn update_with_metadata(&mut self, metadata: &Metadata) -> bool {
        let mut changed = false;

        if self.width != metadata.video_width {
            self.width = metadata.video_width;
            changed = true;
        }

        if self.height != metadata.video_height {
            self.height = metadata.video_height;
            changed = true;
        }

        if self.pixel_aspect_ratio != metadata.video_pixel_aspect_ratio {
            self.pixel_aspect_ratio = metadata.video_pixel_aspect_ratio;
            changed = true;
        }

        if self.framerate != metadata.video_framerate {
            self.framerate = metadata.video_framerate;
            changed = true;
        }

        if self.bitrate != metadata.video_bitrate {
            self.bitrate = metadata.video_bitrate;
            changed = true;
        }

        changed
    }

    fn to_caps(&self) -> Option<gst::Caps> {
        let mut caps = match self.format {
            flavors::CodecId::SORENSON_H263 => Some(gst::Caps::new_simple(
                "video/x-flash-video",
                &[("flvversion", &1i32)],
            )),
            flavors::CodecId::SCREEN => Some(gst::Caps::new_simple("video/x-flash-screen", &[])),
            flavors::CodecId::VP6 => Some(gst::Caps::new_simple("video/x-vp6-flash", &[])),
            flavors::CodecId::VP6A => Some(gst::Caps::new_simple("video/x-vp6-flash-alpha", &[])),
            flavors::CodecId::SCREEN2 => Some(gst::Caps::new_simple("video/x-flash-screen2", &[])),
            flavors::CodecId::H264 => self.avc_sequence_header.as_ref().map(|header| {
                gst::Caps::new_simple(
                    "video/x-h264",
                    &[("stream-format", &"avc"), ("codec_data", &header)],
                )
            }),
            flavors::CodecId::H263 => Some(gst::Caps::new_simple("video/x-h263", &[])),
            flavors::CodecId::MPEG4Part2 => Some(gst::Caps::new_simple(
                "video/mpeg",
                &[("mpegversion", &4i32), ("systemstream", &false)],
            )),
            flavors::CodecId::JPEG => {
                // Unused according to spec
                None
            }
        };

        if let (Some(width), Some(height)) = (self.width, self.height) {
            if let Some(ref mut caps) = caps.as_mut() {
                caps.get_mut()
                    .unwrap()
                    .set_simple(&[("width", &(width as i32)), ("height", &(height as i32))])
            }
        }

        if let Some(par) = self.pixel_aspect_ratio {
            if *par.numer() != 0 && par.numer() != par.denom() {
                if let Some(ref mut caps) = caps.as_mut() {
                    caps.get_mut().unwrap().set_simple(&[(
                        "pixel-aspect-ratio",
                        &gst::Fraction::new(*par.numer(), *par.denom()),
                    )])
                }
            }
        }

        if let Some(fps) = self.framerate {
            if *fps.numer() != 0 {
                if let Some(ref mut caps) = caps.as_mut() {
                    caps.get_mut().unwrap().set_simple(&[(
                        "framerate",
                        &gst::Fraction::new(*fps.numer(), *fps.denom()),
                    )])
                }
            }
        }

        caps
    }
}

impl Metadata {
    fn new(script_data: &flavors::ScriptData) -> Metadata {
        assert_eq!(script_data.name, "onMetaData");

        let mut metadata = Metadata::default();

        let args = match script_data.arguments {
            flavors::ScriptDataValue::Object(ref objects)
            | flavors::ScriptDataValue::ECMAArray(ref objects) => objects,
            _ => return metadata,
        };

        let mut par_n = None;
        let mut par_d = None;

        for arg in args {
            match (arg.name, &arg.data) {
                ("duration", &flavors::ScriptDataValue::Number(duration)) => {
                    metadata.duration = ((duration * 1000.0 * 1000.0 * 1000.0) as u64).into();
                }
                ("creationdate", &flavors::ScriptDataValue::String(date)) => {
                    metadata.creation_date = Some(String::from(date));
                }
                ("creator", &flavors::ScriptDataValue::String(creator)) => {
                    metadata.creator = Some(String::from(creator));
                }
                ("title", &flavors::ScriptDataValue::String(title)) => {
                    metadata.title = Some(String::from(title));
                }
                ("metadatacreator", &flavors::ScriptDataValue::String(creator)) => {
                    metadata.metadata_creator = Some(String::from(creator));
                }
                ("audiodatarate", &flavors::ScriptDataValue::Number(datarate)) => {
                    metadata.audio_bitrate = Some((datarate * 1024.0) as u32);
                }
                ("width", &flavors::ScriptDataValue::Number(width)) => {
                    metadata.video_width = Some(width as u32);
                }
                ("height", &flavors::ScriptDataValue::Number(height)) => {
                    metadata.video_height = Some(height as u32);
                }
                ("framerate", &flavors::ScriptDataValue::Number(framerate)) if framerate >= 0.0 => {
                    if let Some(framerate) = Rational32::approximate_float(framerate) {
                        metadata.video_framerate = Some(framerate);
                    }
                }
                ("AspectRatioX", &flavors::ScriptDataValue::Number(par_x)) if par_x > 0.0 => {
                    par_n = Some(par_x as i32);
                }
                ("AspectRatioY", &flavors::ScriptDataValue::Number(par_y)) if par_y > 0.0 => {
                    par_d = Some(par_y as i32);
                }
                ("videodatarate", &flavors::ScriptDataValue::Number(datarate)) => {
                    metadata.video_bitrate = Some((datarate * 1024.0) as u32);
                }
                _ => {}
            }
        }

        if let (Some(par_n), Some(par_d)) = (par_n, par_d) {
            metadata.video_pixel_aspect_ratio = Some(Rational32::new(par_n, par_d));
        }

        metadata
    }
}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "rsflvdemux",
        gst::Rank::None,
        FlvDemux::get_type(),
    )
}
