//
// Copyright (C) 2021 Rafael Caricio <rafael@caricio.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use crate::playlist::{Playlist, SegmentFormatter};
use gio::prelude::*;
use glib::subclass::prelude::*;
use gst::prelude::*;
use gst::subclass::prelude::*;
use gst::{gst_debug, gst_error, gst_info, gst_trace, gst_warning};
use m3u8_rs::MediaPlaylistType;
use once_cell::sync::Lazy;
use std::fs;
use std::io::Write;
use std::path;
use std::sync::{Arc, Mutex};

const DEFAULT_LOCATION: &str = "segment%05d.ts";
const DEFAULT_PLAYLIST_LOCATION: &str = "playlist.m3u8";
const DEFAULT_MAX_NUM_SEGMENT_FILES: u32 = 10;
const DEFAULT_TARGET_DURATION: u32 = 15;
const DEFAULT_PLAYLIST_LENGTH: u32 = 5;
const DEFAULT_SEND_KEYFRAME_REQUESTS: bool = true;

const SIGNAL_GET_PLAYLIST_STREAM: &str = "get-playlist-stream";
const SIGNAL_GET_FRAGMENT_STREAM: &str = "get-fragment-stream";
const SIGNAL_DELETE_FRAGMENT: &str = "delete-fragment";

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new("hlssink3", gst::DebugColorFlags::empty(), Some("HLS sink"))
});

struct Settings {
    location: String,
    segment_formatter: SegmentFormatter,
    playlist_location: String,
    playlist_root: Option<String>,
    playlist_length: u32,
    playlist_type: Option<MediaPlaylistType>,
    max_num_segment_files: usize,
    target_duration: u32,
    send_keyframe_requests: bool,

    splitmuxsink: gst::Element,
    giostreamsink: gst::Element,
    video_sink: bool,
    audio_sink: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let splitmuxsink = gst::ElementFactory::make("splitmuxsink", Some("split_mux_sink"))
            .expect("Could not make element splitmuxsink");
        let giostreamsink = gst::ElementFactory::make("giostreamsink", Some("giostream_sink"))
            .expect("Could not make element giostreamsink");
        Self {
            location: String::from(DEFAULT_LOCATION),
            segment_formatter: SegmentFormatter::new(DEFAULT_LOCATION).unwrap(),
            playlist_location: String::from(DEFAULT_PLAYLIST_LOCATION),
            playlist_root: None,
            playlist_length: DEFAULT_PLAYLIST_LENGTH,
            playlist_type: None,
            max_num_segment_files: DEFAULT_MAX_NUM_SEGMENT_FILES as usize,
            target_duration: DEFAULT_TARGET_DURATION,
            send_keyframe_requests: DEFAULT_SEND_KEYFRAME_REQUESTS,

            splitmuxsink,
            giostreamsink,
            video_sink: false,
            audio_sink: false,
        }
    }
}

pub(crate) struct StartedState {
    playlist: Playlist,
    fragment_opened_at: Option<gst::ClockTime>,
    current_segment_location: Option<String>,
    old_segment_locations: Vec<String>,
}

impl StartedState {
    fn new(target_duration: f32, playlist_type: Option<MediaPlaylistType>) -> Self {
        Self {
            playlist: Playlist::new(target_duration, playlist_type),
            current_segment_location: None,
            fragment_opened_at: None,
            old_segment_locations: Vec::new(),
        }
    }

    fn fragment_duration_since(&self, fragment_closed: gst::ClockTime) -> f32 {
        assert!(self.fragment_opened_at.is_some());
        let fragment_opened_at = &self.fragment_opened_at.unwrap();
        let segment_duration = fragment_closed - fragment_opened_at;
        segment_duration.mseconds() as f32 / 1_000f32
    }
}

enum State {
    Stopped,
    Started(StartedState),
}

impl Default for State {
    fn default() -> Self {
        Self::Stopped
    }
}

#[derive(Default, Clone)]
pub struct HlsSink3 {
    settings: Arc<Mutex<Settings>>,
    state: Arc<Mutex<State>>,
}

impl HlsSink3 {
    fn start(&self, element: &super::HlsSink3) {
        gst_info!(CAT, obj: element, "Starting");

        let (target_duration, playlist_type) = {
            let settings = self.settings.lock().unwrap();
            (
                settings.target_duration as f32,
                settings.playlist_type.clone(),
            )
        };

        let mut state = self.state.lock().unwrap();
        if let State::Stopped = *state {
            *state = State::Started(StartedState::new(target_duration, playlist_type));
        }
    }

    fn on_format_location(
        &self,
        element: &super::HlsSink3,
        fragment_id: u32,
    ) -> Result<String, String> {
        gst_info!(
            CAT,
            obj: element,
            "Starting the formatting of the fragment-id: {}",
            fragment_id
        );

        // TODO: Create method in state to simplify this boilerplate: `let state = self.state.started()?`
        let mut state_guard = self.state.lock().unwrap();
        let state = match &mut *state_guard {
            State::Stopped => return Err("Not in Started state".to_string()),
            State::Started(s) => s,
        };

        let settings = self.settings.lock().unwrap();
        let segment_file_location = settings.segment_formatter.segment(fragment_id);
        gst_trace!(
            CAT,
            obj: element,
            "Segment location formatted: {}",
            segment_file_location
        );

        state.current_segment_location = Some(segment_file_location.clone());

        let fragment_stream = element
            .emit_by_name::<Option<gio::OutputStream>>(
                SIGNAL_GET_FRAGMENT_STREAM,
                &[&segment_file_location],
            )
            .ok_or_else(|| String::from("Error while getting fragment stream"))?;

        settings
            .giostreamsink
            .set_property("stream", &fragment_stream);

        gst_info!(
            CAT,
            obj: element,
            "New segment location: {:?}",
            state.current_segment_location.as_ref()
        );
        Ok(segment_file_location)
    }

    fn new_file_stream<P>(
        &self,
        element: &super::HlsSink3,
        location: &P,
    ) -> Result<gio::OutputStream, String>
    where
        P: AsRef<path::Path>,
    {
        let file = fs::File::create(location).map_err(move |err| {
            let error_msg = gst::error_msg!(
                gst::ResourceError::OpenWrite,
                [
                    "Could not open file {} for writing: {}",
                    location.as_ref().to_str().unwrap(),
                    err.to_string(),
                ]
            );
            element.post_error_message(error_msg);
            err.to_string()
        })?;
        Ok(gio::WriteOutputStream::new(file).upcast())
    }

    fn delete_fragment<P>(&self, element: &super::HlsSink3, location: &P)
    where
        P: AsRef<path::Path>,
    {
        let _ = fs::remove_file(location).map_err(|err| {
            gst_warning!(
                CAT,
                obj: element,
                "Could not delete segment file: {}",
                err.to_string()
            );
        });
    }

    fn write_playlist(
        &self,
        element: &super::HlsSink3,
        fragment_closed_at: Option<gst::ClockTime>,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        gst_info!(CAT, obj: element, "Preparing to write new playlist");

        let mut state_guard = self.state.lock().unwrap();
        let state = match &mut *state_guard {
            State::Stopped => return Err(gst::StateChangeError),
            State::Started(s) => s,
        };

        gst_info!(CAT, obj: element, "COUNT {}", state.playlist.len());

        // Only add fragment if it's complete.
        if let Some(fragment_closed) = fragment_closed_at {
            let segment_filename = self.segment_filename(state);
            state.playlist.add_segment(
                segment_filename.clone(),
                state.fragment_duration_since(fragment_closed),
            );
            state.old_segment_locations.push(segment_filename);
        }

        let (playlist_location, max_num_segments, max_playlist_length) = {
            let settings = self.settings.lock().unwrap();
            (
                settings.playlist_location.clone(),
                settings.max_num_segment_files,
                settings.playlist_length as usize,
            )
        };

        state.playlist.update_playlist_state(max_playlist_length);

        // Acquires the playlist file handle so we can update it with new content. By default, this
        // is expected to be the same file every time.
        let mut playlist_stream = element
            .emit_by_name::<Option<gio::OutputStream>>(
                SIGNAL_GET_PLAYLIST_STREAM,
                &[&playlist_location],
            )
            .ok_or_else(|| {
                gst_error!(
                    CAT,
                    obj: element,
                    "Could not get stream to write playlist content",
                );
                gst::StateChangeError
            })?
            .into_write();

        state
            .playlist
            .write_to(&mut playlist_stream)
            .map_err(|err| {
                gst_error!(
                    CAT,
                    obj: element,
                    "Could not write new playlist: {}",
                    err.to_string()
                );
                gst::StateChangeError
            })?;
        playlist_stream.flush().map_err(|err| {
            gst_error!(
                CAT,
                obj: element,
                "Could not flush playlist: {}",
                err.to_string()
            );
            gst::StateChangeError
        })?;

        if state.playlist.is_type_undefined() {
            // Cleanup old segments from filesystem
            if state.old_segment_locations.len() > max_num_segments {
                for _ in 0..state.old_segment_locations.len() - max_num_segments {
                    let old_segment_location = state.old_segment_locations.remove(0);
                    if !element
                        .emit_by_name::<bool>(SIGNAL_DELETE_FRAGMENT, &[&old_segment_location])
                    {
                        gst_error!(CAT, obj: element, "Could not delete fragment");
                    }
                }
            }
        }

        gst_debug!(CAT, obj: element, "Wrote new playlist file!");
        Ok(gst::StateChangeSuccess::Success)
    }

    fn segment_filename(&self, state: &mut StartedState) -> String {
        assert!(state.current_segment_location.is_some());
        let segment_filename = path_basename(state.current_segment_location.take().unwrap());

        let settings = self.settings.lock().unwrap();
        if let Some(playlist_root) = &settings.playlist_root {
            format!("{}/{}", playlist_root, segment_filename)
        } else {
            segment_filename
        }
    }

    fn write_final_playlist(
        &self,
        element: &super::HlsSink3,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        gst_debug!(CAT, obj: element, "Preparing to write final playlist");
        self.write_playlist(element, None)
    }

    fn stop(&self, element: &super::HlsSink3) {
        gst_debug!(CAT, obj: element, "Stopping");

        let mut state = self.state.lock().unwrap();
        if let State::Started(_) = *state {
            *state = State::Stopped;
        }

        gst_debug!(CAT, obj: element, "Stopped");
    }
}

#[glib::object_subclass]
impl ObjectSubclass for HlsSink3 {
    const NAME: &'static str = "GstHlsSink3";
    type Type = super::HlsSink3;
    type ParentType = gst::Bin;
}

impl BinImpl for HlsSink3 {
    #[allow(clippy::single_match)]
    fn handle_message(&self, element: &Self::Type, msg: gst::Message) {
        use gst::MessageView;

        match msg.view() {
            MessageView::Element(ref msg) => {
                let event_is_from_splitmuxsink = {
                    let settings = self.settings.lock().unwrap();

                    msg.src().as_ref() == Some(settings.splitmuxsink.upcast_ref())
                };
                if !event_is_from_splitmuxsink {
                    return;
                }

                let s = msg.structure().unwrap();
                match s.name() {
                    "splitmuxsink-fragment-opened" => {
                        if let Ok(new_fragment_opened_at) = s.get::<gst::ClockTime>("running-time")
                        {
                            let mut state = self.state.lock().unwrap();
                            match &mut *state {
                                State::Stopped => {}
                                State::Started(state) => {
                                    state.fragment_opened_at = Some(new_fragment_opened_at)
                                }
                            };
                        }
                    }
                    "splitmuxsink-fragment-closed" => {
                        let s = msg.structure().unwrap();
                        if let Ok(fragment_closed_at) = s.get::<gst::ClockTime>("running-time") {
                            self.write_playlist(element, Some(fragment_closed_at))
                                .unwrap();
                        }
                    }
                    _ => {}
                }
            }
            _ => self.parent_handle_message(element, msg),
        }
    }
}

impl ObjectImpl for HlsSink3 {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecString::new(
                    "location",
                    "File Location",
                    "Location of the file to write",
                    Some(DEFAULT_LOCATION),
                    glib::ParamFlags::READWRITE,
                ),
                glib::ParamSpecString::new(
                    "playlist-location",
                    "Playlist Location",
                    "Location of the playlist to write.",
                    Some(DEFAULT_PLAYLIST_LOCATION),
                    glib::ParamFlags::READWRITE,
                ),
                glib::ParamSpecString::new(
                    "playlist-root",
                    "Playlist Root",
                    "Base path for the segments in the playlist file.",
                    None,
                    glib::ParamFlags::READWRITE,
                ),
                glib::ParamSpecUInt::new(
                    "max-files",
                    "Max files",
                    "Maximum number of files to keep on disk. Once the maximum is reached, old files start to be deleted to make room for new ones.",
                    0,
                    u32::MAX,
                    DEFAULT_MAX_NUM_SEGMENT_FILES,
                    glib::ParamFlags::READWRITE,
                ),
                glib::ParamSpecUInt::new(
                    "target-duration",
                    "Target duration",
                    "The target duration in seconds of a segment/file. (0 - disabled, useful for management of segment duration by the streaming server)",
                    0,
                    u32::MAX,
                    DEFAULT_TARGET_DURATION,
                    glib::ParamFlags::READWRITE,
                ),
                glib::ParamSpecUInt::new(
                    "playlist-length",
                    "Playlist length",
                    "Length of HLS playlist. To allow players to conform to section 6.3.3 of the HLS specification, this should be at least 3. If set to 0, the playlist will be infinite.",
                    0,
                    u32::MAX,
                    DEFAULT_PLAYLIST_LENGTH,
                    glib::ParamFlags::READWRITE,
                ),
                glib::ParamSpecString::new(
                    "playlist-type",
                    "Playlist Type",
                    "The type of the playlist to use. When VOD type is set, the playlist will be live until the pipeline ends execution.",
                    None,
                    glib::ParamFlags::READWRITE,
                ),
                glib::ParamSpecBoolean::new(
                    "send-keyframe-requests",
                    "Send Keyframe Requests",
                    "Send keyframe requests to ensure correct fragmentation. If this is disabled then the input must have keyframes in regular intervals.",
                    DEFAULT_SEND_KEYFRAME_REQUESTS,
                    glib::ParamFlags::READWRITE,
                ),
            ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(
        &self,
        _obj: &Self::Type,
        _id: usize,
        value: &glib::Value,
        pspec: &glib::ParamSpec,
    ) {
        let mut settings = self.settings.lock().unwrap();
        match pspec.name() {
            "location" => {
                settings.location = value
                    .get::<Option<String>>()
                    .expect("type checked upstream")
                    .unwrap_or_else(|| DEFAULT_LOCATION.into());
                settings.segment_formatter = SegmentFormatter::new(&settings.location).expect(
                    "A string containing `%03d` pattern must be used (can be any number from 0-9)",
                );
                settings
                    .splitmuxsink
                    .set_property("location", &settings.location);
            }
            "playlist-location" => {
                settings.playlist_location = value
                    .get::<Option<String>>()
                    .expect("type checked upstream")
                    .unwrap_or_else(|| String::from(DEFAULT_PLAYLIST_LOCATION));
            }
            "playlist-root" => {
                settings.playlist_root = value
                    .get::<Option<String>>()
                    .expect("type checked upstream");
            }
            "max-files" => {
                let max_files: u32 = value.get().expect("type checked upstream");
                settings.max_num_segment_files = max_files as usize;
            }
            "target-duration" => {
                settings.target_duration = value.get().expect("type checked upstream");
                settings.splitmuxsink.set_property(
                    "max-size-time",
                    &(gst::ClockTime::from_seconds(settings.target_duration as u64)),
                );
            }
            "playlist-length" => {
                settings.playlist_length = value.get().expect("type checked upstream");
            }
            "playlist-type" => {
                settings.playlist_type = value
                    .get::<Option<String>>()
                    .expect("type checked upstream")
                    .map(|chosen_type| {
                        if chosen_type.to_lowercase() == "vod" {
                            MediaPlaylistType::Vod
                        } else {
                            MediaPlaylistType::Event
                        }
                    })
            }
            "send-keyframe-requests" => {
                settings.send_keyframe_requests = value.get().expect("type checked upstream");
                settings
                    .splitmuxsink
                    .set_property("send-keyframe-requests", &settings.send_keyframe_requests);
            }
            _ => unimplemented!(),
        };
    }

    fn property(&self, _obj: &Self::Type, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        let settings = self.settings.lock().unwrap();
        match pspec.name() {
            "location" => settings.location.to_value(),
            "playlist-location" => settings.playlist_location.to_value(),
            "playlist-root" => settings.playlist_root.to_value(),
            "max-files" => {
                let max_files = settings.max_num_segment_files as u32;
                max_files.to_value()
            }
            "target-duration" => settings.target_duration.to_value(),
            "playlist-length" => settings.playlist_length.to_value(),
            "playlist-type" => settings
                .playlist_type
                .as_ref()
                .map(|ty| ty.to_string())
                .to_value(),
            "send-keyframe-requests" => settings.send_keyframe_requests.to_value(),
            _ => unimplemented!(),
        }
    }

    fn signals() -> &'static [glib::subclass::Signal] {
        static SIGNALS: Lazy<Vec<glib::subclass::Signal>> = Lazy::new(|| {
            vec![
                glib::subclass::Signal::builder(
                    SIGNAL_GET_PLAYLIST_STREAM,
                    &[String::static_type().into()],
                    gio::OutputStream::static_type().into(),
                )
                .class_handler(|_, args| {
                    let element = args[0]
                        .get::<super::HlsSink3>()
                        .expect("playlist-stream signal arg");
                    let playlist_location =
                        args[1].get::<String>().expect("playlist-stream signal arg");
                    let hlssink3 = element.imp();

                    Some(
                        hlssink3
                            .new_file_stream(&element, &playlist_location)
                            .ok()?
                            .to_value(),
                    )
                })
                .accumulator(|_hint, ret, value| {
                    // First signal handler wins
                    *ret = value.clone();
                    false
                })
                .build(),
                glib::subclass::Signal::builder(
                    SIGNAL_GET_FRAGMENT_STREAM,
                    &[String::static_type().into()],
                    gio::OutputStream::static_type().into(),
                )
                .class_handler(|_, args| {
                    let element = args[0]
                        .get::<super::HlsSink3>()
                        .expect("fragment-stream signal arg");
                    let fragment_location =
                        args[1].get::<String>().expect("fragment-stream signal arg");
                    let hlssink3 = element.imp();

                    Some(
                        hlssink3
                            .new_file_stream(&element, &fragment_location)
                            .ok()?
                            .to_value(),
                    )
                })
                .accumulator(|_hint, ret, value| {
                    // First signal handler wins
                    *ret = value.clone();
                    false
                })
                .build(),
                glib::subclass::Signal::builder(
                    SIGNAL_DELETE_FRAGMENT,
                    &[String::static_type().into()],
                    glib::types::Type::BOOL.into(),
                )
                .class_handler(|_, args| {
                    let element = args[0].get::<super::HlsSink3>().expect("signal arg");
                    let fragment_location = args[1].get::<String>().expect("signal arg");
                    let hlssink3 = element.imp();

                    hlssink3.delete_fragment(&element, &fragment_location);
                    Some(true.to_value())
                })
                .accumulator(|_hint, ret, value| {
                    // First signal handler wins
                    *ret = value.clone();
                    false
                })
                .build(),
            ]
        });

        SIGNALS.as_ref()
    }

    fn constructed(&self, obj: &Self::Type) {
        self.parent_constructed(obj);

        obj.set_element_flags(gst::ElementFlags::SINK);
        obj.set_suppressed_flags(gst::ElementFlags::SINK | gst::ElementFlags::SOURCE);

        let settings = self.settings.lock().unwrap();

        let mux = gst::ElementFactory::make("mpegtsmux", Some("mpeg-ts_mux"))
            .expect("Could not make element mpegtsmux");

        let location: Option<String> = None;
        settings.splitmuxsink.set_properties(&[
            ("location", &location),
            (
                "max-size-time",
                &(gst::ClockTime::from_seconds(settings.target_duration as u64)),
            ),
            ("send-keyframe-requests", &settings.send_keyframe_requests),
            ("muxer", &mux),
            ("sink", &settings.giostreamsink),
            ("reset-muxer", &false),
        ]);

        obj.add(&settings.splitmuxsink).unwrap();

        settings.splitmuxsink.connect("format-location", false, {
            let element_weak = obj.downgrade();
            move |args| {
                let element = match element_weak.upgrade() {
                    Some(element) => element,
                    None => return Some(None::<String>.to_value()),
                };
                let hlssink3 = element.imp();

                let fragment_id = args[1].get::<u32>().unwrap();

                gst_info!(CAT, obj: &element, "Got fragment-id: {}", fragment_id);

                match hlssink3.on_format_location(&element, fragment_id) {
                    Ok(segment_location) => Some(segment_location.to_value()),
                    Err(err) => {
                        gst_error!(CAT, obj: &element, "on format-location handler: {}", err);
                        Some("unknown_segment".to_value())
                    }
                }
            }
        });
    }
}

impl GstObjectImpl for HlsSink3 {}

impl ElementImpl for HlsSink3 {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "HTTP Live Streaming sink",
                "Sink/Muxer",
                "HTTP Live Streaming sink",
                "Alessandro Decina <alessandro.d@gmail.com>, \
                Sebastian Dröge <sebastian@centricular.com>, \
                Rafael Caricio <rafael@caricio.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: Lazy<Vec<gst::PadTemplate>> = Lazy::new(|| {
            let caps = gst::Caps::new_any();
            let video_pad_template = gst::PadTemplate::new(
                "video",
                gst::PadDirection::Sink,
                gst::PadPresence::Request,
                &caps,
            )
            .unwrap();

            let caps = gst::Caps::new_any();
            let audio_pad_template = gst::PadTemplate::new(
                "audio",
                gst::PadDirection::Sink,
                gst::PadPresence::Request,
                &caps,
            )
            .unwrap();

            vec![video_pad_template, audio_pad_template]
        });

        PAD_TEMPLATES.as_ref()
    }

    fn change_state(
        &self,
        element: &Self::Type,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        if let gst::StateChange::NullToReady = transition {
            self.start(element);
        }

        let ret = self.parent_change_state(element, transition)?;

        match transition {
            gst::StateChange::PausedToReady => {
                let write_final = {
                    let mut state = self.state.lock().unwrap();
                    match &mut *state {
                        State::Stopped => false,
                        State::Started(state) => {
                            if state.playlist.is_rendering() {
                                state.playlist.stop();
                                true
                            } else {
                                false
                            }
                        }
                    }
                };

                if write_final {
                    self.write_final_playlist(element)?;
                }
            }
            gst::StateChange::ReadyToNull => {
                self.stop(element);
            }
            _ => (),
        }

        Ok(ret)
    }

    fn request_new_pad(
        &self,
        element: &Self::Type,
        templ: &gst::PadTemplate,
        _name: Option<String>,
        _caps: Option<&gst::Caps>,
    ) -> Option<gst::Pad> {
        let mut settings = self.settings.lock().unwrap();
        match templ.name_template().as_ref().map(|val| val.as_str()) {
            Some("audio") => {
                if settings.audio_sink {
                    gst_debug!(
                        CAT,
                        obj: element,
                        "requested_new_pad: audio pad is already set"
                    );
                    return None;
                }

                let peer_pad = settings.splitmuxsink.request_pad_simple("audio_0").unwrap();
                let sink_pad =
                    gst::GhostPad::from_template_with_target(templ, Some("audio"), &peer_pad)
                        .unwrap();
                element.add_pad(&sink_pad).unwrap();
                sink_pad.set_active(true).unwrap();
                settings.audio_sink = true;

                Some(sink_pad.upcast())
            }
            Some("video") => {
                if settings.video_sink {
                    gst_debug!(
                        CAT,
                        obj: element,
                        "requested_new_pad: video pad is already set"
                    );
                    return None;
                }
                let peer_pad = settings.splitmuxsink.request_pad_simple("video").unwrap();

                let sink_pad =
                    gst::GhostPad::from_template_with_target(templ, Some("video"), &peer_pad)
                        .unwrap();
                element.add_pad(&sink_pad).unwrap();
                sink_pad.set_active(true).unwrap();
                settings.video_sink = true;

                Some(sink_pad.upcast())
            }
            None => {
                gst_debug!(CAT, obj: element, "template name returned `None`",);
                None
            }
            Some(other_name) => {
                gst_debug!(
                    CAT,
                    obj: element,
                    "requested_new_pad: name \"{}\" is not audio or video",
                    other_name
                );
                None
            }
        }
    }

    fn release_pad(&self, element: &Self::Type, pad: &gst::Pad) {
        let mut settings = self.settings.lock().unwrap();

        if !settings.audio_sink && !settings.video_sink {
            return;
        }

        let ghost_pad = pad.downcast_ref::<gst::GhostPad>().unwrap();
        if let Some(peer) = ghost_pad.target() {
            settings.splitmuxsink.release_request_pad(&peer);
        }

        pad.set_active(false).unwrap();
        element.remove_pad(pad).unwrap();

        if "audio" == ghost_pad.name() {
            settings.audio_sink = false;
        } else {
            settings.video_sink = false;
        }
    }
}

/// The content of the last item of a path separated by `/` character.
fn path_basename(name: impl AsRef<str>) -> String {
    name.as_ref().split('/').last().unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_extract_basenames() {
        for (input, output) in [
            ("", ""),
            ("value", "value"),
            ("/my/nice/path.ts", "path.ts"),
            ("file.ts", "file.ts"),
            ("https://localhost/output/file.vtt", "file.vtt"),
        ] {
            assert_eq!(path_basename(input), output);
        }
    }
}
