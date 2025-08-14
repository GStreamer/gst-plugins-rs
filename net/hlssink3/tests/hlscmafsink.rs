// Copyright (C) 2025 Sanchayan Maity <sanchayan@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gio::prelude::*;
use gst::prelude::*;
use gsthlssink3::hlssink3::HlsSink3PlaylistType;
use std::io::Write;
use std::sync::{mpsc, Arc, Mutex};

mod common;
use crate::common::*;

fn init() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        gst::init().unwrap();
        gstfmp4::plugin_register_static().expect("Need cmafmux for hlscmafsink test");
        gsthlssink3::plugin_register_static().expect("hlscmafsink test");
    });
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum HlsSinkEvent {
    GetPlaylistStream(String),
    GetFragmentStream(String),
    SegmentAddedMessage(String),
}

struct MemoryPlaylistFile {
    handler: Arc<Mutex<String>>,
}

impl MemoryPlaylistFile {
    fn clear_content(&self) {
        let mut string = self.handler.lock().unwrap();
        string.clear();
    }
}

impl Write for MemoryPlaylistFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let value = std::str::from_utf8(buf).unwrap();
        let mut string = self.handler.lock().unwrap();
        string.push_str(value);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_hlscmafsink_video_with_single_media_file() -> Result<(), ()> {
    init();

    let pipeline = gst::Pipeline::with_name("video_pipeline");

    let video_src = gst::ElementFactory::make("videotestsrc")
        .property("is-live", true)
        .property("num-buffers", 512i32)
        .build()
        .unwrap();

    let caps = gst::Caps::builder("video/x-raw")
        .field("wifth", 320)
        .field("height", 240)
        .field("format", "I420")
        .field("framerate", gst::Fraction::new(30, 1))
        .build();
    let capsfilter = gst::ElementFactory::make("capsfilter")
        .property("caps", caps)
        .build()
        .expect("Must be able to instantiate capsfilter");
    let videorate = gst::ElementFactory::make("videorate").build().unwrap();
    let x264enc = gst::ElementFactory::make("x264enc")
        .property("key-int-max", 60u32)
        .property("bitrate", 2000u32)
        .property_from_str("speed-preset", "ultrafast")
        .property_from_str("tune", "zerolatency")
        .build()
        .expect("Must be able to instantiate x264enc");
    let h264parse = gst::ElementFactory::make("h264parse").build().unwrap();

    let hlscmafsink = gst::ElementFactory::make("hlscmafsink")
        .name("test_hlscmafsink")
        .property("target-duration", 6u32)
        .property("single-media-file", "main.mp4")
        .build()
        .expect("Must be able to instantiate hlscmafsinksink");

    hlscmafsink.set_property("playlist-type", HlsSink3PlaylistType::Vod);
    let pl_type: HlsSink3PlaylistType = hlscmafsink.property("playlist-type");
    assert_eq!(pl_type, HlsSink3PlaylistType::Vod);

    let (hls_events_sender, hls_events_receiver) = mpsc::sync_channel(5);
    let (hls_messages_sender, hls_messages_receiver) = mpsc::sync_channel(5);
    let playlist_content = Arc::new(Mutex::new(String::from("")));

    hlscmafsink.connect("get-playlist-stream", false, {
        let hls_events_sender = hls_events_sender.clone();
        let playlist_content = playlist_content.clone();
        move |args| {
            let location = args[1].get::<String>().expect("No location given");

            hls_events_sender
                .try_send(HlsSinkEvent::GetPlaylistStream(location))
                .expect("Send playlist event");

            let playlist = MemoryPlaylistFile {
                handler: Arc::clone(&playlist_content),
            };

            playlist.clear_content();
            let output = gio::WriteOutputStream::new(playlist);
            Some(output.to_value())
        }
    });

    hlscmafsink.connect("get-fragment-stream", false, {
        let hls_events_sender = hls_events_sender.clone();
        move |args| {
            let location = args[1].get::<String>().expect("No location given");

            hls_events_sender
                .try_send(HlsSinkEvent::GetFragmentStream(location))
                .expect("Send fragment event");

            let stream = gio::MemoryOutputStream::new_resizable();
            Some(stream.to_value())
        }
    });

    pipeline
        .add_many([
            &video_src,
            &capsfilter,
            &videorate,
            &x264enc,
            &h264parse,
            &hlscmafsink,
        ])
        .unwrap();
    gst::Element::link_many([
        &video_src,
        &capsfilter,
        &videorate,
        &x264enc,
        &h264parse,
        &hlscmafsink,
    ])
    .unwrap();

    pipeline.set_state(gst::State::Playing).unwrap();

    let mut byte_ranges: Vec<ByteRange> = Vec::new();
    let mut eos = false;
    let bus = pipeline.bus().unwrap();
    while let Some(msg) = bus.timed_pop(gst::ClockTime::NONE) {
        use gst::MessageView;
        match msg.view() {
            MessageView::Eos(..) => {
                eos = true;
                break;
            }
            MessageView::Element(msg) => {
                if let Some(structure) = msg.structure() {
                    if structure.has_name("hls-segment-added") {
                        let location = structure.get::<String>("location").unwrap();
                        let byte_range = get_byte_ranges(structure);
                        byte_ranges.extend(byte_range);

                        hls_messages_sender
                            .try_send(HlsSinkEvent::SegmentAddedMessage(location))
                            .expect("Send segment added event");
                    }
                }
            }
            MessageView::Error(err) => panic!("{err}"),
            _ => (),
        }
    }

    pipeline.set_state(gst::State::Null).unwrap();
    assert!(eos);

    let mut actual_events = Vec::new();
    while let Ok(event) = hls_events_receiver.try_recv() {
        actual_events.push(event);
    }

    let mut actual_messages = Vec::new();
    while let Ok(event) = hls_messages_receiver.try_recv() {
        actual_messages.push(event);
    }

    eprintln!("Playlist byte ranges: {byte_ranges:?}");
    // We only validate the byte range and map tag. The actual value of
    // byte range can differ from each run and hence we do not validate
    // the entire playlist.
    assert!(validate_byterange_sequence(&byte_ranges));
    assert!(all_ranges_non_overlapping(&byte_ranges));

    let expected_messages = {
        use self::HlsSinkEvent::*;
        vec![
            // For single media file, location of added segment will
            // always be same.
            SegmentAddedMessage("main.mp4".to_string()),
            SegmentAddedMessage("main.mp4".to_string()),
            SegmentAddedMessage("main.mp4".to_string()),
        ]
    };
    assert_eq!(expected_messages, actual_messages);

    let expected_ordering_of_events = {
        use self::HlsSinkEvent::*;
        vec![
            // For single media file, GET_FRAGMENT_STREAM will only be
            // emitted once.
            GetFragmentStream("main.mp4".to_string()),
            GetPlaylistStream("playlist.m3u8".to_string()),
            GetPlaylistStream("playlist.m3u8".to_string()),
            GetPlaylistStream("playlist.m3u8".to_string()),
            GetPlaylistStream("playlist.m3u8".to_string()),
        ]
    };
    assert_eq!(expected_ordering_of_events, actual_events);

    Ok(())
}
