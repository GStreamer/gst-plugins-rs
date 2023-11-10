// Copyright (C) 2021 OneStream Live <guillaume.desmottes@onestream.live>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use std::sync::{mpsc, Mutex, MutexGuard};
use std::sync::{Arc, Weak};

use gst::glib;
use gst::prelude::*;
use gst::subclass::prelude::*;

use gst::glib::once_cell::sync::Lazy;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "uriplaylistbin",
        gst::DebugColorFlags::empty(),
        Some("Uri Playlist Bin"),
    )
});

/// how many items are allowed to be prepared and waiting in the pipeline
const MAX_STREAMING_ITEMS: usize = 2;

#[derive(Debug, thiserror::Error)]
enum PlaylistError {
    #[error("plugin missing: {error}")]
    PluginMissing { error: anyhow::Error },
    #[error("{item:?} failed: {error}")]
    ItemFailed { error: anyhow::Error, item: Item },
}

/// Number of different streams currently handled by the element
#[derive(Debug, Default, Clone, PartialEq)]
struct StreamsTopology {
    audio: u32,
    video: u32,
    text: u32,
}

impl StreamsTopology {
    fn n_streams(&self) -> u32 {
        self.audio + self.video + self.text
    }
}

impl From<gst::StreamCollection> for StreamsTopology {
    fn from(collection: gst::StreamCollection) -> Self {
        let (mut audio, mut video, mut text) = (0, 0, 0);
        for stream in collection.iter() {
            match stream.stream_type() {
                gst::StreamType::AUDIO => audio += 1,
                gst::StreamType::VIDEO => video += 1,
                gst::StreamType::TEXT => text += 1,
                _ => {}
            }
        }

        Self { audio, video, text }
    }
}

#[derive(Debug, Clone)]
struct Settings {
    uris: Vec<String>,
    iterations: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            uris: vec![],
            iterations: 1,
        }
    }
}

#[derive(Debug)]
enum Status {
    /// all good element is working
    Running,
    /// the element stopped because of an error
    Error,
    /// the element is being shut down
    ShuttingDown,
}

impl Status {
    /// check if the element should stop proceeding
    fn done(&self) -> bool {
        match self {
            Status::Running => false,
            Status::Error | Status::ShuttingDown => true,
        }
    }
}

#[derive(Debug)]
struct State {
    streamsynchronizer: gst::Element,
    concat_audio: Vec<gst::Element>,
    concat_video: Vec<gst::Element>,
    concat_text: Vec<gst::Element>,

    playlist: Playlist,

    /// the current number of streams handled by the element
    streams_topology: StreamsTopology,
    status: Status,

    // we have max one item in one of each of those states
    waiting_for_stream_collection: Option<Item>,
    waiting_for_ss_eos: Option<Item>,
    waiting_for_pads: Option<Item>,
    blocked: Option<Item>,
    // multiple items can be streaming, `concat` elements will block them all but the active one
    streaming: Vec<Item>,
    // items which have been fully played, waiting to be cleaned up
    done: Vec<Item>,

    // read-only properties
    current_iteration: u32,
    current_uri_index: u64,
}

impl State {
    fn new(uris: Vec<String>, iterations: u32, streamsynchronizer: gst::Element) -> Self {
        Self {
            concat_audio: vec![],
            concat_video: vec![],
            concat_text: vec![],
            streamsynchronizer,
            playlist: Playlist::new(uris, iterations),
            streams_topology: StreamsTopology::default(),
            status: Status::Running,
            waiting_for_stream_collection: None,
            waiting_for_ss_eos: None,
            waiting_for_pads: None,
            blocked: None,
            streaming: vec![],
            done: vec![],
            current_iteration: 0,
            current_uri_index: 0,
        }
    }

    /// Return the item whose decodebin is either `src` or an ancestor of `src`
    fn find_item_from_src(&self, src: &gst::Object) -> Option<Item> {
        // iterate in all the places we store `Item`, ordering does not matter
        // as one decodebin element can be in only one Item.
        let mut items = self
            .waiting_for_stream_collection
            .iter()
            .chain(self.waiting_for_ss_eos.iter())
            .chain(self.waiting_for_pads.iter())
            .chain(self.blocked.iter())
            .chain(self.streaming.iter())
            .chain(self.done.iter());

        items
            .find(|item| {
                let decodebin = item.uridecodebin();
                let from_decodebin = src == &decodebin;
                let bin = decodebin.downcast_ref::<gst::Bin>().unwrap();
                from_decodebin || src.has_as_ancestor(bin)
            })
            .cloned()
    }

    fn unblock_item(&mut self, imp: &UriPlaylistBin) {
        if let Some(blocked) = self.blocked.take() {
            let (messages, channels) = blocked.set_streaming(self.streams_topology.n_streams());

            gst::log!(
                CAT,
                imp: imp,
                "send pending message of item #{} and unblock its pads",
                blocked.index()
            );

            // send pending messages then unblock pads
            for msg in messages {
                let _ = imp.obj().post_message(msg);
            }

            channels.send(true);

            self.streaming.push(blocked);
        }
    }
}

#[derive(Default)]
pub struct UriPlaylistBin {
    settings: Mutex<Settings>,
    state: Mutex<Option<State>>,
}

#[derive(Debug, Clone)]
enum ItemState {
    /// Waiting to create a decodebin element
    Pending,
    /// Waiting to receive the stream collection from its decodebin element
    WaitingForStreamCollection { uridecodebin: gst::Element },
    /// Waiting for streamsynchronizer to be eos on all its src pads.
    /// Only used to block item whose streams topology is different from the one
    /// currently handled by the element. In such case we need to wait for
    /// streamsynchronizer to be flushed before adding/removing concat elements.
    WaitingForStreamsynchronizerEos {
        uridecodebin: gst::Element,
        /// src pads from decodebin currently blocked
        decodebin_pads: Vec<gst::Pad>,
        /// number of streamsynchronizer src pads which are not eos yet
        waiting_eos: u32,
        stream_collection_msg: gst::Message,
        // channels used to block pads flow until streamsynchronizer is eos
        channels: Channels,
    },
    /// Waiting that pads of all the streams have been created on decodebin.
    /// Required to ensure that streams are plugged to concat in the playlist order.
    WaitingForPads {
        uridecodebin: gst::Element,
        n_pads_pendings: u32,
        stream_collection_msg: gst::Message,
        /// concat sink pads which have been requested to handle this item
        concat_sink_pads: Vec<(gst::Element, gst::Pad)>,
        // channels used to block pad flow in the Blocked state
        channels: Channels,
    },
    /// Pads have been linked to `concat` elements but are blocked until the next item is linked to `concat` as well.
    /// This is required to ensure gap-less transition between items.
    Blocked {
        uridecodebin: gst::Element,
        stream_collection_msg: gst::Message,
        stream_selected_msg: Option<gst::Message>,
        concat_sink_pads: Vec<(gst::Element, gst::Pad)>,
        channels: Channels,
    },
    /// Buffers are flowing
    Streaming {
        uridecodebin: gst::Element,
        concat_sink_pads: Vec<(gst::Element, gst::Pad)>,
        // number of pads which are not eos yet
        waiting_eos: u32,
    },
    /// Item has been fully streamed
    Done {
        uridecodebin: gst::Element,
        concat_sink_pads: Vec<(gst::Element, gst::Pad)>,
    },
}

#[derive(Debug, Clone)]
struct Item {
    inner: Arc<Mutex<ItemInner>>,
}

impl Item {
    fn new(uri: String, index: usize) -> Self {
        let inner = ItemInner {
            uri,
            index,
            state: ItemState::Pending,
        };

        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    fn uri(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.uri.clone()
    }

    fn index(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.index
    }

    fn uridecodebin(&self) -> gst::Element {
        let inner = self.inner.lock().unwrap();

        match &inner.state {
            ItemState::WaitingForStreamCollection { uridecodebin }
            | ItemState::WaitingForStreamsynchronizerEos { uridecodebin, .. }
            | ItemState::WaitingForPads { uridecodebin, .. }
            | ItemState::Blocked { uridecodebin, .. }
            | ItemState::Streaming { uridecodebin, .. }
            | ItemState::Done { uridecodebin, .. } => uridecodebin.clone(),
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    fn concat_sink_pads(&self) -> Vec<(gst::Element, gst::Pad)> {
        let inner = self.inner.lock().unwrap();

        match &inner.state {
            ItemState::WaitingForPads {
                concat_sink_pads, ..
            }
            | ItemState::Blocked {
                concat_sink_pads, ..
            }
            | ItemState::Streaming {
                concat_sink_pads, ..
            }
            | ItemState::Done {
                concat_sink_pads, ..
            } => concat_sink_pads.clone(),
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    fn dec_n_pads_pending(&self) -> u32 {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::WaitingForPads {
                n_pads_pendings, ..
            } => {
                *n_pads_pendings -= 1;
                *n_pads_pendings
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    fn receiver(&self) -> mpsc::Receiver<bool> {
        let mut inner = self.inner.lock().unwrap();

        let channels = match &mut inner.state {
            ItemState::WaitingForPads { channels, .. } => channels,
            ItemState::WaitingForStreamsynchronizerEos { channels, .. } => channels,
            // receiver is no longer supposed to be accessed once in the `Blocked` state
            _ => panic!("invalid state: {:?}", inner.state),
        };

        channels.get_receiver()
    }

    fn add_blocked_pad(&self, pad: gst::Pad) {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::WaitingForStreamsynchronizerEos { decodebin_pads, .. } => {
                decodebin_pads.push(pad);
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    /// decrement waiting_eos on a WaitingForStreamsynchronizeEos item, returns if all the streams are now eos or not
    fn dec_waiting_eos_ss(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::WaitingForStreamsynchronizerEos { waiting_eos, .. } => {
                *waiting_eos -= 1;
                *waiting_eos == 0
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    fn is_streaming(&self) -> bool {
        let inner = self.inner.lock().unwrap();

        matches!(&inner.state, ItemState::Streaming { .. })
    }

    /// queue the stream-selected message of a blocked item
    fn add_stream_selected(&self, msg: gst::Message) {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::Blocked {
                stream_selected_msg,
                ..
            } => {
                *stream_selected_msg = Some(msg);
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    // decrement waiting_eos on a Streaming item, returns if all the streams are now eos or not
    fn dec_waiting_eos(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::Streaming { waiting_eos, .. } => {
                *waiting_eos -= 1;
                *waiting_eos == 0
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    fn add_concat_sink_pad(&self, concat: &gst::Element, sink_pad: &gst::Pad) {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::WaitingForPads {
                concat_sink_pads, ..
            } => {
                concat_sink_pads.push((concat.clone(), sink_pad.clone()));
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    // change state methods

    // from the Pending state, called when starting to process the item
    fn set_waiting_for_stream_collection(&self) -> Result<(), PlaylistError> {
        let mut inner = self.inner.lock().unwrap();

        let uridecodebin = gst::ElementFactory::make("uridecodebin3")
            .name(&format!("playlist-decodebin-{}", inner.index))
            .property("uri", &inner.uri)
            .build()
            .map_err(|e| PlaylistError::PluginMissing { error: e.into() })?;

        assert!(matches!(inner.state, ItemState::Pending));
        inner.state = ItemState::WaitingForStreamCollection { uridecodebin };

        Ok(())
    }

    // from the WaitingForStreamCollection state, called when we received the item stream collection
    // and its stream topology matches what is currently being processed by the element.
    fn set_waiting_for_pads(&self, n_streams: u32, msg: &gst::message::StreamCollection) {
        let mut inner = self.inner.lock().unwrap();
        assert!(matches!(
            inner.state,
            ItemState::WaitingForStreamCollection { .. }
        ));

        match &inner.state {
            ItemState::WaitingForStreamCollection { uridecodebin } => {
                inner.state = ItemState::WaitingForPads {
                    uridecodebin: uridecodebin.clone(),
                    n_pads_pendings: n_streams,
                    stream_collection_msg: msg.copy(),
                    concat_sink_pads: vec![],
                    channels: Channels::default(),
                };
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    // from the WaitingForStreamCollection state, called when we received the item stream collection
    // but its stream topology does not match what is currently being processed by the element,
    // having to wait until streamsynchronizer is flushed to internally reorganize the element.
    fn set_waiting_for_ss_eos(&self, waiting_eos: u32, msg: &gst::message::StreamCollection) {
        let mut inner = self.inner.lock().unwrap();

        match &inner.state {
            ItemState::WaitingForStreamCollection { uridecodebin } => {
                inner.state = ItemState::WaitingForStreamsynchronizerEos {
                    uridecodebin: uridecodebin.clone(),
                    decodebin_pads: vec![],
                    waiting_eos,
                    // FIXME: save deep copy once https://gitlab.freedesktop.org/gstreamer/gstreamer-rs/-/issues/363 is fixed
                    stream_collection_msg: msg.copy(),
                    channels: Channels::default(),
                };
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    // from the WaitingForStreamsynchronizerEos state, called when the streamsynchronizer has been flushed
    // and the item can now be processed.
    fn done_waiting_for_ss_eos(&self) -> (StreamsTopology, Vec<gst::Pad>, Channels) {
        let mut inner = self.inner.lock().unwrap();

        match &inner.state {
            ItemState::WaitingForStreamsynchronizerEos {
                uridecodebin,
                decodebin_pads,
                waiting_eos,
                stream_collection_msg,
                channels,
                ..
            } => {
                assert_eq!(*waiting_eos, 0);

                let topology = match stream_collection_msg.view() {
                    gst::MessageView::StreamCollection(stream_collection_msg) => {
                        StreamsTopology::from(stream_collection_msg.stream_collection())
                    }
                    _ => unreachable!(),
                };
                let pending_pads = decodebin_pads.clone();
                let channels = channels.clone();

                inner.state = ItemState::WaitingForPads {
                    uridecodebin: uridecodebin.clone(),
                    n_pads_pendings: topology.n_streams(),
                    stream_collection_msg: stream_collection_msg.copy(),
                    concat_sink_pads: vec![],
                    channels: Channels::default(),
                };

                (topology, pending_pads, channels)
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    // from the WaitingForPads state, called when all the pads from decodebin have been added and connected to concat elements.
    fn set_blocked(&self) {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::WaitingForPads {
                uridecodebin,
                channels,
                stream_collection_msg,
                concat_sink_pads,
                ..
            } => {
                inner.state = ItemState::Blocked {
                    uridecodebin: uridecodebin.clone(),
                    channels: channels.clone(),
                    concat_sink_pads: concat_sink_pads.clone(),
                    stream_collection_msg: stream_collection_msg.copy(),
                    stream_selected_msg: None,
                };
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    // from the Blocked state, called when the item streaming threads can be unblocked.
    // Return the queued messages from this item and the sender to unblock their pads
    fn set_streaming(&self, n_streams: u32) -> (Vec<gst::Message>, Channels) {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::Blocked {
                uridecodebin,
                channels,
                stream_collection_msg,
                stream_selected_msg,
                concat_sink_pads,
                ..
            } => {
                let mut messages = vec![stream_collection_msg.copy()];
                if let Some(msg) = stream_selected_msg {
                    messages.push(msg.copy());
                }
                let channels = channels.clone();

                inner.state = ItemState::Streaming {
                    uridecodebin: uridecodebin.clone(),
                    waiting_eos: n_streams,
                    concat_sink_pads: concat_sink_pads.clone(),
                };

                (messages, channels)
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    // from the Streaming state, called when the item has been fully processed and can be cleaned up
    fn set_done(&self) {
        let mut inner = self.inner.lock().unwrap();

        match &mut inner.state {
            ItemState::Streaming {
                uridecodebin,
                concat_sink_pads,
                ..
            } => {
                inner.state = ItemState::Done {
                    uridecodebin: uridecodebin.clone(),
                    concat_sink_pads: concat_sink_pads.clone(),
                };
            }
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    fn channels(&self) -> Channels {
        let inner = self.inner.lock().unwrap();

        match &inner.state {
            ItemState::WaitingForStreamsynchronizerEos { channels, .. } => channels.clone(),
            ItemState::WaitingForPads { channels, .. } => channels.clone(),
            ItemState::Blocked { channels, .. } => channels.clone(),
            _ => panic!("invalid state: {:?}", inner.state),
        }
    }

    fn downgrade(&self) -> Weak<Mutex<ItemInner>> {
        Arc::downgrade(&self.inner)
    }

    fn upgrade(weak: &Weak<Mutex<ItemInner>>) -> Option<Item> {
        weak.upgrade().map(|inner| Item { inner })
    }
}

#[derive(Debug, Clone)]
struct ItemInner {
    uri: String,
    index: usize,
    state: ItemState,
}

struct Playlist {
    items: Box<dyn Iterator<Item = Item> + Send>,

    uris: Vec<String>,
}

impl Playlist {
    fn new(uris: Vec<String>, iterations: u32) -> Self {
        Self {
            items: Self::create_items(uris.clone(), iterations),
            uris,
        }
    }

    fn create_items(
        uris: Vec<String>,
        iterations: u32,
    ) -> Box<dyn Iterator<Item = Item> + Send + Sync> {
        fn infinite_iter(uris: Vec<String>) -> Box<dyn Iterator<Item = Item> + Send + Sync> {
            Box::new(
                uris.into_iter()
                    .cycle()
                    .enumerate()
                    .map(|(index, uri)| Item::new(uri, index)),
            )
        }
        fn finite_iter(
            uris: Vec<String>,
            iterations: u32,
        ) -> Box<dyn Iterator<Item = Item> + Send + Sync> {
            let n = (iterations as usize)
                .checked_mul(uris.len())
                .unwrap_or(usize::MAX);

            Box::new(
                uris.into_iter()
                    .cycle()
                    .take(n)
                    .enumerate()
                    .map(|(index, uri)| Item::new(uri, index)),
            )
        }

        if iterations == 0 {
            infinite_iter(uris)
        } else {
            finite_iter(uris, iterations)
        }
    }

    fn next(&mut self) -> Result<Option<Item>, PlaylistError> {
        let item = match self.items.next() {
            None => return Ok(None),
            Some(item) => item,
        };

        if item.index() == usize::MAX {
            // prevent overflow with infinite playlist
            self.items = Self::create_items(self.uris.clone(), 0);
        }

        item.set_waiting_for_stream_collection()?;

        Ok(Some(item))
    }
}

impl std::fmt::Debug for Playlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Playlist")
            .field("uris", &self.uris)
            .finish()
    }
}

fn stream_type_from_pad_name(name: &str) -> anyhow::Result<(gst::StreamType, usize)> {
    if let Some(index) = name.strip_prefix("audio_") {
        Ok((gst::StreamType::AUDIO, index.parse().unwrap()))
    } else if let Some(index) = name.strip_prefix("video_") {
        Ok((gst::StreamType::VIDEO, index.parse().unwrap()))
    } else if let Some(index) = name.strip_prefix("text_") {
        Ok((gst::StreamType::TEXT, index.parse().unwrap()))
    } else {
        Err(anyhow::anyhow!("type of pad {} not supported", name))
    }
}

#[glib::object_subclass]
impl ObjectSubclass for UriPlaylistBin {
    const NAME: &'static str = "GstUriPlaylistBin";
    type Type = super::UriPlaylistBin;
    type ParentType = gst::Bin;
}

impl ObjectImpl for UriPlaylistBin {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecBoxed::builder::<Vec<String>>("uris")
                    .nick("URIs")
                    .blurb("URIs of the medias to play")
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt::builder("iterations")
                    .nick("Iterations")
                    .blurb("Number of time the playlist items should be played each (0 = unlimited)")
                    .default_value(1)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt::builder("current-iteration")
                    .nick("Current iteration")
                    .blurb("The index of the current playlist iteration, or 0 if the iterations property is 0 (unlimited playlist)")
                    .read_only()
                    .build(),
                glib::ParamSpecUInt64::builder("current-uri-index")
                    .nick("Current URI")
                    .blurb("The index from the uris property of the current URI being played")
                    .read_only()
                    .build(),
            ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "uris" => {
                let mut settings = self.settings.lock().unwrap();
                let new_value = value.get().expect("type checked upstream");
                gst::info!(
                    CAT,
                    imp: self,
                    "Changing uris from {:?} to {:?}",
                    settings.uris,
                    new_value,
                );
                settings.uris = new_value;
            }
            "iterations" => {
                let mut settings = self.settings.lock().unwrap();
                let new_value = value.get().expect("type checked upstream");
                gst::info!(
                    CAT,
                    imp: self,
                    "Changing iterations from {:?} to {:?}",
                    settings.iterations,
                    new_value,
                );
                settings.iterations = new_value;
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        match pspec.name() {
            "uris" => {
                let settings = self.settings.lock().unwrap();
                settings.uris.to_value()
            }
            "iterations" => {
                let settings = self.settings.lock().unwrap();
                settings.iterations.to_value()
            }
            "current-iteration" => {
                let state = self.state.lock().unwrap();
                state
                    .as_ref()
                    .map(|state| state.current_iteration)
                    .unwrap_or(0)
                    .to_value()
            }
            "current-uri-index" => {
                let state = self.state.lock().unwrap();
                state
                    .as_ref()
                    .map(|state| state.current_uri_index)
                    .unwrap_or(0)
                    .to_value()
            }
            _ => unimplemented!(),
        }
    }

    fn constructed(&self) {
        self.parent_constructed();

        let obj = self.obj();
        obj.set_suppressed_flags(gst::ElementFlags::SOURCE | gst::ElementFlags::SINK);
        obj.set_element_flags(gst::ElementFlags::SOURCE);
    }
}

impl GstObjectImpl for UriPlaylistBin {}

impl BinImpl for UriPlaylistBin {
    fn handle_message(&self, msg: gst::Message) {
        match msg.view() {
            gst::MessageView::StreamCollection(stream_collection_msg) => {
                if let Err(e) = self.handle_stream_collection(stream_collection_msg) {
                    self.failed(e);
                }
                // stream collection will be send when the item starts streaming
                return;
            }
            gst::MessageView::StreamsSelected(stream_selected) => {
                if !self.handle_stream_selected(stream_selected) {
                    return;
                }
            }
            gst::MessageView::Error(error) => {
                // find item which raised the error
                let mut state_guard = self.state.lock().unwrap();
                let state = state_guard.as_mut().unwrap();

                let src = error.src().unwrap();
                let item = state.find_item_from_src(src);

                drop(state_guard);

                if let Some(item) = item {
                    // handle the error message so we can add the failing uri as error details

                    self.failed(PlaylistError::ItemFailed {
                        error: anyhow::anyhow!(
                            "Error when processing item #{} ({}): {}",
                            item.index(),
                            item.uri(),
                            error.error().to_string()
                        ),
                        item,
                    });
                    return;
                }
            }
            _ => (),
        }

        self.parent_handle_message(msg)
    }
}

impl ElementImpl for UriPlaylistBin {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "Playlist Source",
                "Generic/Source",
                "Sequentially play uri streams",
                "Guillaume Desmottes <guillaume.desmottes@onestream.live>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: Lazy<Vec<gst::PadTemplate>> = Lazy::new(|| {
            let audio_src_pad_template = gst::PadTemplate::new(
                "audio_%u",
                gst::PadDirection::Src,
                gst::PadPresence::Sometimes,
                &gst::Caps::new_any(),
            )
            .unwrap();

            let video_src_pad_template = gst::PadTemplate::new(
                "video_%u",
                gst::PadDirection::Src,
                gst::PadPresence::Sometimes,
                &gst::Caps::new_any(),
            )
            .unwrap();

            let text_src_pad_template = gst::PadTemplate::new(
                "text_%u",
                gst::PadDirection::Src,
                gst::PadPresence::Sometimes,
                &gst::Caps::new_any(),
            )
            .unwrap();

            vec![
                audio_src_pad_template,
                video_src_pad_template,
                text_src_pad_template,
            ]
        });

        PAD_TEMPLATES.as_ref()
    }

    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        if transition == gst::StateChange::NullToReady {
            if let Err(e) = self.start() {
                self.failed(e);
                return Err(gst::StateChangeError);
            }
        }

        if transition == gst::StateChange::PausedToReady {
            let mut state_guard = self.state.lock().unwrap();
            let state = state_guard.as_mut().unwrap();

            state.status = Status::ShuttingDown;

            // The probe callback owns a ref on the item and so on the sender as well.
            // As a result we have to explicitly unblock all receivers as dropping the sender
            // is not enough.
            if let Some(item) = state.waiting_for_ss_eos.take() {
                item.channels().send(false);
            }
            if let Some(item) = state.waiting_for_pads.take() {
                item.channels().send(false);
            }
            if let Some(item) = state.blocked.take() {
                item.channels().send(false);
            }
        }

        let res = self.parent_change_state(transition);

        if transition == gst::StateChange::ReadyToNull {
            self.stop();
        }

        res
    }
}

impl UriPlaylistBin {
    fn start(&self) -> Result<(), PlaylistError> {
        gst::debug!(CAT, imp: self, "Starting");
        {
            let mut state_guard = self.state.lock().unwrap();
            assert!(state_guard.is_none());

            let streamsynchronizer = gst::ElementFactory::make("streamsynchronizer")
                .name("playlist-streamsync")
                .build()
                .map_err(|e| PlaylistError::PluginMissing { error: e.into() })?;

            self.obj().add(&streamsynchronizer).unwrap();

            let settings = self.settings.lock().unwrap();

            *state_guard = Some(State::new(
                settings.uris.clone(),
                settings.iterations,
                streamsynchronizer,
            ));
        }

        self.start_next_item()?;

        Ok(())
    }

    fn start_next_item(&self) -> Result<(), PlaylistError> {
        let mut state_guard = self.state.lock().unwrap();
        let state = state_guard.as_mut().unwrap();

        // clean up done items, so uridecodebin elements and concat sink pads don't pile up in the pipeline
        while let Some(done) = state.done.pop() {
            let uridecodebin = done.uridecodebin();
            gst::log!(CAT, imp: self, "remove {} from bin", uridecodebin.name());

            for (concat, sink_pad) in done.concat_sink_pads() {
                // calling release_request_pad() while holding the pad stream lock would deadlock
                concat.call_async(move |concat| {
                    concat.release_request_pad(&sink_pad);
                });
            }

            // can't change state from the streaming thread
            uridecodebin.call_async(move |uridecodebin| {
                let _ = uridecodebin.set_state(gst::State::Null);
            });

            self.obj().remove(&uridecodebin).unwrap();
        }

        if state.waiting_for_stream_collection.is_some()
            || state.waiting_for_pads.is_some()
            || state.waiting_for_ss_eos.is_some()
        {
            // another item is being prepared
            return Ok(());
        }

        let n_streaming = state.streaming.len();
        if n_streaming >= MAX_STREAMING_ITEMS {
            gst::log!(
                CAT,
                imp: self,
                "Too many items streaming ({}), wait before starting the next one",
                n_streaming
            );

            return Ok(());
        }

        let item = match state.playlist.next()? {
            Some(item) => item,
            None => {
                gst::debug!(CAT, imp: self, "no more item to queue",);

                // unblock last item
                state.unblock_item(self);

                self.update_current(state_guard);

                return Ok(());
            }
        };

        gst::debug!(
            CAT,
            imp: self,
            "start decoding item #{}: {}",
            item.index(),
            item.uri()
        );

        let uridecodebin = item.uridecodebin();

        self.obj().add(&uridecodebin).unwrap();

        let item_clone = item.clone();
        assert!(state.waiting_for_stream_collection.is_none());
        state.waiting_for_stream_collection = Some(item);

        uridecodebin.connect_pad_added(move |uridecodebin, src_pad| {
            let element = match uridecodebin
                .parent()
                .and_then(|p| p.downcast::<super::UriPlaylistBin>().ok())
            {
                Some(element) => element,
                None => return,
            };
            let imp = element.imp();
            let mut state_guard = imp.state.lock().unwrap();
            let state = state_guard.as_mut().unwrap();

            if let Some(item) = state.waiting_for_ss_eos.as_ref() {
                // block pad until streamsynchronizer is eos
                let imp_weak = imp.downgrade();
                let receiver = Mutex::new(item.receiver());

                gst::debug!(
                    CAT,
                    imp: imp,
                    "Block pad {} until streamsynchronizer is flushed",
                    src_pad.name(),
                );

                src_pad.add_probe(gst::PadProbeType::BLOCK_DOWNSTREAM, move |pad, _info| {
                    let Some(imp) = imp_weak.upgrade() else {
                        return gst::PadProbeReturn::Remove;
                    };

                    if let Some(parent) = pad.parent() {
                        let receiver = receiver.lock().unwrap();
                        let _ = receiver.recv();

                        gst::log!(
                            CAT,
                            imp: imp,
                            "pad {}:{} has been unblocked",
                            parent.name(),
                            pad.name()
                        );
                    }

                    gst::PadProbeReturn::Remove
                });

                item.add_blocked_pad(src_pad.clone());
            } else {
                drop(state_guard);
                imp.process_decodebin_pad(src_pad);
            }
        });

        drop(state_guard);

        uridecodebin
            .sync_state_with_parent()
            .map_err(|e| PlaylistError::ItemFailed {
                error: e.into(),
                item: item_clone,
            })?;

        Ok(())
    }

    fn handle_stream_collection(
        &self,
        stream_collection_msg: &gst::message::StreamCollection,
    ) -> Result<(), PlaylistError> {
        let mut state_guard = self.state.lock().unwrap();
        let state = state_guard.as_mut().unwrap();
        let src = stream_collection_msg.src().unwrap();

        if let Some(item) = state.waiting_for_stream_collection.clone() {
            // check message is from the decodebin we are waiting for
            let uridecodebin = item.uridecodebin();

            if src.has_as_ancestor(&uridecodebin) {
                let topology = StreamsTopology::from(stream_collection_msg.stream_collection());

                gst::debug!(
                    CAT,
                    imp: self,
                    "got stream collection from {}: {:?}",
                    src.name(),
                    topology
                );

                if state.streams_topology.n_streams() == 0 {
                    state.streams_topology = topology.clone();
                }

                assert!(state.waiting_for_pads.is_none());

                if state.streams_topology != topology {
                    gst::debug!(
                    CAT,
                    imp: self, "streams topoly changed ('{:?}' -> '{:?}'), waiting for streamsynchronize to be flushed",
                    state.streams_topology, topology);
                    item.set_waiting_for_ss_eos(
                        state.streams_topology.n_streams(),
                        stream_collection_msg,
                    );
                    state.waiting_for_ss_eos = Some(item);

                    // unblock previous item as we need it to be flushed out of streamsynchronizer
                    state.unblock_item(self);
                } else {
                    item.set_waiting_for_pads(topology.n_streams(), stream_collection_msg);
                    state.waiting_for_pads = Some(item);
                }

                state.waiting_for_stream_collection = None;

                self.update_current(state_guard);
            }
        }
        Ok(())
    }

    // return true if the message can be forwarded
    fn handle_stream_selected(&self, stream_selected_msg: &gst::message::StreamsSelected) -> bool {
        let mut state_guard = self.state.lock().unwrap();
        let state = state_guard.as_mut().unwrap();
        let src = stream_selected_msg.src().unwrap();

        if let Some(item) = state.blocked.clone() {
            let uridecodebin = item.uridecodebin();

            if src.has_as_ancestor(&uridecodebin) {
                // stream-selected message is from the blocked item, queue the message until it's unblocked
                gst::debug!(
                    CAT,
                    imp: self,
                    "queue stream-selected message from {} as item is currently blocked",
                    src.name(),
                );

                item.add_stream_selected(stream_selected_msg.copy());
                false
            } else {
                true
            }
        } else {
            true
        }
    }

    fn process_decodebin_pad(&self, src_pad: &gst::Pad) {
        let element = self.obj();

        let start_next = {
            let mut state_guard = self.state.lock().unwrap();
            let state = state_guard.as_mut().unwrap();

            if state.status.done() {
                return;
            }

            let item = match state.waiting_for_pads.as_ref() {
                Some(item) => item.clone(),
                None => return, // element is being shutdown
            };

            // Parse the pad name to extract the stream type and its index.
            // We could get the type from the Stream object from the StreamStart sticky event but we'd still have
            // to parse the name for the index.
            let pad_name = src_pad.name();
            let (stream_type, stream_index) = match stream_type_from_pad_name(&pad_name) {
                Ok((stream_type, stream_index)) => (stream_type, stream_index),
                Err(e) => {
                    gst::warning!(CAT, imp: self, "Ignoring pad {}: {}", pad_name, e);
                    return;
                }
            };

            let concat = match stream_type {
                gst::StreamType::AUDIO => state.concat_audio.get(stream_index),
                gst::StreamType::VIDEO => state.concat_video.get(stream_index),
                gst::StreamType::TEXT => state.concat_text.get(stream_index),
                _ => unreachable!(), // early return on unsupported streams above
            };

            let concat = match concat {
                None => {
                    gst::debug!(
                        CAT,
                        imp: self,
                        "stream {} from item #{}: creating concat element",
                        pad_name,
                        item.index()
                    );

                    let concat = match gst::ElementFactory::make("concat")
                        .name(&format!(
                            "playlist-concat-{}-{}",
                            stream_type.name(),
                            stream_index
                        ))
                        .build()
                    {
                        Ok(concat) => concat,
                        Err(_) => {
                            drop(state_guard);
                            self.failed(PlaylistError::PluginMissing {
                                error: anyhow::anyhow!("element 'concat' missing"),
                            });
                            return;
                        }
                    };

                    // this is done by the streamsynchronizer element downstream
                    concat.set_property("adjust-base", false);

                    element.add(&concat).unwrap();

                    concat.sync_state_with_parent().unwrap();

                    // link concat elements to streamsynchronizer
                    let concat_src = concat.static_pad("src").unwrap();
                    let sync_sink = state
                        .streamsynchronizer
                        .request_pad_simple("sink_%u")
                        .unwrap();
                    concat_src.link(&sync_sink).unwrap();

                    let element_weak = element.downgrade();

                    // add event probe on streamsynchronizer src pad. Will only be used when we are waiting for the
                    // streamsynchronizer to be flushed in order to handle streams topology changes.
                    let src_pad_name = sync_sink.name().to_string().replace("sink", "src");
                    let sync_src = state.streamsynchronizer.static_pad(&src_pad_name).unwrap();
                    sync_src.add_probe(gst::PadProbeType::EVENT_DOWNSTREAM, move |_pad, info| {
                        let Some(ev) = info.event() else {
                            return gst::PadProbeReturn::Pass;
                        };

                        if ev.type_() != gst::EventType::Eos {
                            return gst::PadProbeReturn::Pass;
                        }

                        let Some(element) = element_weak.upgrade() else {
                            return gst::PadProbeReturn::Remove;
                        };
                        let imp = element.imp();

                        let item = {
                            let mut state_guard = imp.state.lock().unwrap();
                            let state = state_guard.as_mut().unwrap();
                            state.waiting_for_ss_eos.as_ref().cloned()
                        };

                        if let Some(item) = item {
                            if item.dec_waiting_eos_ss() {
                                gst::debug!(CAT, imp: imp, "streamsynchronizer has been flushed, reorganize pipeline to fit new streams topology and unblock item");
                                imp.handle_topology_change();
                                gst::PadProbeReturn::Drop
                            } else {
                                gst::PadProbeReturn::Drop
                            }
                        } else {
                            gst::PadProbeReturn::Pass
                        }
                    });

                    // ghost streamsynchronizer src pad
                    let sync_src_name = sync_sink.name().as_str().replace("sink", "src");
                    let src = state.streamsynchronizer.static_pad(&sync_src_name).unwrap();
                    let ghost = gst::GhostPad::builder_with_target(&src)
                        .unwrap()
                        .name(pad_name.as_str())
                        .build();
                    ghost.set_active(true).unwrap();

                    // proxy sticky events
                    src.sticky_events_foreach(|event| {
                        use std::ops::ControlFlow;
                        let _ = ghost.store_sticky_event(event);
                        ControlFlow::Continue(gst::EventForeachAction::Keep)
                    });

                    unsafe {
                        ghost.set_event_function(|pad, parent, event| match event.view() {
                            gst::EventView::SelectStreams(_) => {
                                // TODO: handle select-streams event
                                if let Some(element) = parent {
                                    gst::fixme!(
                                        CAT,
                                        obj: element,
                                        "select-streams event not supported ('{:?}')",
                                        event
                                    );
                                }
                                false
                            }
                            _ => gst::Pad::event_default(pad, parent, event),
                        });
                    }

                    element.add_pad(&ghost).unwrap();

                    match stream_type {
                        gst::StreamType::AUDIO => {
                            state.concat_audio.push(concat.clone());
                        }
                        gst::StreamType::VIDEO => {
                            state.concat_video.push(concat.clone());
                        }
                        gst::StreamType::TEXT => {
                            state.concat_text.push(concat.clone());
                        }
                        _ => unreachable!(), // early return on unsupported streams above
                    }

                    concat
                }
                Some(concat) => {
                    gst::debug!(
                        CAT,
                        imp: self,
                        "stream {} from item #{}: re-using concat element {}",
                        pad_name,
                        item.index(),
                        concat.name()
                    );

                    concat.clone()
                }
            };

            let sink_pad = concat.request_pad_simple("sink_%u").unwrap();
            src_pad.link(&sink_pad).unwrap();

            item.add_concat_sink_pad(&concat, &sink_pad);

            // block pad until next item is reaching the `Blocked` state
            let receiver = Mutex::new(item.receiver());
            let element_weak = element.downgrade();
            // passing ownership of item to the probe callback would introduce a reference cycle as the item is owning the sinkpad
            let item_weak = item.downgrade();

            sink_pad.add_probe(gst::PadProbeType::BLOCK_DOWNSTREAM, move |pad, info| {
                let Some(element) = element_weak.upgrade() else {
                    return gst::PadProbeReturn::Remove;
                };
                let parent = pad.parent().unwrap();
                let Some(item) = Item::upgrade(&item_weak) else {
                    return gst::PadProbeReturn::Remove;
                };

                if !item.is_streaming() {
                    // block pad until next item is ready
                    gst::log!(
                        CAT,
                        obj: element,
                        "blocking pad {}:{} until next item is ready",
                        parent.name(),
                        pad.name()
                    );

                    let receiver = receiver.lock().unwrap();

                    if let Ok(false) = receiver.recv() {
                        // we are shutting down so remove the probe.
                        // Don't handle Err(_) here as if the item has multiple pads, the sender may be dropped in unblock_item()
                        // before all probes received the message, resulting in a receiving error.
                        return gst::PadProbeReturn::Remove;
                    }

                    gst::log!(
                        CAT,
                        obj: element,
                        "pad {}:{} has been unblocked",
                        parent.name(),
                        pad.name()
                    );

                    gst::PadProbeReturn::Pass
                } else {
                    let Some(ev) = info.event() else {
                        return gst::PadProbeReturn::Pass;
                    };

                    if ev.type_() != gst::EventType::Eos {
                        return gst::PadProbeReturn::Pass;
                    }

                    if item.dec_waiting_eos() {
                        // all the streams are eos, item is now done
                        gst::log!(
                            CAT,
                            obj: element,
                            "all streams of item #{} are eos",
                            item.index()
                        );

                        let imp = element.imp();
                        {
                            let mut state_guard = imp.state.lock().unwrap();
                            let state = state_guard.as_mut().unwrap();

                            let index = item.index();

                            let removed = state
                                .streaming
                                .iter()
                                .position(|i| i.index() == index)
                                .map(|e| state.streaming.remove(e));

                            if let Some(item) = removed {
                                item.set_done();
                                state.done.push(item);
                            }
                        }

                        if let Err(e) = imp.start_next_item() {
                            imp.failed(e);
                        }
                    }

                    gst::PadProbeReturn::Remove
                }
            });

            if item.dec_n_pads_pending() == 0 {
                // we got all the pads
                gst::debug!(
                    CAT,
                    imp: self,
                    "got all the pads for item #{}",
                    item.index()
                );

                // all pads have been linked to concat, unblock previous item
                state.unblock_item(self);

                state.waiting_for_pads = None;
                // block item until the next one is fully linked to concat
                item.set_blocked();
                state.blocked = Some(item);

                self.update_current(state_guard);

                true
            } else {
                false
            }
        };

        if start_next {
            gst::debug!(CAT, imp: self, "got all pending streams, queue next item");

            if let Err(e) = self.start_next_item() {
                self.failed(e);
            }
        }
    }

    /// called when all previous items have been flushed from streamsynchronizer
    /// and so the elements can reorganize itself to handle a pending changes in
    /// streams topology.
    fn handle_topology_change(&self) {
        let (pending_pads, channels) = {
            let mut state_guard = self.state.lock().unwrap();
            let state = state_guard.as_mut().unwrap();

            let item = match state.waiting_for_ss_eos.take() {
                Some(item) => item,
                None => return, // element is being shutdown
            };

            let (topology, pending_pads, channels) = item.done_waiting_for_ss_eos();
            state.waiting_for_pads = Some(item);

            // remove now useless concat elements, missing ones will be added when handling src pads from decodebin

            fn remove_useless_concat(
                imp: &UriPlaylistBin,
                n_stream: usize,
                concats: &mut Vec<gst::Element>,
                streamsynchronizer: &gst::Element,
            ) {
                while n_stream < concats.len() {
                    // need to remove concat elements
                    let concat = concats.pop().unwrap();
                    gst::log!(CAT, imp: imp, "remove {}", concat.name());

                    let concat_src = concat.static_pad("src").unwrap();
                    let ss_sink = concat_src.peer().unwrap();

                    // unlink and remove sink pad from streamsynchronizer
                    concat_src.unlink(&ss_sink).unwrap();
                    streamsynchronizer.release_request_pad(&ss_sink);

                    // remove associated ghost pad
                    let src_pads = imp.obj().src_pads();
                    let ghost = src_pads
                        .iter()
                        .find(|pad| {
                            let ghost = pad.downcast_ref::<gst::GhostPad>().unwrap();
                            ghost.target().is_none()
                        })
                        .unwrap();
                    imp.obj().remove_pad(ghost).unwrap();

                    imp.obj().remove(&concat).unwrap();
                    let _ = concat.set_state(gst::State::Null);
                }
            }

            remove_useless_concat(
                self,
                topology.audio as usize,
                &mut state.concat_audio,
                &state.streamsynchronizer,
            );
            remove_useless_concat(
                self,
                topology.video as usize,
                &mut state.concat_video,
                &state.streamsynchronizer,
            );
            remove_useless_concat(
                self,
                topology.text as usize,
                &mut state.concat_text,
                &state.streamsynchronizer,
            );

            state.streams_topology = topology;

            (pending_pads, channels)
        };

        // process decodebin src pads we already received and unblock them
        for pad in pending_pads.iter() {
            self.process_decodebin_pad(pad);
        }

        channels.send(true);
    }

    fn failed(&self, error: PlaylistError) {
        {
            let mut state_guard = self.state.lock().unwrap();
            let state = state_guard.as_mut().unwrap();

            if state.status.done() {
                return;
            }
            state.status = Status::Error;

            if let Some(blocked) = state.blocked.take() {
                // unblock streaming thread
                blocked.set_streaming(state.streams_topology.n_streams());
            }
        }
        gst::error!(CAT, imp: self, "{error}");

        match error {
            PlaylistError::PluginMissing { .. } => {
                gst::element_imp_error!(self, gst::CoreError::MissingPlugin, ["{error}"]);
            }
            PlaylistError::ItemFailed { ref item, .. } => {
                // remove failing uridecodebin
                let uridecodebin = item.uridecodebin();
                uridecodebin.call_async(move |uridecodebin| {
                    let _ = uridecodebin.set_state(gst::State::Null);
                });
                let _ = self.obj().remove(&uridecodebin);

                let details = gst::Structure::builder("details");
                let details = details.field("uri", item.uri());

                gst::element_imp_error!(
                    self,
                    gst::LibraryError::Failed,
                    ["{error}"],
                    details: details.build()
                );
            }
        }

        self.update_current(self.state.lock().unwrap());
    }

    fn update_current(&self, mut state_guard: MutexGuard<Option<State>>) {
        let (uris_len, infinite) = {
            let settings = self.settings.lock().unwrap();

            (settings.uris.len(), settings.iterations == 0)
        };

        if let Some(state) = state_guard.as_mut() {
            // first streaming item is the one actually being played
            if let Some(current) = state.streaming.get(0) {
                let (mut current_iteration, current_uri_index) = (
                    (current.index() / uris_len) as u32,
                    (current.index() % uris_len) as u64,
                );

                if infinite {
                    current_iteration = 0;
                }

                let element = self.obj();
                let mut notify_iteration = false;
                let mut notify_index = false;

                if current_iteration != state.current_iteration {
                    state.current_iteration = current_iteration;
                    notify_iteration = true;
                }
                if current_uri_index != state.current_uri_index {
                    state.current_uri_index = current_uri_index;
                    notify_index = true;
                }

                // drop mutex before notifying changes as the callback will likely try to fetch the updated values
                // which would deadlock.
                drop(state_guard);

                if notify_iteration {
                    element.notify("current-iteration");
                }
                if notify_index {
                    element.notify("current-uri-index");
                }
            }
        }
    }

    fn stop(&self) {
        // remove all children and pads
        let children = self.obj().children();
        let children_ref = children.iter().collect::<Vec<_>>();
        self.obj().remove_many(&children_ref).unwrap();

        for pad in self.obj().src_pads() {
            self.obj().remove_pad(&pad).unwrap();
        }

        let mut state_guard = self.state.lock().unwrap();
        *state_guard = None;
    }
}

#[derive(Default, Clone, Debug)]
struct Channels {
    senders: Arc<Mutex<Vec<mpsc::Sender<bool>>>>,
}

impl Channels {
    fn get_receiver(&self) -> mpsc::Receiver<bool> {
        let mut senders = self.senders.lock().unwrap();

        let (sender, receiver) = mpsc::channel();
        senders.push(sender);
        receiver
    }

    fn send(&self, val: bool) {
        let mut senders = self.senders.lock().unwrap();

        // remove sender if sending failed
        senders.retain(|sender| sender.send(val).is_ok());
    }
}
