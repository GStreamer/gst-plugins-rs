// Copyright (C) 2021 Guillaume Desmottes <guillaume@desmottes.be>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use std::sync::{mpsc, Arc, Mutex, MutexGuard};

use futures::future::{AbortHandle, Abortable, Aborted};
use once_cell::sync::Lazy;
use tokio::{runtime, task::JoinHandle};

use gst::glib;
use gst::prelude::*;
use gst::subclass::prelude::*;
use gst_base::subclass::{base_src::CreateSuccess, prelude::*};

use librespot::playback::{
    audio_backend::{Sink, SinkResult},
    config::PlayerConfig,
    convert::Converter,
    decoder::AudioPacket,
    mixer::NoOpVolume,
    player::{Player, PlayerEvent},
};

use super::Bitrate;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "spotifyaudiosrc",
        gst::DebugColorFlags::empty(),
        Some("Spotify audio source"),
    )
});

static RUNTIME: Lazy<runtime::Runtime> = Lazy::new(|| {
    runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()
        .unwrap()
});

/// Messages from the librespot thread
enum Message {
    Buffer(gst::Buffer),
    Eos,
    Unavailable,
}

struct State {
    player: Player,

    /// receiver sending buffer to streaming thread
    receiver: mpsc::Receiver<Message>,
    /// thread receiving player events from librespot
    player_channel_handle: JoinHandle<()>,
}

#[derive(Default)]
struct Settings {
    common: crate::common::Settings,
    bitrate: Bitrate,
}

#[derive(Default)]
pub struct SpotifyAudioSrc {
    setup_thread: Mutex<Option<SetupThread>>,
    state: Arc<Mutex<Option<State>>>,
    settings: Mutex<Settings>,
}

struct SetupThread {
    thread_handle: std::thread::JoinHandle<Result<anyhow::Result<()>, Aborted>>,
    abort_handle: AbortHandle,
}

#[glib::object_subclass]
impl ObjectSubclass for SpotifyAudioSrc {
    const NAME: &'static str = "GstSpotifyAudioSrc";
    type Type = super::SpotifyAudioSrc;
    type ParentType = gst_base::PushSrc;
    type Interfaces = (gst::URIHandler,);
}

impl ObjectImpl for SpotifyAudioSrc {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            let mut props = crate::common::Settings::properties();
            let default = Settings::default();

            props.push(
                glib::ParamSpecEnum::builder_with_default::<Bitrate>("bitrate", default.bitrate)
                    .nick("Spotify bitrate")
                    .blurb("Spotify audio bitrate in kbit/s")
                    .mutable_ready()
                    .build(),
            );
            props
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        let mut settings = self.settings.lock().unwrap();

        match pspec.name() {
            "bitrate" => {
                settings.bitrate = value.get().expect("type checked upstream");
            }
            _ => settings.common.set_property(value, pspec),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        let settings = self.settings.lock().unwrap();

        match pspec.name() {
            "bitrate" => settings.bitrate.to_value(),
            _ => settings.common.property(pspec),
        }
    }
}

impl GstObjectImpl for SpotifyAudioSrc {}

impl ElementImpl for SpotifyAudioSrc {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "Spotify source",
                "Source/Audio",
                "Spotify source",
                "Guillaume Desmottes <guillaume@desmottes.be>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: Lazy<Vec<gst::PadTemplate>> = Lazy::new(|| {
            let caps = gst::Caps::builder("application/ogg").build();

            let src_pad_template = gst::PadTemplate::new(
                "src",
                gst::PadDirection::Src,
                gst::PadPresence::Always,
                &caps,
            )
            .unwrap();

            vec![src_pad_template]
        });

        PAD_TEMPLATES.as_ref()
    }
}

impl BaseSrcImpl for SpotifyAudioSrc {
    fn start(&self) -> Result<(), gst::ErrorMessage> {
        {
            let state = self.state.lock().unwrap();
            if state.is_some() {
                // already started
                return Ok(());
            }
        }

        {
            let setup_thread = self.setup_thread.lock().unwrap();
            if setup_thread.is_some() {
                // already starting
                return Ok(());
            }
            self.start_setup(setup_thread);
        }

        Ok(())
    }

    fn stop(&self) -> Result<(), gst::ErrorMessage> {
        // stop the setup if it's not completed yet
        self.cancel_setup();

        if let Some(state) = self.state.lock().unwrap().take() {
            gst::debug!(CAT, imp: self, "stopping");
            state.player.stop();
            state.player_channel_handle.abort();
            // FIXME: not sure why this is needed to unblock BufferSink::write(), dropping State should drop the receiver
            drop(state.receiver);
        }

        Ok(())
    }

    fn unlock(&self) -> Result<(), gst::ErrorMessage> {
        self.cancel_setup();

        self.parent_unlock()
    }
}

impl PushSrcImpl for SpotifyAudioSrc {
    fn create(
        &self,
        _buffer: Option<&mut gst::BufferRef>,
    ) -> Result<CreateSuccess, gst::FlowError> {
        let state_set = {
            let state = self.state.lock().unwrap();
            state.is_some()
        };

        if !state_set {
            let setup_thread = self.setup_thread.lock().unwrap();
            if setup_thread.is_none() {
                // unlock() could potentially cancel the setup, and create() can be called after unlock() without going through start() again.
                self.start_setup(setup_thread);
            }
        }

        {
            // wait for the setup to be completed
            let mut setup_thread = self.setup_thread.lock().unwrap();
            if let Some(setup) = setup_thread.take() {
                let res = setup.thread_handle.join().unwrap();

                match res {
                    Err(_aborted) => {
                        gst::debug!(CAT, imp: self, "setup has been cancelled");
                        return Err(gst::FlowError::Flushing);
                    }
                    Ok(Err(err)) => {
                        let details = format!("{err:?}");
                        gst::error!(CAT, imp: self, "failed to start: {}", details);
                        gst::element_imp_error!(self, gst::ResourceError::Settings, [&details]);
                        return Err(gst::FlowError::Error);
                    }
                    Ok(Ok(_)) => {}
                }
            }
        }

        let state = self.state.lock().unwrap();
        let state = state.as_ref().unwrap();

        match state.receiver.recv().unwrap() {
            Message::Buffer(buffer) => {
                gst::log!(CAT, imp: self, "got buffer of size {}", buffer.size());
                Ok(CreateSuccess::NewBuffer(buffer))
            }
            Message::Eos => {
                gst::debug!(CAT, imp: self, "eos");
                Err(gst::FlowError::Eos)
            }
            Message::Unavailable => {
                gst::error!(CAT, imp: self, "track is not available");
                gst::element_imp_error!(
                    self,
                    gst::ResourceError::NotFound,
                    ["track is not available"]
                );
                Err(gst::FlowError::Error)
            }
        }
    }
}

struct BufferSink {
    sender: mpsc::SyncSender<Message>,
}

impl Sink for BufferSink {
    fn write(&mut self, packet: AudioPacket, _converter: &mut Converter) -> SinkResult<()> {
        let oggdata = match packet {
            AudioPacket::OggData(data) => data,
            AudioPacket::Samples(_) => unimplemented!(),
        };
        let buffer = gst::Buffer::from_slice(oggdata);

        // ignore if sending fails as that means the source element is being shutdown
        let _ = self.sender.send(Message::Buffer(buffer));

        Ok(())
    }
}

impl URIHandlerImpl for SpotifyAudioSrc {
    const URI_TYPE: gst::URIType = gst::URIType::Src;

    fn protocols() -> &'static [&'static str] {
        &["spotify"]
    }

    fn uri(&self) -> Option<String> {
        let settings = self.settings.lock().unwrap();

        if settings.common.track.is_empty() {
            None
        } else {
            Some(settings.common.track.clone())
        }
    }

    fn set_uri(&self, uri: &str) -> Result<(), glib::Error> {
        gst::debug!(CAT, imp: self, "set URI: {}", uri);

        let url = url::Url::parse(uri)
            .map_err(|e| glib::Error::new(gst::URIError::BadUri, &format!("{e:?}")))?;

        // allow to configure auth and cache settings from the URI
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "username" | "password" | "cache-credentials" | "cache-files" => {
                    self.obj().set_property(&key, value.as_ref());
                }
                _ => {
                    gst::warning!(CAT, imp: self, "unsupported query: {}={}", key, value);
                }
            }
        }

        self.obj()
            .set_property("track", format!("{}:{}", url.scheme(), url.path()));

        Ok(())
    }
}

impl SpotifyAudioSrc {
    fn start_setup(&self, mut setup_thread: MutexGuard<Option<SetupThread>>) {
        let self_ = self.to_owned();

        // run the runtime from another thread to prevent the "start a runtime from within a runtime" panic
        // when the plugin is statically linked.
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let thread_handle = std::thread::spawn(move || {
            RUNTIME.block_on(async move {
                let future = Abortable::new(self_.setup(), abort_registration);
                future.await
            })
        });

        setup_thread.replace(SetupThread {
            thread_handle,
            abort_handle,
        });
    }

    async fn setup(&self) -> anyhow::Result<()> {
        {
            let state = self.state.lock().unwrap();

            if state.is_some() {
                // already setup
                return Ok(());
            }
        }

        let src = self.obj();

        let (session, track, bitrate) = {
            let (common, bitrate) = {
                let settings = self.settings.lock().unwrap();
                let bitrate = settings.bitrate.into();

                (settings.common.clone(), bitrate)
            };

            let session = common.connect_session(src.clone(), &CAT).await?;
            let track = common.track_id()?;
            gst::debug!(CAT, imp: self, "Requesting bitrate {:?}", bitrate);

            (session, track, bitrate)
        };

        let player_config = PlayerConfig {
            passthrough: true,
            bitrate,
            ..Default::default()
        };

        // use a sync channel to prevent buffering the whole track inside the channel
        let (sender, receiver) = mpsc::sync_channel(2);
        let sender_clone = sender.clone();

        let (mut player, mut player_event_channel) =
            Player::new(player_config, session, Box::new(NoOpVolume), || {
                Box::new(BufferSink { sender })
            });

        player.load(track, true, 0);

        let player_channel_handle = RUNTIME.spawn(async move {
            let sender = sender_clone;

            while let Some(event) = player_event_channel.recv().await {
                match event {
                    PlayerEvent::EndOfTrack { .. } => {
                        let _ = sender.send(Message::Eos);
                    }
                    PlayerEvent::Unavailable { .. } => {
                        let _ = sender.send(Message::Unavailable);
                    }
                    _ => {}
                }
            }
        });

        let mut state = self.state.lock().unwrap();

        state.replace(State {
            player,
            receiver,
            player_channel_handle,
        });

        Ok(())
    }

    fn cancel_setup(&self) {
        let mut setup_thread = self.setup_thread.lock().unwrap();

        if let Some(setup) = setup_thread.take() {
            setup.abort_handle.abort();
        }
    }
}
