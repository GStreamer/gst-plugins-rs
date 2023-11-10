// Copyright (C) 2021 Mathieu Duponchelle <mathieu@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use crate::cea608utils::Cea608Mode;
use anyhow::{anyhow, Error};
use gst::glib;
use gst::prelude::*;
use gst::subclass::prelude::*;
use std::collections::HashMap;
use std::sync::Mutex;

use gst::glib::once_cell::sync::Lazy;

use super::CaptionSource;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "transcriberbin",
        gst::DebugColorFlags::empty(),
        Some("Transcribe and inject closed captions"),
    )
});

const DEFAULT_PASSTHROUGH: bool = false;
const DEFAULT_LATENCY: gst::ClockTime = gst::ClockTime::from_seconds(4);
const DEFAULT_TRANSLATE_LATENCY: gst::ClockTime = gst::ClockTime::from_mseconds(500);
const DEFAULT_ACCUMULATE: gst::ClockTime = gst::ClockTime::ZERO;
const DEFAULT_MODE: Cea608Mode = Cea608Mode::RollUp2;
const DEFAULT_CAPTION_SOURCE: CaptionSource = CaptionSource::Both;
const DEFAULT_INPUT_LANG_CODE: &str = "en-US";

const CEA608MUX_LATENCY: gst::ClockTime = gst::ClockTime::from_mseconds(100);

/* One per language, including original */
struct TranscriptionChannel {
    bin: gst::Bin,
    textwrap: gst::Element,
    tttocea608: gst::Element,
    language: String,
}

impl TranscriptionChannel {
    fn link_transcriber(&self, transcriber: &gst::Element) -> Result<(), Error> {
        let transcriber_src_pad = match self.language.as_str() {
            "transcript" => transcriber
                .static_pad("src")
                .ok_or(anyhow!("Failed to retrieve transcription source pad"))?,
            language => {
                let pad = transcriber
                    .request_pad_simple("translate_src_%u")
                    .ok_or(anyhow!("Failed to request translation source pad"))?;
                pad.set_property("language-code", language);
                pad
            }
        };

        transcriber_src_pad.link(&self.bin.static_pad("sink").unwrap())?;

        Ok(())
    }
}

struct State {
    framerate: Option<gst::Fraction>,
    tearing_down: bool,
    internal_bin: gst::Bin,
    audio_queue_passthrough: gst::Element,
    video_queue: gst::Element,
    audio_tee: gst::Element,
    transcriber_resample: gst::Element,
    transcriber_aconv: gst::Element,
    transcriber: gst::Element,
    ccmux: gst::Element,
    ccmux_filter: gst::Element,
    cccombiner: gst::Element,
    transcription_bin: gst::Bin,
    transcription_channels: HashMap<String, TranscriptionChannel>,
    cccapsfilter: gst::Element,
    transcription_valve: gst::Element,
}

struct Settings {
    cc_caps: gst::Caps,
    latency: gst::ClockTime,
    translate_latency: gst::ClockTime,
    passthrough: bool,
    accumulate_time: gst::ClockTime,
    mode: Cea608Mode,
    caption_source: CaptionSource,
    translation_languages: Option<gst::Structure>,
    language_code: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            cc_caps: gst::Caps::builder("closedcaption/x-cea-608")
                .field("format", "raw")
                .build(),
            passthrough: DEFAULT_PASSTHROUGH,
            latency: DEFAULT_LATENCY,
            translate_latency: DEFAULT_TRANSLATE_LATENCY,
            accumulate_time: DEFAULT_ACCUMULATE,
            mode: DEFAULT_MODE,
            caption_source: DEFAULT_CAPTION_SOURCE,
            translation_languages: None,
            language_code: String::from(DEFAULT_INPUT_LANG_CODE),
        }
    }
}

// Struct containing all the element data
pub struct TranscriberBin {
    audio_srcpad: gst::GhostPad,
    video_srcpad: gst::GhostPad,
    audio_sinkpad: gst::GhostPad,
    video_sinkpad: gst::GhostPad,

    state: Mutex<Option<State>>,
    settings: Mutex<Settings>,
}

impl TranscriberBin {
    fn construct_channel_bin(&self, lang: &str) -> Result<TranscriptionChannel, Error> {
        let bin = gst::Bin::new();
        let queue = gst::ElementFactory::make("queue").build()?;
        let textwrap = gst::ElementFactory::make("textwrap").build()?;
        let tttocea608 = gst::ElementFactory::make("tttocea608").build()?;
        let capsfilter = gst::ElementFactory::make("capsfilter").build()?;
        let converter = gst::ElementFactory::make("ccconverter").build()?;

        bin.add_many([&queue, &textwrap, &tttocea608, &capsfilter, &converter])?;
        gst::Element::link_many([&queue, &textwrap, &tttocea608, &capsfilter, &converter])?;

        queue.set_property("max-size-buffers", 0u32);
        queue.set_property("max-size-time", 0u64);

        textwrap.set_property("lines", 2u32);

        capsfilter.set_property(
            "caps",
            gst::Caps::builder("closedcaption/x-cea-608")
                .field("format", "raw")
                .field("framerate", gst::Fraction::new(30000, 1001))
                .build(),
        );

        let sinkpad = gst::GhostPad::with_target(&queue.static_pad("sink").unwrap()).unwrap();
        let srcpad = gst::GhostPad::with_target(&converter.static_pad("src").unwrap()).unwrap();
        bin.add_pad(&sinkpad)?;
        bin.add_pad(&srcpad)?;

        Ok(TranscriptionChannel {
            bin,
            textwrap,
            tttocea608,
            language: String::from(lang),
        })
    }

    fn construct_transcription_bin(&self, state: &mut State) -> Result<(), Error> {
        gst::debug!(CAT, imp: self, "Building transcription bin");

        let aqueue_transcription = gst::ElementFactory::make("queue")
            .name("transqueue")
            .property("max-size-buffers", 0u32)
            .property("max-size-bytes", 0u32)
            .property("max-size-time", 5_000_000_000u64)
            .property_from_str("leaky", "downstream")
            .build()?;
        let ccconverter = gst::ElementFactory::make("ccconverter").build()?;

        state.transcription_bin.add_many([
            &aqueue_transcription,
            &state.transcriber_resample,
            &state.transcriber_aconv,
            &state.transcriber,
            &state.ccmux,
            &state.ccmux_filter,
            &ccconverter,
            &state.cccapsfilter,
            &state.transcription_valve,
        ])?;

        gst::Element::link_many([
            &aqueue_transcription,
            &state.transcriber_resample,
            &state.transcriber_aconv,
            &state.transcriber,
        ])?;

        gst::Element::link_many([
            &state.ccmux,
            &state.ccmux_filter,
            &ccconverter,
            &state.cccapsfilter,
            &state.transcription_valve,
        ])?;

        for (padname, channel) in &state.transcription_channels {
            state.transcription_bin.add(&channel.bin)?;

            channel.link_transcriber(&state.transcriber)?;

            let ccmux_pad = state
                .ccmux
                .request_pad_simple(padname)
                .ok_or(anyhow!("Failed to request ccmux sink pad"))?;
            channel.bin.static_pad("src").unwrap().link(&ccmux_pad)?;
        }

        state.ccmux.set_property("latency", CEA608MUX_LATENCY);

        let transcription_audio_sinkpad =
            gst::GhostPad::with_target(&aqueue_transcription.static_pad("sink").unwrap()).unwrap();
        let transcription_audio_srcpad =
            gst::GhostPad::with_target(&state.transcription_valve.static_pad("src").unwrap())
                .unwrap();

        state
            .transcription_bin
            .add_pad(&transcription_audio_sinkpad)?;
        state
            .transcription_bin
            .add_pad(&transcription_audio_srcpad)?;

        state.internal_bin.add(&state.transcription_bin)?;

        state.transcription_bin.set_locked_state(true);

        Ok(())
    }

    fn construct_internal_bin(&self, state: &mut State) -> Result<(), Error> {
        let aclocksync = gst::ElementFactory::make("clocksync").build()?;

        let vclocksync = gst::ElementFactory::make("clocksync").build()?;

        state.internal_bin.add_many([
            &aclocksync,
            &state.audio_tee,
            &state.audio_queue_passthrough,
            &vclocksync,
            &state.video_queue,
            &state.cccombiner,
        ])?;

        aclocksync.link(&state.audio_tee)?;
        state
            .audio_tee
            .link_pads(Some("src_%u"), &state.audio_queue_passthrough, Some("sink"))?;
        vclocksync.link(&state.video_queue)?;
        state
            .video_queue
            .link_pads(Some("src"), &state.cccombiner, Some("sink"))?;

        let internal_audio_sinkpad =
            gst::GhostPad::builder_with_target(&aclocksync.static_pad("sink").unwrap())
                .unwrap()
                .name("audio_sink")
                .build();
        let internal_audio_srcpad = gst::GhostPad::builder_with_target(
            &state.audio_queue_passthrough.static_pad("src").unwrap(),
        )
        .unwrap()
        .name("audio_src")
        .build();
        let internal_video_sinkpad =
            gst::GhostPad::builder_with_target(&vclocksync.static_pad("sink").unwrap())
                .unwrap()
                .name("video_sink")
                .build();
        let internal_video_srcpad =
            gst::GhostPad::builder_with_target(&state.cccombiner.static_pad("src").unwrap())
                .unwrap()
                .name("video_src")
                .build();

        state.internal_bin.add_pad(&internal_audio_sinkpad)?;
        state.internal_bin.add_pad(&internal_audio_srcpad)?;
        state.internal_bin.add_pad(&internal_video_sinkpad)?;
        state.internal_bin.add_pad(&internal_video_srcpad)?;

        let imp_weak = self.downgrade();
        let comp_sinkpad = &state.cccombiner.static_pad("sink").unwrap();
        // Drop caption meta from video buffer if user preference is transcription
        comp_sinkpad.add_probe(gst::PadProbeType::BUFFER, move |_, probe_info| {
            let Some(imp) = imp_weak.upgrade() else {
                return gst::PadProbeReturn::Remove;
            };

            let settings = imp.settings.lock().unwrap();
            if settings.caption_source != CaptionSource::Transcription {
                return gst::PadProbeReturn::Pass;
            }

            if let Some(buffer) = probe_info.buffer_mut() {
                let buffer = buffer.make_mut();
                while let Some(meta) = buffer.meta_mut::<gst_video::VideoCaptionMeta>() {
                    meta.remove().unwrap();
                }
            }

            gst::PadProbeReturn::Ok
        });

        self.obj().add(&state.internal_bin)?;

        state.cccombiner.set_property("latency", 100.mseconds());

        self.audio_sinkpad
            .set_target(Some(&state.internal_bin.static_pad("audio_sink").unwrap()))?;
        self.audio_srcpad
            .set_target(Some(&state.internal_bin.static_pad("audio_src").unwrap()))?;
        self.video_sinkpad
            .set_target(Some(&state.internal_bin.static_pad("video_sink").unwrap()))?;
        self.video_srcpad
            .set_target(Some(&state.internal_bin.static_pad("video_src").unwrap()))?;

        self.construct_transcription_bin(state)?;

        Ok(())
    }

    fn setup_transcription(&self, state: &State) {
        let settings = self.settings.lock().unwrap();
        let mut cc_caps = settings.cc_caps.clone();

        let cc_caps_mut = cc_caps.make_mut();
        let s = cc_caps_mut.structure_mut(0).unwrap();

        s.set("framerate", state.framerate.unwrap());

        state.cccapsfilter.set_property("caps", &cc_caps);

        let ccmux_caps = gst::Caps::builder("closedcaption/x-cea-608")
            .field("framerate", state.framerate.unwrap())
            .build();

        state.ccmux_filter.set_property("caps", ccmux_caps);

        let max_size_time = settings.latency
            + settings.translate_latency
            + settings.accumulate_time
            + CEA608MUX_LATENCY;

        for queue in [&state.audio_queue_passthrough, &state.video_queue] {
            queue.set_property("max-size-bytes", 0u32);
            queue.set_property("max-size-buffers", 0u32);
            queue.set_property("max-size-time", max_size_time);
        }

        let latency_ms = settings.latency.mseconds() as u32;
        state.transcriber.set_property("latency", latency_ms);

        let translate_latency_ms = settings.translate_latency.mseconds() as u32;
        state
            .transcriber
            .set_property("translate-latency", translate_latency_ms);

        if !settings.passthrough {
            state
                .transcription_bin
                .link_pads(Some("src"), &state.cccombiner, Some("caption"))
                .unwrap();

            state.transcription_bin.set_locked_state(false);
            state.transcription_bin.sync_state_with_parent().unwrap();

            let transcription_sink_pad = state.transcription_bin.static_pad("sink").unwrap();
            // Might be linked already if "translation-languages" is set
            if transcription_sink_pad.peer().is_none() {
                let audio_tee_pad = state.audio_tee.request_pad_simple("src_%u").unwrap();
                audio_tee_pad.link(&transcription_sink_pad).unwrap();
            }
        }

        drop(settings);

        self.setup_cc_mode(state);
    }

    fn disable_transcription_bin(&self) {
        let mut state = self.state.lock().unwrap();

        if let Some(ref mut state) = state.as_mut() {
            state.tearing_down = false;

            // At this point, we want to check whether passthrough
            // has been unset in the meantime
            let passthrough = self.settings.lock().unwrap().passthrough;

            if passthrough {
                gst::debug!(CAT, imp: self, "disabling transcription bin");

                let bin_sink_pad = state.transcription_bin.static_pad("sink").unwrap();
                if let Some(audio_tee_pad) = bin_sink_pad.peer() {
                    audio_tee_pad.unlink(&bin_sink_pad).unwrap();
                    state.audio_tee.release_request_pad(&audio_tee_pad);
                }

                let bin_src_pad = state.transcription_bin.static_pad("src").unwrap();
                if let Some(cccombiner_pad) = bin_src_pad.peer() {
                    bin_src_pad.unlink(&cccombiner_pad).unwrap();
                    state.cccombiner.release_request_pad(&cccombiner_pad);
                }

                state.transcription_bin.set_locked_state(true);
                state.transcription_bin.set_state(gst::State::Null).unwrap();
            }
        }
    }

    fn block_and_update(&self, passthrough: bool) {
        let mut s = self.state.lock().unwrap();

        if let Some(ref mut state) = s.as_mut() {
            if passthrough {
                let sinkpad = state.transcription_bin.static_pad("sink").unwrap();
                let imp_weak = self.downgrade();
                state.tearing_down = true;
                drop(s);
                let _ = sinkpad.add_probe(
                    gst::PadProbeType::IDLE
                        | gst::PadProbeType::BUFFER
                        | gst::PadProbeType::EVENT_DOWNSTREAM,
                    move |_pad, _info| {
                        let Some(imp) = imp_weak.upgrade() else {
                            return gst::PadProbeReturn::Remove;
                        };

                        imp.disable_transcription_bin();

                        gst::PadProbeReturn::Remove
                    },
                );
            } else if state.tearing_down {
                // Do nothing, wait for the previous transcription bin
                // to finish tearing down
            } else {
                state
                    .transcription_bin
                    .link_pads(Some("src"), &state.cccombiner, Some("caption"))
                    .unwrap();
                state.transcription_bin.set_locked_state(false);
                state.transcription_bin.sync_state_with_parent().unwrap();

                let audio_tee_pad = state.audio_tee.request_pad_simple("src_%u").unwrap();
                let transcription_sink_pad = state.transcription_bin.static_pad("sink").unwrap();
                audio_tee_pad.link(&transcription_sink_pad).unwrap();
            }
        }
    }

    fn setup_cc_mode(&self, state: &State) {
        let mode = self.settings.lock().unwrap().mode;

        gst::debug!(CAT, imp: self, "setting CC mode {:?}", mode);

        for channel in state.transcription_channels.values() {
            channel.tttocea608.set_property("mode", mode);

            if mode.is_rollup() {
                channel.textwrap.set_property("accumulate-time", 0u64);
            } else {
                let accumulate_time = self.settings.lock().unwrap().accumulate_time;

                channel
                    .textwrap
                    .set_property("accumulate-time", accumulate_time);
            }
        }
    }

    /* We make no ceremonies here because the function can only
     * be called in READY */
    fn relink_transcriber(
        &self,
        state: &mut State,
        old_transcriber: &gst::Element,
    ) -> Result<(), Error> {
        gst::debug!(
            CAT,
            imp: self,
            "Relinking transcriber, old: {:?}, new: {:?}",
            old_transcriber,
            state.transcriber
        );

        state.transcriber_aconv.unlink(old_transcriber);

        for channel in state.transcription_channels.values() {
            old_transcriber.unlink(&channel.bin);
        }
        state.transcription_bin.remove(old_transcriber).unwrap();
        old_transcriber.set_state(gst::State::Null).unwrap();

        state.transcription_bin.add(&state.transcriber)?;
        state.transcriber.sync_state_with_parent().unwrap();
        state.transcriber_aconv.link(&state.transcriber)?;

        for channel in state.transcription_channels.values() {
            channel.link_transcriber(&state.transcriber)?;
        }

        Ok(())
    }

    fn reconfigure_transcription_bin(&self, lang_code_only: bool) -> Result<(), Error> {
        let mut state = self.state.lock().unwrap();

        if let Some(ref mut state) = state.as_mut() {
            let settings = self.settings.lock().unwrap();

            gst::debug!(
                CAT,
                imp: self,
                "Updating transcription/translation language"
            );

            // Unlink sinkpad temporarily
            let sinkpad = state.transcription_bin.static_pad("sink").unwrap();
            let peer = sinkpad.peer();
            if let Some(peer) = &peer {
                gst::debug!(CAT, imp: self, "Unlinking {:?}", peer);
                peer.unlink(&sinkpad)?;
                state.audio_tee.release_request_pad(peer);
            }

            state.transcription_bin.set_locked_state(true);
            state.transcription_bin.set_state(gst::State::Null).unwrap();

            state
                .transcriber
                .set_property("language-code", &settings.language_code);

            if lang_code_only {
                if !settings.passthrough {
                    gst::debug!(CAT, imp: self, "Syncing state with parent");

                    drop(settings);

                    state.transcription_bin.set_locked_state(false);
                    state.transcription_bin.sync_state_with_parent()?;

                    let audio_tee_pad = state.audio_tee.request_pad_simple("src_%u").unwrap();
                    audio_tee_pad.link(&sinkpad)?;
                }

                return Ok(());
            }

            for channel in state.transcription_channels.values() {
                let sinkpad = channel.bin.static_pad("sink").unwrap();
                if let Some(peer) = sinkpad.peer() {
                    peer.unlink(&sinkpad)?;
                    if channel.language != "transcript" {
                        state.transcriber.release_request_pad(&peer);
                    }
                }

                let srcpad = channel.bin.static_pad("src").unwrap();
                if let Some(peer) = srcpad.peer() {
                    srcpad.unlink(&peer)?;
                    state.ccmux.release_request_pad(&peer);
                }

                state.transcription_bin.remove(&channel.bin)?;
            }

            state.transcription_channels.clear();

            if let Some(ref map) = settings.translation_languages {
                for (key, value) in map.iter() {
                    let channel = key.to_lowercase();
                    if !["cc1", "cc3"].contains(&channel.as_str()) {
                        anyhow::bail!("Unknown 608 channel {}, valid values are cc1, cc3", channel);
                    }
                    let language_code = value.get::<String>()?;

                    state.transcription_channels.insert(
                        channel.to_owned(),
                        self.construct_channel_bin(&language_code).unwrap(),
                    );
                }
            } else {
                state.transcription_channels.insert(
                    "cc1".to_string(),
                    self.construct_channel_bin("transcript").unwrap(),
                );
            }

            for (padname, channel) in &state.transcription_channels {
                state.transcription_bin.add(&channel.bin)?;

                channel.link_transcriber(&state.transcriber)?;

                let ccmux_pad = state
                    .ccmux
                    .request_pad_simple(padname)
                    .ok_or(anyhow!("Failed to request ccmux sink pad"))?;
                channel.bin.static_pad("src").unwrap().link(&ccmux_pad)?;
            }

            drop(settings);
            self.setup_cc_mode(state);

            if !self.settings.lock().unwrap().passthrough {
                gst::debug!(CAT, imp: self, "Syncing state with parent");

                state.transcription_bin.set_locked_state(false);
                state.transcription_bin.sync_state_with_parent()?;

                let audio_tee_pad = state.audio_tee.request_pad_simple("src_%u").unwrap();
                audio_tee_pad.link(&sinkpad)?;
            }
        }

        Ok(())
    }

    fn update_languages(&self, lang_code_only: bool) {
        let s = self.state.lock().unwrap();

        if let Some(state) = s.as_ref() {
            gst::debug!(
                CAT,
                imp: self,
                "Schedule transcription/translation language update"
            );

            let sinkpad = state.transcription_bin.static_pad("sink").unwrap();
            let imp_weak = self.downgrade();
            drop(s);

            let _ = sinkpad.add_probe(
                gst::PadProbeType::IDLE
                    | gst::PadProbeType::BUFFER
                    | gst::PadProbeType::EVENT_DOWNSTREAM,
                move |_pad, _info| {
                    let Some(imp) = imp_weak.upgrade() else {
                        return gst::PadProbeReturn::Remove;
                    };

                    if imp.reconfigure_transcription_bin(lang_code_only).is_err() {
                        gst::element_imp_error!(
                            imp,
                            gst::StreamError::Failed,
                            ["Couldn't reconfigure channels"]
                        );
                    }

                    gst::PadProbeReturn::Remove
                },
            );
        } else {
            gst::debug!(CAT, imp: self, "Transcriber is not configured yet");
        }
    }

    #[allow(clippy::single_match)]
    fn src_query(&self, pad: &gst::Pad, query: &mut gst::QueryRef) -> bool {
        use gst::QueryViewMut;

        gst::log!(CAT, obj: pad, "Handling query {:?}", query);

        match query.view_mut() {
            QueryViewMut::Latency(q) => {
                let mut upstream_query = gst::query::Latency::new();

                let ret = gst::Pad::query_default(pad, Some(&*self.obj()), &mut upstream_query);

                if ret {
                    let (_, mut min, _) = upstream_query.result();
                    let (received_framerate, translating) = {
                        let state = self.state.lock().unwrap();
                        if let Some(state) = state.as_ref() {
                            (
                                state.framerate,
                                state
                                    .transcription_channels
                                    .values()
                                    .any(|c| c.language != "transcript"),
                            )
                        } else {
                            (None, false)
                        }
                    };

                    let settings = self.settings.lock().unwrap();
                    if settings.passthrough || received_framerate.is_none() {
                        min += settings.latency + settings.accumulate_time + CEA608MUX_LATENCY;

                        if translating {
                            min += settings.translate_latency;
                        }

                        /* The sub latency introduced by cea608mux */
                        if let Some(framerate) = received_framerate {
                            min += gst::ClockTime::SECOND
                                .mul_div_floor(framerate.denom() as u64, framerate.numer() as u64)
                                .unwrap();
                        }
                    } else if settings.mode.is_rollup() {
                        min += settings.accumulate_time;
                    }

                    q.set(true, min, gst::ClockTime::NONE);
                }

                ret
            }
            _ => gst::Pad::query_default(pad, Some(&*self.obj()), query),
        }
    }

    fn build_state(&self) -> Result<State, Error> {
        let internal_bin = gst::Bin::with_name("internal");
        let transcription_bin = gst::Bin::with_name("transcription-bin");
        let audio_tee = gst::ElementFactory::make("tee")
            // Protect passthrough enable (and resulting dynamic reconfigure)
            // from non-streaming thread
            .property("allow-not-linked", true)
            .build()?;
        let cccombiner = gst::ElementFactory::make("cccombiner")
            .name("cccombiner")
            .build()?;
        let transcriber_resample = gst::ElementFactory::make("audioresample").build()?;
        let transcriber_aconv = gst::ElementFactory::make("audioconvert").build()?;
        let transcriber = gst::ElementFactory::make("awstranscriber")
            .name("transcriber")
            .property(
                "language-code",
                &self.settings.lock().unwrap().language_code,
            )
            .build()?;
        let audio_queue_passthrough = gst::ElementFactory::make("queue").build()?;
        let video_queue = gst::ElementFactory::make("queue").build()?;
        let cccapsfilter = gst::ElementFactory::make("capsfilter").build()?;
        let transcription_valve = gst::ElementFactory::make("valve")
            .property_from_str("drop-mode", "transform-to-gap")
            .build()?;
        let ccmux = gst::ElementFactory::make("cea608mux")
            .property_from_str("start-time-selection", "first")
            .build()?;
        let ccmux_filter = gst::ElementFactory::make("capsfilter").build()?;

        let mut transcription_channels = HashMap::new();

        if let Some(ref map) = self.settings.lock().unwrap().translation_languages {
            for (key, value) in map.iter() {
                let channel = key.to_lowercase();
                if !["cc1", "cc3"].contains(&channel.as_str()) {
                    anyhow::bail!("Unknown 608 channel {}, valid values are cc1, cc3", channel);
                }
                let language_code = value.get::<String>()?;

                transcription_channels.insert(
                    channel.to_owned(),
                    self.construct_channel_bin(&language_code).unwrap(),
                );
            }
        } else {
            transcription_channels.insert(
                "cc1".to_string(),
                self.construct_channel_bin("transcript").unwrap(),
            );
        }

        Ok(State {
            framerate: None,
            internal_bin,
            audio_queue_passthrough,
            video_queue,
            transcriber_resample,
            transcriber_aconv,
            transcriber,
            ccmux,
            ccmux_filter,
            audio_tee,
            cccombiner,
            transcription_bin,
            transcription_channels,
            cccapsfilter,
            transcription_valve,
            tearing_down: false,
        })
    }

    #[allow(clippy::single_match)]
    fn video_sink_event(&self, pad: &gst::Pad, event: gst::Event) -> bool {
        use gst::EventView;

        gst::log!(CAT, obj: pad, "Handling event {:?}", event);
        match event.view() {
            EventView::Caps(e) => {
                let mut state = self.state.lock().unwrap();

                if let Some(ref mut state) = state.as_mut() {
                    let caps = e.caps();
                    let s = caps.structure(0).unwrap();

                    let had_framerate = state.framerate.is_some();

                    if let Ok(framerate) = s.get::<gst::Fraction>("framerate") {
                        state.framerate = Some(framerate);
                    } else {
                        state.framerate = Some(gst::Fraction::new(30, 1));
                    }

                    if !had_framerate {
                        gst::info!(
                            CAT,
                            imp: self,
                            "Received video caps, setting up transcription"
                        );
                        self.setup_transcription(state);
                    }
                }

                gst::Pad::event_default(pad, Some(&*self.obj()), event)
            }
            _ => gst::Pad::event_default(pad, Some(&*self.obj()), event),
        }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for TranscriberBin {
    const NAME: &'static str = "GstTranscriberBin";
    type Type = super::TranscriberBin;
    type ParentType = gst::Bin;

    fn with_class(klass: &Self::Class) -> Self {
        let templ = klass.pad_template("sink_audio").unwrap();
        let audio_sinkpad = gst::GhostPad::from_template(&templ);
        let templ = klass.pad_template("src_audio").unwrap();
        let audio_srcpad = gst::GhostPad::builder_from_template(&templ)
            .query_function(|pad, parent, query| {
                TranscriberBin::catch_panic_pad_function(
                    parent,
                    || false,
                    |transcriber| transcriber.src_query(pad.upcast_ref(), query),
                )
            })
            .build();

        let templ = klass.pad_template("sink_video").unwrap();
        let video_sinkpad = gst::GhostPad::builder_from_template(&templ)
            .event_function(|pad, parent, event| {
                TranscriberBin::catch_panic_pad_function(
                    parent,
                    || false,
                    |transcriber| transcriber.video_sink_event(pad.upcast_ref(), event),
                )
            })
            .build();
        let templ = klass.pad_template("src_video").unwrap();
        let video_srcpad = gst::GhostPad::builder_from_template(&templ)
            .query_function(|pad, parent, query| {
                TranscriberBin::catch_panic_pad_function(
                    parent,
                    || false,
                    |transcriber| transcriber.src_query(pad.upcast_ref(), query),
                )
            })
            .build();

        Self {
            audio_srcpad,
            video_srcpad,
            audio_sinkpad,
            video_sinkpad,
            state: Mutex::new(None),
            settings: Mutex::new(Settings::default()),
        }
    }
}

impl ObjectImpl for TranscriberBin {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecBoolean::builder("passthrough")
                    .nick("Passthrough")
                    .blurb("Whether transcription should occur")
                    .default_value(DEFAULT_PASSTHROUGH)
                    .mutable_playing()
                    .build(),
                glib::ParamSpecUInt::builder("latency")
                    .nick("Latency")
                    .blurb("Amount of milliseconds to allow the transcriber")
                    .default_value(DEFAULT_LATENCY.mseconds() as u32)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt::builder("accumulate-time")
                    .nick("accumulate-time")
                    .blurb("Cut-off time for textwrap accumulation, in milliseconds (0=do not accumulate). \
                    Set this to a non-default value if you plan to switch to pop-on mode")
                    .default_value(DEFAULT_ACCUMULATE.mseconds() as u32)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecEnum::builder_with_default("mode", DEFAULT_MODE)
                    .nick("Mode")
                    .blurb("Which closed caption mode to operate in")
                    .mutable_playing()
                    .build(),
                glib::ParamSpecBoxed::builder::<gst::Caps>("cc-caps")
                    .nick("Closed Caption caps")
                    .blurb("The expected format of the closed captions")
                    .mutable_ready()
                    .build(),
                glib::ParamSpecObject::builder::<gst::Element>("transcriber")
                    .nick("Transcriber")
                    .blurb("The transcriber element to use")
                    .mutable_ready()
                    .build(),
                glib::ParamSpecEnum::builder_with_default("caption-source", DEFAULT_CAPTION_SOURCE)
                    .nick("Caption source")
                    .blurb("Caption source to use. \
                    If \"Transcription\" or \"Inband\" is selected, the caption meta \
                    of the other source will be dropped by transcriberbin")
                    .mutable_playing()
                    .build(),
                glib::ParamSpecBoxed::builder::<gst::Structure>("translation-languages")
                    .nick("Translation languages")
                    .blurb("A map of CEA 608 channels to language codes, eg translation-languages=\"languages, CC1=fr, CC3=transcript\" will map the French translation to CC1 and the original transcript to CC3")
                    .mutable_playing()
                    .build(),
                glib::ParamSpecUInt::builder("translate-latency")
                    .nick("Translation Latency")
                    .blurb("Amount of extra milliseconds to allow for translating")
                    .default_value(DEFAULT_TRANSLATE_LATENCY.mseconds() as u32)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecString::builder("language-code")
                    .nick("Language Code")
                    .blurb("The language of the input stream")
                    .default_value(Some(DEFAULT_INPUT_LANG_CODE))
                    .mutable_playing()
                    .build(),
            ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "passthrough" => {
                let mut settings = self.settings.lock().unwrap();

                let old_passthrough = settings.passthrough;
                let new_passthrough = value.get().expect("type checked upstream");
                settings.passthrough = new_passthrough;

                if old_passthrough != new_passthrough {
                    drop(settings);
                    self.block_and_update(new_passthrough);
                }
            }
            "latency" => {
                let mut settings = self.settings.lock().unwrap();
                settings.latency = gst::ClockTime::from_mseconds(
                    value.get::<u32>().expect("type checked upstream").into(),
                );
            }
            "accumulate-time" => {
                let mut settings = self.settings.lock().unwrap();
                settings.accumulate_time = gst::ClockTime::from_mseconds(
                    value.get::<u32>().expect("type checked upstream").into(),
                );
            }
            "mode" => {
                let mut settings = self.settings.lock().unwrap();

                let old_mode = settings.mode;
                let new_mode = value.get().expect("type checked upstream");
                settings.mode = new_mode;

                if old_mode != new_mode {
                    drop(settings);
                    self.setup_cc_mode(self.state.lock().unwrap().as_ref().unwrap());
                }
            }
            "cc-caps" => {
                let mut settings = self.settings.lock().unwrap();
                settings.cc_caps = value.get().expect("type checked upstream");
            }
            "transcriber" => {
                let mut s = self.state.lock().unwrap();
                if let Some(ref mut state) = s.as_mut() {
                    let old_transcriber = state.transcriber.clone();
                    state.transcriber = value.get().expect("type checked upstream");
                    if old_transcriber != state.transcriber {
                        match self.relink_transcriber(state, &old_transcriber) {
                            Ok(()) => (),
                            Err(err) => {
                                gst::error!(CAT, "invalid transcriber: {}", err);
                                drop(s);
                                *self.state.lock().unwrap() = None;
                            }
                        }
                    }
                }
            }
            "caption-source" => {
                let mut settings = self.settings.lock().unwrap();
                settings.caption_source = value.get().expect("type checked upstream");

                let s = self.state.lock().unwrap();
                if let Some(state) = s.as_ref() {
                    if settings.caption_source == CaptionSource::Inband {
                        gst::debug!(CAT, imp: self, "Use inband caption, dropping transcription");
                        state.transcription_valve.set_property("drop", true);
                    } else {
                        gst::debug!(CAT, imp: self, "Stop dropping transcription");
                        state.transcription_valve.set_property("drop", false);
                    }
                }
            }
            "translation-languages" => {
                let mut settings = self.settings.lock().unwrap();
                settings.translation_languages = value
                    .get::<Option<gst::Structure>>()
                    .expect("type checked upstream");
                gst::debug!(
                    CAT,
                    imp: self,
                    "Updated translation-languages {:?}",
                    settings.translation_languages
                );
                drop(settings);

                self.update_languages(false);
            }
            "translate-latency" => {
                let mut settings = self.settings.lock().unwrap();
                settings.translate_latency = gst::ClockTime::from_mseconds(
                    value.get::<u32>().expect("type checked upstream").into(),
                );
            }
            "language-code" => {
                let code = value
                    .get::<Option<String>>()
                    .expect("type checked upstream")
                    .unwrap_or_else(|| String::from(DEFAULT_INPUT_LANG_CODE));
                let mut settings = self.settings.lock().unwrap();
                if settings.language_code != code {
                    gst::debug!(
                        CAT,
                        imp: self,
                        "Updating language code {} -> {}",
                        settings.language_code,
                        code
                    );

                    settings.language_code = code;
                    drop(settings);

                    self.update_languages(true)
                }
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        match pspec.name() {
            "passthrough" => {
                let settings = self.settings.lock().unwrap();
                settings.passthrough.to_value()
            }
            "latency" => {
                let settings = self.settings.lock().unwrap();
                (settings.latency.mseconds() as u32).to_value()
            }
            "accumulate-time" => {
                let settings = self.settings.lock().unwrap();
                (settings.accumulate_time.mseconds() as u32).to_value()
            }
            "mode" => {
                let settings = self.settings.lock().unwrap();
                settings.mode.to_value()
            }
            "cc-caps" => {
                let settings = self.settings.lock().unwrap();
                settings.cc_caps.to_value()
            }
            "transcriber" => {
                let state = self.state.lock().unwrap();
                if let Some(state) = state.as_ref() {
                    state.transcriber.to_value()
                } else {
                    let ret: Option<gst::Element> = None;
                    ret.to_value()
                }
            }
            "caption-source" => {
                let settings = self.settings.lock().unwrap();
                settings.caption_source.to_value()
            }
            "translation-languages" => {
                let settings = self.settings.lock().unwrap();
                settings.translation_languages.to_value()
            }
            "translate-latency" => {
                let settings = self.settings.lock().unwrap();
                (settings.translate_latency.mseconds() as u32).to_value()
            }
            "language-code" => {
                let settings = self.settings.lock().unwrap();
                settings.language_code.to_value()
            }
            _ => unimplemented!(),
        }
    }

    fn constructed(&self) {
        self.parent_constructed();

        let obj = self.obj();
        obj.add_pad(&self.audio_srcpad).unwrap();
        obj.add_pad(&self.audio_sinkpad).unwrap();
        obj.add_pad(&self.video_srcpad).unwrap();
        obj.add_pad(&self.video_sinkpad).unwrap();

        *self.state.lock().unwrap() = match self.build_state() {
            Ok(mut state) => match self.construct_internal_bin(&mut state) {
                Ok(()) => Some(state),
                Err(err) => {
                    gst::error!(CAT, "Failed to build internal bin: {}", err);
                    None
                }
            },
            Err(err) => {
                gst::error!(CAT, "Failed to build state: {}", err);
                None
            }
        }
    }
}

impl GstObjectImpl for TranscriberBin {}

impl ElementImpl for TranscriberBin {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "TranscriberBin",
                "Audio / Video / Text",
                "Transcribes audio and adds it as closed captions",
                "Mathieu Duponchelle <mathieu@centricular.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: Lazy<Vec<gst::PadTemplate>> = Lazy::new(|| {
            let caps = gst::Caps::builder("video/x-raw").any_features().build();
            let video_src_pad_template = gst::PadTemplate::new(
                "src_video",
                gst::PadDirection::Src,
                gst::PadPresence::Always,
                &caps,
            )
            .unwrap();
            let video_sink_pad_template = gst::PadTemplate::new(
                "sink_video",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &caps,
            )
            .unwrap();

            let caps = gst::Caps::builder("audio/x-raw").build();
            let audio_src_pad_template = gst::PadTemplate::new(
                "src_audio",
                gst::PadDirection::Src,
                gst::PadPresence::Always,
                &caps,
            )
            .unwrap();
            let audio_sink_pad_template = gst::PadTemplate::new(
                "sink_audio",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &caps,
            )
            .unwrap();

            vec![
                video_src_pad_template,
                video_sink_pad_template,
                audio_src_pad_template,
                audio_sink_pad_template,
            ]
        });

        PAD_TEMPLATES.as_ref()
    }

    #[allow(clippy::single_match)]
    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        gst::trace!(CAT, imp: self, "Changing state {:?}", transition);

        match transition {
            gst::StateChange::ReadyToPaused => {
                let mut state = self.state.lock().unwrap();

                if let Some(ref mut state) = state.as_mut() {
                    if state.framerate.is_some() {
                        gst::info!(
                            CAT,
                            imp: self,
                            "Received video caps, setting up transcription"
                        );
                        self.setup_transcription(state);
                    }
                } else {
                    drop(state);
                    gst::element_imp_error!(
                        self,
                        gst::StreamError::Failed,
                        ["Can't change state with no state"]
                    );
                    return Err(gst::StateChangeError);
                }
            }
            _ => (),
        }

        self.parent_change_state(transition)
    }
}

impl BinImpl for TranscriberBin {
    fn handle_message(&self, msg: gst::Message) {
        use gst::MessageView;

        match msg.view() {
            MessageView::Error(m) => {
                /* We must have a state here */
                let s = self.state.lock().unwrap();

                if let Some(state) = s.as_ref() {
                    if msg.src() == Some(state.transcriber.upcast_ref()) {
                        gst::error!(
                            CAT,
                            imp: self,
                            "Transcriber has posted an error ({:?}), going back to passthrough",
                            m
                        );
                        drop(s);
                        let mut settings = self.settings.lock().unwrap();
                        settings.passthrough = true;
                        drop(settings);
                        self.obj().notify("passthrough");
                        self.obj().call_async(move |bin| {
                            let thiz = bin.imp();
                            thiz.block_and_update(true);
                        });
                    } else {
                        drop(s);
                        self.parent_handle_message(msg);
                    }
                } else {
                    drop(s);
                    self.parent_handle_message(msg);
                }
            }
            _ => self.parent_handle_message(msg),
        }
    }
}
