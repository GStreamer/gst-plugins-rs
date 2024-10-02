// Copyright (C) 2021 Mathieu Duponchelle <mathieu@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use crate::cea608utils::Cea608Mode;
use crate::cea708utils::Cea708Mode;
use anyhow::{anyhow, Error};
use gst::glib;
use gst::prelude::*;
use gst::subclass::prelude::*;
use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use super::{CaptionSource, MuxMethod};

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
const DEFAULT_MUX_METHOD: MuxMethod = MuxMethod::Cea608;

const CEAX08MUX_LATENCY: gst::ClockTime = gst::ClockTime::from_mseconds(100);

/* One per language, including original */
struct TranscriptionChannel {
    bin: gst::Bin,
    textwrap: gst::Element,
    tttoceax08: gst::Element,
    language: String,
    ccmux_pad_name: String,
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

        gst::debug!(
            CAT,
            obj = transcriber,
            "Linking transcriber source pad {transcriber_src_pad:?} to channel"
        );

        transcriber_src_pad.link(&self.bin.static_pad("sink").unwrap())?;

        Ok(())
    }
}

/* Locking order: State, Settings, PadState, PadSettings */

struct State {
    mux_method: MuxMethod,
    framerate: Option<gst::Fraction>,
    tearing_down: usize,
    internal_bin: gst::Bin,
    video_queue: gst::Element,
    ccmux: gst::Element,
    ccmux_filter: gst::Element,
    cccombiner: gst::Element,
    transcription_bin: gst::Bin,
    cccapsfilter: gst::Element,
    transcription_valve: gst::Element,
    audio_serial: u32,
    audio_sink_pads: HashMap<String, super::TranscriberSinkPad>,
}

struct Settings {
    cc_caps: gst::Caps,
    latency: gst::ClockTime,
    translate_latency: gst::ClockTime,
    passthrough: bool,
    accumulate_time: gst::ClockTime,
    caption_source: CaptionSource,
    mux_method: MuxMethod,
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
            caption_source: DEFAULT_CAPTION_SOURCE,
            mux_method: DEFAULT_MUX_METHOD,
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
    fn construct_channel_bin(
        &self,
        lang: &str,
        mux_method: MuxMethod,
        caption_streams: Vec<String>,
    ) -> Result<TranscriptionChannel, Error> {
        let bin = gst::Bin::new();
        let queue = gst::ElementFactory::make("queue").build()?;
        let textwrap = gst::ElementFactory::make("textwrap").build()?;
        let (tttoceax08, ccmux_pad_name) = match mux_method {
            MuxMethod::Cea608 => {
                if caption_streams.len() != 1 {
                    anyhow::bail!("Muxing zero/multiple cea608 streams for the same language is not supported");
                }
                (
                    gst::ElementFactory::make("tttocea608").build()?,
                    caption_streams[0].clone(),
                )
            }
            MuxMethod::Cea708 => {
                if !(1..=2).contains(&caption_streams.len()) {
                    anyhow::bail!(
                        "Incorrect number of caption stream names {} for muxing 608/708",
                        caption_streams.len()
                    );
                }
                let mut service_no = None;
                let mut cea608_channel = None;
                for cc in caption_streams.iter() {
                    if let Some(cea608) = cc.to_lowercase().strip_prefix("cc") {
                        if cea608_channel.is_some() {
                            anyhow::bail!(
                                "Multiple CEA-608 streams for a language are not supported"
                            );
                        }
                        let channel = cea608.parse::<u32>()?;
                        if (1..=4).contains(&channel) {
                            cea608_channel = Some(channel);
                        } else {
                            anyhow::bail!(
                                "CEA-608 channels only support values between 1 and 4 inclusive"
                            );
                        }
                    } else if let Some(cea708_service) = cc.strip_prefix("708_") {
                        if service_no.is_some() {
                            anyhow::bail!(
                                "Multiple CEA-708 streams for a language are not supported"
                            );
                        }
                        service_no = Some(cea708_service.parse::<u32>()?);
                    } else {
                        anyhow::bail!(
                            "caption service name does not match \'708_%u\', or cc1, or cc3"
                        );
                    }
                }
                let service_no = service_no.ok_or(anyhow!("No 708 caption service provided"))?;
                let mut builder =
                    gst::ElementFactory::make("tttocea708").property("service-number", service_no);
                if let Some(channel) = cea608_channel {
                    builder = builder.property("cea608-channel", channel);
                }
                (builder.build()?, format!("sink_{}", service_no))
            }
        };
        let capsfilter = gst::ElementFactory::make("capsfilter").build()?;
        let converter = gst::ElementFactory::make("ccconverter").build()?;

        bin.add_many([&queue, &textwrap, &tttoceax08, &capsfilter, &converter])?;
        gst::Element::link_many([&queue, &textwrap, &tttoceax08, &capsfilter, &converter])?;

        queue.set_property("max-size-buffers", 0u32);
        queue.set_property("max-size-time", 0u64);

        textwrap.set_property("lines", 2u32);

        let caps = match mux_method {
            MuxMethod::Cea608 => gst::Caps::builder("closedcaption/x-cea-608")
                .field("format", "raw")
                .field("framerate", gst::Fraction::new(30000, 1001))
                .build(),
            MuxMethod::Cea708 => gst::Caps::builder("closedcaption/x-cea-708")
                .field("format", "cc_data")
                .field("framerate", gst::Fraction::new(30000, 1001))
                .build(),
        };

        capsfilter.set_property("caps", caps);

        let sinkpad = gst::GhostPad::with_target(&queue.static_pad("sink").unwrap()).unwrap();
        let srcpad = gst::GhostPad::with_target(&converter.static_pad("src").unwrap()).unwrap();
        bin.add_pad(&sinkpad)?;
        bin.add_pad(&srcpad)?;

        Ok(TranscriptionChannel {
            bin,
            textwrap,
            tttoceax08,
            language: String::from(lang),
            ccmux_pad_name,
        })
    }

    fn link_input_audio_stream(
        &self,
        pad_name: &str,
        pad_state: &TranscriberSinkPadState,
        state: &mut State,
    ) -> Result<(), Error> {
        gst::debug!(CAT, imp = self, "Linking input audio stream {pad_name}");

        pad_state
            .transcription_bin
            .set_property("name", format!("transcription-bin-{}", pad_name));

        state
            .internal_bin
            .add_many([
                &pad_state.clocksync,
                &pad_state.identity,
                &pad_state.audio_tee,
                &pad_state.queue_passthrough,
            ])
            .unwrap();
        gst::Element::link_many([
            &pad_state.clocksync,
            &pad_state.identity,
            &pad_state.audio_tee,
        ])?;
        pad_state.audio_tee.link_pads(
            Some("src_%u"),
            &pad_state.queue_passthrough,
            Some("sink"),
        )?;
        state.transcription_bin.add(&pad_state.transcription_bin)?;
        let aqueue_transcription = gst::ElementFactory::make("queue")
            .name("transqueue")
            .property("max-size-buffers", 0u32)
            .property("max-size-bytes", 0u32)
            .property("max-size-time", 5_000_000_000u64)
            .property_from_str("leaky", "downstream")
            .build()?;

        pad_state.transcription_bin.add_many([
            &aqueue_transcription,
            &pad_state.transcriber_resample,
            &pad_state.transcriber_aconv,
        ])?;

        if let Some(ref transcriber) = pad_state.transcriber {
            pad_state.transcription_bin.add(transcriber)?;
        }

        gst::Element::link_many([
            &aqueue_transcription,
            &pad_state.transcriber_resample,
            &pad_state.transcriber_aconv,
        ])?;

        if let Some(ref transcriber) = pad_state.transcriber {
            pad_state.transcriber_aconv.link(transcriber)?;
        }

        let transcription_audio_sinkpad =
            gst::GhostPad::builder_with_target(&aqueue_transcription.static_pad("sink").unwrap())
                .unwrap()
                .name(pad_name)
                .build();

        pad_state
            .transcription_bin
            .add_pad(&transcription_audio_sinkpad)?;

        let transcription_audio_sinkpad =
            gst::GhostPad::with_target(&transcription_audio_sinkpad).unwrap();

        state
            .transcription_bin
            .add_pad(&transcription_audio_sinkpad)?;

        for channel in pad_state.transcription_channels.values() {
            pad_state.transcription_bin.add(&channel.bin)?;

            if let Some(ref transcriber) = pad_state.transcriber {
                channel.link_transcriber(transcriber)?;
            }

            let srcpad =
                gst::GhostPad::builder_with_target(&channel.bin.static_pad("src").unwrap())
                    .unwrap()
                    .name(format!("src_{}", channel.language))
                    .build();

            pad_state.transcription_bin.add_pad(&srcpad)?;
            if state.ccmux.static_pad(&channel.ccmux_pad_name).is_none() {
                let ccmux_pad = state
                    .ccmux
                    .request_pad_simple(&channel.ccmux_pad_name)
                    .ok_or(anyhow!("Failed to request ccmux sink pad"))?;
                srcpad.link(&ccmux_pad)?;
            }
        }

        Ok(())
    }

    fn construct_transcription_bin(&self, state: &mut State) -> Result<(), Error> {
        gst::debug!(CAT, imp = self, "Building transcription bin");

        let ccconverter = gst::ElementFactory::make("ccconverter").build()?;

        state.transcription_bin.add_many([
            &state.ccmux,
            &state.ccmux_filter,
            &ccconverter,
            &state.cccapsfilter,
            &state.transcription_valve,
        ])?;

        gst::Element::link_many([
            &state.ccmux,
            &state.ccmux_filter,
            &ccconverter,
            &state.cccapsfilter,
            &state.transcription_valve,
        ])?;

        state.ccmux.set_property("latency", CEAX08MUX_LATENCY);

        let transcription_audio_srcpad =
            gst::GhostPad::with_target(&state.transcription_valve.static_pad("src").unwrap())
                .unwrap();

        state
            .transcription_bin
            .add_pad(&transcription_audio_srcpad)?;

        state.internal_bin.add(&state.transcription_bin)?;

        state.transcription_bin.set_locked_state(true);

        Ok(())
    }

    fn construct_internal_bin(&self, state: &mut State) -> Result<(), Error> {
        let vclocksync = gst::ElementFactory::make("clocksync")
            .name("vclocksync")
            .build()?;

        state
            .internal_bin
            .add_many([&vclocksync, &state.video_queue, &state.cccombiner])?;

        vclocksync.link(&state.video_queue)?;
        state
            .video_queue
            .link_pads(Some("src"), &state.cccombiner, Some("sink"))?;

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

        self.video_sinkpad
            .set_target(Some(&state.internal_bin.static_pad("video_sink").unwrap()))?;
        self.video_srcpad
            .set_target(Some(&state.internal_bin.static_pad("video_src").unwrap()))?;

        self.construct_transcription_bin(state)?;

        let pad = self
            .audio_sinkpad
            .downcast_ref::<super::TranscriberSinkPad>()
            .unwrap();
        // FIXME: replace this pattern with https://doc.rust-lang.org/nightly/std/sync/struct.MappedMutexGuard.html
        let ps = pad.imp().state.lock().unwrap();
        let pad_state = ps.as_ref().unwrap();

        self.link_input_audio_stream("sink_audio", pad_state, state)?;

        let internal_audio_sinkpad =
            gst::GhostPad::builder_with_target(&pad_state.clocksync.static_pad("sink").unwrap())
                .unwrap()
                .name("audio_sink")
                .build();
        let internal_audio_srcpad = gst::GhostPad::builder_with_target(
            &pad_state.queue_passthrough.static_pad("src").unwrap(),
        )
        .unwrap()
        .name("audio_src")
        .build();

        state.internal_bin.add_pad(&internal_audio_sinkpad)?;
        state.internal_bin.add_pad(&internal_audio_srcpad)?;

        self.audio_sinkpad
            .set_target(Some(&state.internal_bin.static_pad("audio_sink").unwrap()))?;
        self.audio_srcpad
            .set_target(Some(&state.internal_bin.static_pad("audio_src").unwrap()))?;
        Ok(())
    }

    fn setup_transcription(&self, state: &State) {
        let settings = self.settings.lock().unwrap();
        let mut cc_caps = settings.cc_caps.clone();

        let cc_caps_mut = cc_caps.make_mut();
        let s = cc_caps_mut.structure_mut(0).unwrap();

        s.set("framerate", state.framerate.unwrap());

        state.cccapsfilter.set_property("caps", &cc_caps);

        let ccmux_caps = match state.mux_method {
            MuxMethod::Cea608 => gst::Caps::builder("closedcaption/x-cea-608")
                .field("framerate", state.framerate.unwrap())
                .build(),
            MuxMethod::Cea708 => gst::Caps::builder("closedcaption/x-cea-708")
                .field("format", "cc_data")
                .field("framerate", state.framerate.unwrap())
                .build(),
        };

        state.ccmux_filter.set_property("caps", ccmux_caps);

        let max_size_time = settings.latency
            + settings.translate_latency
            + settings.accumulate_time
            + CEAX08MUX_LATENCY;

        gst::debug!(
            CAT,
            "Calculated max size time for passthrough branches: {max_size_time}"
        );

        state.video_queue.set_property("max-size-bytes", 0u32);
        state.video_queue.set_property("max-size-buffers", 0u32);
        state
            .video_queue
            .set_property("max-size-time", max_size_time);

        for pad in state.audio_sink_pads.values() {
            let ps = pad.imp().state.lock().unwrap();
            let pad_state = ps.as_ref().unwrap();

            if let Some(ref transcriber) = pad_state.transcriber {
                let latency_ms = settings.latency.mseconds() as u32;
                transcriber.set_property("transcribe-latency", latency_ms);

                let translate_latency_ms = settings.translate_latency.mseconds() as u32;
                transcriber.set_property("translate-latency", translate_latency_ms);
            }
            pad_state
                .queue_passthrough
                .set_property("max-size-bytes", 0u32);
            pad_state
                .queue_passthrough
                .set_property("max-size-buffers", 0u32);
            pad_state
                .queue_passthrough
                .set_property("max-size-time", max_size_time);
        }

        if !settings.passthrough {
            gst::debug!(
                CAT,
                imp = self,
                "Linking transcription bins and synchronizing state"
            );
            state
                .transcription_bin
                .link_pads(Some("src"), &state.cccombiner, Some("caption"))
                .unwrap();

            state.transcription_bin.set_locked_state(false);
            state.transcription_bin.sync_state_with_parent().unwrap();

            for pad in state.audio_sink_pads.values() {
                let ps = pad.imp().state.lock().unwrap();
                let pad_state = ps.as_ref().unwrap();
                pad_state.transcription_bin.set_locked_state(false);
                pad_state
                    .transcription_bin
                    .sync_state_with_parent()
                    .unwrap();
                let transcription_sink_pad =
                    state.transcription_bin.static_pad(&pad.name()).unwrap();
                // Might be linked already if "translation-languages" is set
                if transcription_sink_pad.peer().is_none() {
                    let audio_tee_pad = pad_state.audio_tee.request_pad_simple("src_%u").unwrap();
                    audio_tee_pad.link(&transcription_sink_pad).unwrap();
                }
            }
        }

        for pad in state.audio_sink_pads.values() {
            let ps = pad.imp().state.lock().unwrap();
            let pad_state = ps.as_ref().unwrap();
            let pad_settings = pad.imp().settings.lock().unwrap();
            self.setup_cc_mode(pad, pad_state, state.mux_method, pad_settings.mode);
        }
    }

    fn disable_transcription_bin(&self, state: &mut State) {
        // At this point, we want to check whether passthrough
        // has been unset in the meantime
        let passthrough = self.settings.lock().unwrap().passthrough;

        if passthrough {
            gst::debug!(CAT, imp = self, "disabling transcription bin");

            for pad in state.audio_sink_pads.values() {
                let ps = pad.imp().state.lock().unwrap();
                let pad_state = ps.as_ref().unwrap();
                let bin_sink_pad = state.transcription_bin.static_pad(&pad.name()).unwrap();
                if let Some(audio_tee_pad) = bin_sink_pad.peer() {
                    audio_tee_pad.unlink(&bin_sink_pad).unwrap();
                    pad_state.audio_tee.release_request_pad(&audio_tee_pad);
                }
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

    fn block_and_update(&self, passthrough: bool) {
        let mut s = self.state.lock().unwrap();

        if let Some(ref mut state) = s.as_mut() {
            if passthrough {
                state.tearing_down = state.audio_sink_pads.len();
                let sinkpads = state.audio_sink_pads.clone();
                drop(s);
                for sinkpad in sinkpads.values() {
                    let imp_weak = self.downgrade();
                    let _ = sinkpad.add_probe(
                        gst::PadProbeType::IDLE
                            | gst::PadProbeType::BUFFER
                            | gst::PadProbeType::EVENT_DOWNSTREAM,
                        move |_pad, _info| {
                            let Some(imp) = imp_weak.upgrade() else {
                                return gst::PadProbeReturn::Remove;
                            };

                            let mut s = imp.state.lock().unwrap();

                            if let Some(ref mut state) = s.as_mut() {
                                state.tearing_down -= 1;
                                if state.tearing_down == 0 {
                                    imp.disable_transcription_bin(state);
                                }
                            }

                            gst::PadProbeReturn::Remove
                        },
                    );
                }
            } else if state.tearing_down > 0 {
                // Do nothing, wait for the previous transcription bin
                // to finish tearing down
            } else {
                state
                    .transcription_bin
                    .link_pads(Some("src"), &state.cccombiner, Some("caption"))
                    .unwrap();
                state.transcription_bin.set_locked_state(false);
                state.transcription_bin.sync_state_with_parent().unwrap();

                for pad in state.audio_sink_pads.values() {
                    let ps = pad.imp().state.lock().unwrap();
                    let pad_state = ps.as_ref().unwrap();
                    pad_state.transcription_bin.set_locked_state(false);
                    pad_state
                        .transcription_bin
                        .sync_state_with_parent()
                        .unwrap();
                    let audio_tee_pad = pad_state.audio_tee.request_pad_simple("src_%u").unwrap();
                    let transcription_sink_pad =
                        state.transcription_bin.static_pad(&pad.name()).unwrap();
                    audio_tee_pad.link(&transcription_sink_pad).unwrap();
                }
            }
        }
    }

    fn setup_cc_mode(
        &self,
        pad: &super::TranscriberSinkPad,
        pad_state: &TranscriberSinkPadState,
        mux_method: MuxMethod,
        mode: Cea608Mode,
    ) {
        gst::debug!(
            CAT,
            imp = self,
            "setting CC mode {:?} for pad {:?}",
            mode,
            pad
        );

        for channel in pad_state.transcription_channels.values() {
            match mux_method {
                MuxMethod::Cea608 => channel.tttoceax08.set_property("mode", mode),
                MuxMethod::Cea708 => match mode {
                    Cea608Mode::PopOn => channel.tttoceax08.set_property("mode", Cea708Mode::PopOn),
                    Cea608Mode::PaintOn => {
                        channel.tttoceax08.set_property("mode", Cea708Mode::PaintOn)
                    }
                    Cea608Mode::RollUp2 | Cea608Mode::RollUp3 | Cea608Mode::RollUp4 => {
                        channel.tttoceax08.set_property("mode", Cea708Mode::RollUp)
                    }
                },
            }

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
        pad_state: &TranscriberSinkPadState,
        old_transcriber: Option<&gst::Element>,
    ) -> Result<(), Error> {
        gst::debug!(
            CAT,
            imp = self,
            "Relinking transcriber, old: {:?}, new: {:?}",
            old_transcriber,
            pad_state.transcriber
        );

        if let Some(old_transcriber) = old_transcriber {
            gst::debug!(
                CAT,
                imp = self,
                "Unlinking old transcriber {old_transcriber:?}"
            );
            pad_state.transcriber_aconv.unlink(old_transcriber);
            for channel in pad_state.transcription_channels.values() {
                old_transcriber.unlink(&channel.bin);
            }
            let _ = state.transcription_bin.remove(old_transcriber);
            old_transcriber.set_state(gst::State::Null).unwrap();
        }

        if let Some(ref transcriber) = pad_state.transcriber {
            state.transcription_bin.add(transcriber)?;
            transcriber.sync_state_with_parent().unwrap();
            pad_state.transcriber_aconv.link(transcriber)?;

            for channel in pad_state.transcription_channels.values() {
                channel.link_transcriber(transcriber)?;
            }
        }

        Ok(())
    }

    fn construct_transcription_channels(
        &self,
        settings: &TranscriberSinkPadSettings,
        mux_method: MuxMethod,
        transcription_channels: &mut HashMap<String, TranscriptionChannel>,
    ) -> Result<(), Error> {
        if let Some(ref map) = settings.translation_languages {
            for (key, value) in map.iter() {
                let key = key.to_lowercase();
                let (language_code, caption_streams) = match mux_method {
                    MuxMethod::Cea608 => {
                        if ["cc1", "cc3"].contains(&key.as_str()) {
                            (value.get::<String>()?, vec![key.to_string()])
                        } else if let Ok(caption_stream) = value.get::<String>() {
                            if !["cc1", "cc3"].contains(&caption_stream.as_str()) {
                                anyhow::bail!(
                                    "Unknown 608 channel {}, valid values are cc1, cc3",
                                    caption_stream
                                );
                            }
                            (key, vec![caption_stream])
                        } else {
                            anyhow::bail!("Unknown 608 channel/language {}", key);
                        }
                    }
                    MuxMethod::Cea708 => {
                        if let Ok(caption_stream) = value.get::<String>() {
                            (key, vec![caption_stream])
                        } else if let Ok(caption_streams) = value.get::<gst::List>() {
                            let mut streams = vec![];
                            for s in caption_streams.iter() {
                                let service = s.get::<String>()?;
                                if ["cc1", "cc3"].contains(&service.as_str())
                                    || service.starts_with("708_")
                                {
                                    streams.push(service);
                                } else {
                                    anyhow::bail!("Unknown 708 service {}, valid values are cc1, cc3 or 708_*", key);
                                }
                            }
                            (key, streams)
                        } else {
                            anyhow::bail!("Unknown 708 translation language field {}", key);
                        }
                    }
                };

                transcription_channels.insert(
                    language_code.to_owned(),
                    self.construct_channel_bin(&language_code, mux_method, caption_streams)?,
                );
            }
        } else {
            let caption_streams = match mux_method {
                MuxMethod::Cea608 => vec!["cc1".to_string()],
                MuxMethod::Cea708 => vec!["cc1".to_string(), "708_1".to_string()],
            };
            transcription_channels.insert(
                "transcript".to_string(),
                self.construct_channel_bin("transcript", mux_method, caption_streams)?,
            );
        }
        Ok(())
    }

    fn reconfigure_transcription_bin(
        &self,
        pad: &TranscriberSinkPad,
        lang_code_only: bool,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().unwrap();

        if let Some(ref mut state) = state.as_mut() {
            let settings = self.settings.lock().unwrap();
            let mut ps = pad.state.lock().unwrap();
            let pad_state = ps.as_mut().unwrap();
            let pad_settings = pad.settings.lock().unwrap();

            gst::debug!(
                CAT,
                imp = self,
                "Updating transcription/translation language"
            );

            // Unlink sinkpad temporarily
            let sinkpad = state
                .transcription_bin
                .static_pad(&pad.obj().name())
                .unwrap();
            let peer = sinkpad.peer();
            if let Some(peer) = &peer {
                gst::debug!(CAT, imp = self, "Unlinking {:?}", peer);
                peer.unlink(&sinkpad)?;
                pad_state.audio_tee.release_request_pad(peer);
            }

            pad_state.transcription_bin.set_locked_state(true);
            pad_state
                .transcription_bin
                .set_state(gst::State::Null)
                .unwrap();

            if let Some(ref transcriber) = pad_state.transcriber {
                transcriber.set_property("language-code", &pad_settings.language_code);
            }

            if lang_code_only {
                if !settings.passthrough {
                    gst::debug!(CAT, imp = self, "Syncing state with parent");

                    drop(settings);

                    // While we haven't locked the state here, the state of the
                    // top level transcription bin might be locked, for instance
                    // at start up. Unlock and sync both the inner and top level
                    // bin states to ensure data flows in the correct state
                    state.transcription_bin.set_locked_state(false);
                    state.transcription_bin.sync_state_with_parent().unwrap();

                    pad_state.transcription_bin.set_locked_state(false);
                    pad_state.transcription_bin.sync_state_with_parent()?;

                    let audio_tee_pad = pad_state.audio_tee.request_pad_simple("src_%u").unwrap();
                    audio_tee_pad.link(&sinkpad)?;
                }

                return Ok(());
            }

            for channel in pad_state.transcription_channels.values() {
                let sinkpad = channel.bin.static_pad("sink").unwrap();
                if let Some(peer) = sinkpad.peer() {
                    peer.unlink(&sinkpad)?;
                    if channel.language != "transcript" {
                        if let Some(ref transcriber) = pad_state.transcriber {
                            transcriber.release_request_pad(&peer);
                        }
                    }
                }

                let srcpad = channel.bin.static_pad("src").unwrap();
                if let Some(peer) = srcpad.peer() {
                    // The source pad might not have been linked to the muxer initially, for
                    // instance in case of a collision with another source pad's
                    // translation-languages mapping
                    if peer.parent().and_downcast_ref::<gst::Element>()
                        == Some(state.ccmux.as_ref())
                    {
                        srcpad.unlink(&peer)?;
                        state.ccmux.release_request_pad(&peer);
                    }
                }

                pad_state.transcription_bin.remove(&channel.bin)?;
            }

            pad_state.transcription_channels.clear();

            self.construct_transcription_channels(
                &pad_settings,
                state.mux_method,
                &mut pad_state.transcription_channels,
            )?;

            for channel in pad_state.transcription_channels.values() {
                pad_state.transcription_bin.add(&channel.bin)?;

                if let Some(ref transcriber) = pad_state.transcriber {
                    channel.link_transcriber(transcriber)?;
                }

                let srcpad = pad_state
                    .transcription_bin
                    .static_pad(&format!("src_{}", channel.language))
                    .unwrap();

                srcpad
                    .downcast_ref::<gst::GhostPad>()
                    .unwrap()
                    .set_target(channel.bin.static_pad("src").as_ref())?;

                if state.ccmux.static_pad(&channel.ccmux_pad_name).is_none() {
                    let ccmux_pad = state
                        .ccmux
                        .request_pad_simple(&channel.ccmux_pad_name)
                        .ok_or(anyhow!("Failed to request ccmux sink pad"))?;
                    srcpad.link(&ccmux_pad)?;
                }
            }

            self.setup_cc_mode(&pad.obj(), pad_state, state.mux_method, pad_settings.mode);

            if !settings.passthrough {
                gst::debug!(CAT, imp = self, "Syncing state with parent");

                let audio_tee_pad = pad_state.audio_tee.request_pad_simple("src_%u").unwrap();

                drop(pad_settings);
                drop(settings);

                pad_state.transcription_bin.set_locked_state(false);
                pad_state.transcription_bin.sync_state_with_parent()?;
                audio_tee_pad.link(&sinkpad)?;
            }
        }

        Ok(())
    }

    fn update_languages(&self, pad: &super::TranscriberSinkPad, lang_code_only: bool) {
        gst::debug!(
            CAT,
            imp = self,
            "Schedule transcription/translation language update for pad {pad:?}"
        );

        let Some(sinkpad) = pad
            .imp()
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .transcription_bin
            .static_pad(pad.name().as_str())
        else {
            gst::debug!(CAT, imp = pad.imp(), "transcription bin not set up yet");
            return;
        };

        let imp_weak = self.downgrade();
        let pad_weak = pad.downgrade();

        let _ = sinkpad.add_probe(
            gst::PadProbeType::IDLE
                | gst::PadProbeType::BUFFER
                | gst::PadProbeType::EVENT_DOWNSTREAM,
            move |_pad, _info| {
                let Some(imp) = imp_weak.upgrade() else {
                    return gst::PadProbeReturn::Remove;
                };

                let Some(pad) = pad_weak.upgrade() else {
                    return gst::PadProbeReturn::Remove;
                };

                if let Err(e) = imp.reconfigure_transcription_bin(pad.imp(), lang_code_only) {
                    gst::error!(CAT, "Couldn't reconfigure channels: {e}");
                    gst::element_imp_error!(
                        imp,
                        gst::StreamError::Failed,
                        ["Couldn't reconfigure channels: {}", e]
                    );
                    *imp.state.lock().unwrap() = None;
                }

                gst::PadProbeReturn::Remove
            },
        );
    }

    fn any_sink_is_translating(&self, state: &State) -> bool {
        for pad in state.audio_sink_pads.values() {
            let ps = pad.imp().state.lock().unwrap();
            let pad_state = ps.as_ref().unwrap();
            if pad_state
                .transcription_channels
                .values()
                .any(|c| c.language != "transcript")
            {
                return true;
            }
        }
        false
    }

    fn any_sink_is_rollup(&self, state: &State) -> bool {
        for pad in state.audio_sink_pads.values() {
            let pad_settings = pad.imp().settings.lock().unwrap();
            if pad_settings.mode.is_rollup() {
                return true;
            }
        }
        false
    }

    #[allow(clippy::single_match)]
    fn src_query(&self, pad: &gst::Pad, query: &mut gst::QueryRef) -> bool {
        use gst::QueryViewMut;

        gst::log!(CAT, obj = pad, "Handling query {:?}", query);

        match query.view_mut() {
            QueryViewMut::Latency(q) => {
                let mut upstream_query = gst::query::Latency::new();

                let ret = gst::Pad::query_default(pad, Some(&*self.obj()), &mut upstream_query);

                if ret {
                    let (_, mut min, _) = upstream_query.result();
                    let state = self.state.lock().unwrap();
                    let (received_framerate, translating) = {
                        if let Some(state) = state.as_ref() {
                            (state.framerate, self.any_sink_is_translating(state))
                        } else {
                            (None, false)
                        }
                    };

                    let settings = self.settings.lock().unwrap();
                    if settings.passthrough || received_framerate.is_none() {
                        min += settings.latency + settings.accumulate_time + CEAX08MUX_LATENCY;

                        if translating {
                            min += settings.translate_latency;
                        }

                        /* The sub latency introduced by ceax08mux */
                        if let Some(framerate) = received_framerate {
                            min += gst::ClockTime::SECOND
                                .mul_div_floor(framerate.denom() as u64, framerate.numer() as u64)
                                .unwrap();
                        }
                    } else if let Some(state) = state.as_ref() {
                        if self.any_sink_is_rollup(state) {
                            min += settings.accumulate_time;
                        }
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
        let cccombiner = gst::ElementFactory::make("cccombiner")
            .name("cccombiner")
            .build()?;
        let video_queue = gst::ElementFactory::make("queue").build()?;
        let cccapsfilter = gst::ElementFactory::make("capsfilter").build()?;
        let transcription_valve = gst::ElementFactory::make("valve")
            .property_from_str("drop-mode", "transform-to-gap")
            .build()?;

        let settings = self.settings.lock().unwrap();
        let mux_method = settings.mux_method;

        let ccmux = match mux_method {
            MuxMethod::Cea608 => gst::ElementFactory::make("cea608mux")
                .property_from_str("start-time-selection", "first")
                .build()?,
            MuxMethod::Cea708 => gst::ElementFactory::make("cea708mux")
                .property_from_str("start-time-selection", "first")
                .build()?,
        };
        let ccmux_filter = gst::ElementFactory::make("capsfilter").build()?;

        let pad = self
            .audio_sinkpad
            .clone()
            .downcast::<super::TranscriberSinkPad>()
            .unwrap();
        let mut audio_sink_pads = HashMap::new();
        audio_sink_pads.insert(self.audio_sinkpad.name().to_string(), pad.clone());
        let mut ps = pad.imp().state.lock().unwrap();
        let pad_state = ps
            .as_mut()
            .map_err(|err| anyhow!("Sink pad state creation failed: {err}"))?;
        let pad_settings = pad.imp().settings.lock().unwrap();
        self.construct_transcription_channels(
            &pad_settings,
            settings.mux_method,
            &mut pad_state.transcription_channels,
        )?;

        Ok(State {
            mux_method,
            framerate: None,
            internal_bin,
            video_queue,
            ccmux,
            ccmux_filter,
            cccombiner,
            transcription_bin,
            cccapsfilter,
            transcription_valve,
            tearing_down: 0,
            audio_serial: 0,
            audio_sink_pads,
        })
    }

    #[allow(clippy::single_match)]
    fn video_sink_event(&self, pad: &gst::Pad, event: gst::Event) -> bool {
        use gst::EventView;

        gst::log!(CAT, obj = pad, "Handling event {:?}", event);
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
                            imp = self,
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

impl ChildProxyImpl for TranscriberBin {
    fn child_by_index(&self, index: u32) -> Option<glib::Object> {
        let parent_children_count = self.parent_children_count();

        if index < parent_children_count {
            self.parent_child_by_index(index)
        } else {
            self.obj()
                .pads()
                .into_iter()
                .nth((index - parent_children_count) as usize)
                .map(|p| p.upcast())
        }
    }

    fn children_count(&self) -> u32 {
        let object = self.obj();
        self.parent_children_count() + object.num_pads() as u32
    }

    fn child_by_name(&self, name: &str) -> Option<glib::Object> {
        if let Some(child) = self.parent_child_by_name(name) {
            Some(child)
        } else {
            self.obj().static_pad(name).map(|pad| pad.upcast())
        }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for TranscriberBin {
    const NAME: &'static str = "GstTranscriberBin";
    type Type = super::TranscriberBin;
    type ParentType = gst::Bin;
    type Interfaces = (gst::ChildProxy,);

    fn with_class(klass: &Self::Class) -> Self {
        let templ = klass.pad_template("sink_audio").unwrap();
        let audio_sinkpad =
            gst::PadBuilder::<super::TranscriberSinkPad>::from_template(&templ).build();
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
            audio_sinkpad: audio_sinkpad.into(),
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
                    .blurb("A map of language codes to caption channels, e.g. translation-languages=\"languages, transcript={CC1, 708_1}, fr={708_2, CC3}\" will map the French translation to CC1/service 1 and the original transcript to CC3/service 2")
                    .construct()
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
                glib::ParamSpecEnum::builder("mux-method")
                    .nick("Mux Method")
                    .blurb("The method for muxing multiple transcription streams")
                    .default_value(DEFAULT_MUX_METHOD)
                    .construct()
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
                self.audio_sinkpad.set_property(
                    "mode",
                    value.get::<Cea608Mode>().expect("type checked upstream"),
                );
            }
            "cc-caps" => {
                let mut settings = self.settings.lock().unwrap();
                settings.cc_caps = value.get().expect("type checked upstream");
            }
            "transcriber" => {
                self.audio_sinkpad.set_property(
                    "transcriber",
                    value.get::<gst::Element>().expect("type checked upstream"),
                );
            }
            "caption-source" => {
                let mut settings = self.settings.lock().unwrap();
                settings.caption_source = value.get().expect("type checked upstream");

                let s = self.state.lock().unwrap();
                if let Some(state) = s.as_ref() {
                    if settings.caption_source == CaptionSource::Inband {
                        gst::debug!(
                            CAT,
                            imp = self,
                            "Use inband caption, dropping transcription"
                        );
                        state.transcription_valve.set_property("drop", true);
                    } else {
                        gst::debug!(CAT, imp = self, "Stop dropping transcription");
                        state.transcription_valve.set_property("drop", false);
                    }
                }
            }
            "translation-languages" => {
                self.audio_sinkpad.set_property(
                    "translation-languages",
                    value
                        .get::<Option<gst::Structure>>()
                        .expect("type checked upstream"),
                );
            }
            "translate-latency" => {
                let mut settings = self.settings.lock().unwrap();
                settings.translate_latency = gst::ClockTime::from_mseconds(
                    value.get::<u32>().expect("type checked upstream").into(),
                );
            }
            "language-code" => {
                self.audio_sinkpad.set_property(
                    "language-code",
                    value
                        .get::<Option<String>>()
                        .expect("type checked upstream"),
                );
            }
            "mux-method" => {
                let mut settings = self.settings.lock().unwrap();
                settings.mux_method = value.get().expect("type checked upstream")
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
            "mode" => self.audio_sinkpad.property("mode"),
            "cc-caps" => {
                let settings = self.settings.lock().unwrap();
                settings.cc_caps.to_value()
            }
            "transcriber" => self.audio_sinkpad.property("transcriber"),
            "caption-source" => {
                let settings = self.settings.lock().unwrap();
                settings.caption_source.to_value()
            }
            "translation-languages" => self.audio_sinkpad.property("translation-languages"),
            "translate-latency" => {
                let settings = self.settings.lock().unwrap();
                (settings.translate_latency.mseconds() as u32).to_value()
            }
            "language-code" => self.audio_sinkpad.property("language-code"),
            "mux-method" => {
                let settings = self.settings.lock().unwrap();
                settings.mux_method.to_value()
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
            let audio_sink_pad_template = gst::PadTemplate::with_gtype(
                "sink_audio",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &caps,
                super::TranscriberSinkPad::static_type(),
            )
            .unwrap();
            let secondary_audio_sink_pad_template = gst::PadTemplate::with_gtype(
                "sink_audio_%u",
                gst::PadDirection::Sink,
                gst::PadPresence::Request,
                &caps,
                super::TranscriberSinkPad::static_type(),
            )
            .unwrap();
            let secondary_audio_src_pad_template = gst::PadTemplate::with_gtype(
                "src_audio_%u",
                gst::PadDirection::Src,
                gst::PadPresence::Sometimes,
                &caps,
                super::TranscriberSrcPad::static_type(),
            )
            .unwrap();

            vec![
                video_src_pad_template,
                video_sink_pad_template,
                audio_src_pad_template,
                audio_sink_pad_template,
                secondary_audio_sink_pad_template,
                secondary_audio_src_pad_template,
            ]
        });

        PAD_TEMPLATES.as_ref()
    }

    fn release_pad(&self, pad: &gst::Pad) {
        if self.obj().current_state() > gst::State::Null {
            gst::fixme!(
                CAT,
                obj = pad,
                "releasing secondary audio stream while PLAYING is untested"
            );
        }

        // In practice we will probably at least need some flushing here,
        // and latency recalculating, but at least the basic skeleton for
        // releasing is in place

        let Some(pad) = pad.downcast_ref::<super::TranscriberSinkPad>() else {
            gst::error!(CAT, imp = self, "not a transcriber sink pad: {pad:?}");
            return;
        };

        let mut s = self.state.lock().unwrap();
        let ps = pad.imp().state.lock().unwrap();
        let pad_state = ps.as_ref().unwrap();

        pad_state.transcription_bin.set_locked_state(true);
        let _ = pad_state.transcription_bin.set_state(gst::State::Null);

        if let Some(ref mut state) = s.as_mut() {
            for channel in pad_state.transcription_channels.values() {
                if let Some(srcpad) = pad_state
                    .transcription_bin
                    .static_pad(&format!("src_{}", channel.language))
                {
                    if let Some(peer) = srcpad.peer() {
                        let _ = state.ccmux.remove_pad(&peer);
                    }
                }
            }

            let _ = state.transcription_bin.remove(&pad_state.transcription_bin);
            for srcpad in pad_state.audio_tee.iterate_src_pads() {
                let srcpad = srcpad.unwrap();
                if let Some(peer) = srcpad.peer() {
                    if let Some(parent) = peer.parent() {
                        if parent == state.transcription_bin {
                            let _ = parent.downcast::<gst::Element>().unwrap().remove_pad(&peer);
                        }
                    }
                }
            }
            let _ = state.internal_bin.remove_many([
                &pad_state.clocksync,
                &pad_state.identity,
                &pad_state.audio_tee,
            ]);
            state.audio_sink_pads.remove(pad.name().as_str());
        }

        let srcpad = pad_state
            .srcpad_name
            .as_ref()
            .and_then(|name| self.obj().static_pad(name));

        drop(ps);
        drop(s);

        let _ = pad.set_active(false);
        let _ = self.obj().remove_pad(pad);

        if let Some(srcpad) = srcpad {
            let _ = srcpad.set_active(false);
            let _ = self.obj().remove_pad(&srcpad);
        }

        self.obj()
            .child_removed(pad.upcast_ref::<gst::Object>(), &pad.name());
    }

    fn request_new_pad(
        &self,
        _templ: &gst::PadTemplate,
        _name: Option<&str>,
        _caps: Option<&gst::Caps>,
    ) -> Option<gst::Pad> {
        let element = self.obj();
        if element.current_state() > gst::State::Null {
            gst::error!(CAT, "element pads can only be requested before starting");
            return None;
        }

        let mut s = self.state.lock().unwrap();
        if let Some(ref mut state) = s.as_mut() {
            let name = format!("sink_audio_{}", state.audio_serial);

            let templ = self.obj().pad_template("sink_audio_%u").unwrap();
            let sink_pad = gst::PadBuilder::<super::TranscriberSinkPad>::from_template(&templ)
                .name(&name)
                .build();

            let src_pad = {
                let settings = self.settings.lock().unwrap();
                let mut s = sink_pad.imp().state.lock().unwrap();
                let pad_state = match s.as_mut() {
                    Ok(s) => s,
                    Err(e) => {
                        gst::error!(CAT, "Failed to construct sink pad: {e}");
                        return None;
                    }
                };
                let pad_settings = sink_pad.imp().settings.lock().unwrap();
                self.construct_transcription_channels(
                    &pad_settings,
                    settings.mux_method,
                    &mut pad_state.transcription_channels,
                )
                .unwrap();

                if let Err(e) = self.link_input_audio_stream(&name, pad_state, state) {
                    gst::error!(CAT, "Failed to link secondary audio stream: {e}");
                    return None;
                }

                let internal_sink_pad = gst::GhostPad::builder_with_target(
                    &pad_state.clocksync.static_pad("sink").unwrap(),
                )
                .unwrap()
                .name(name.clone())
                .build();
                internal_sink_pad.set_active(true).unwrap();
                state.internal_bin.add_pad(&internal_sink_pad).unwrap();
                sink_pad.set_target(Some(&internal_sink_pad)).unwrap();
                sink_pad.set_active(true).unwrap();
                state
                    .audio_sink_pads
                    .insert(name.to_string(), sink_pad.clone());

                let templ = self.obj().pad_template("src_audio_%u").unwrap();
                let name = format!("src_audio_{}", state.audio_serial);
                let src_pad = gst::PadBuilder::<super::TranscriberSrcPad>::from_template(&templ)
                    .name(name.as_str())
                    .query_function(|pad, parent, query| {
                        TranscriberBin::catch_panic_pad_function(
                            parent,
                            || false,
                            |transcriber| transcriber.src_query(pad.upcast_ref(), query),
                        )
                    })
                    .build();
                let internal_src_pad = gst::GhostPad::builder_with_target(
                    &pad_state.queue_passthrough.static_pad("src").unwrap(),
                )
                .unwrap()
                .name(&name)
                .build();
                internal_src_pad.set_active(true).unwrap();
                state.internal_bin.add_pad(&internal_src_pad).unwrap();
                src_pad.set_target(Some(&internal_src_pad)).unwrap();
                src_pad.set_active(true).unwrap();

                pad_state.srcpad_name = Some(name.clone());

                src_pad
            };

            state.audio_serial += 1;

            drop(s);

            self.obj().add_pad(&sink_pad).unwrap();
            self.obj()
                .child_added(sink_pad.upcast_ref::<gst::Object>(), &sink_pad.name());
            self.obj().add_pad(&src_pad).unwrap();

            Some(sink_pad.upcast())
        } else {
            None
        }
    }

    #[allow(clippy::single_match)]
    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        gst::trace!(CAT, imp = self, "Changing state {:?}", transition);

        match transition {
            gst::StateChange::ReadyToPaused => {
                let mut state = self.state.lock().unwrap();

                if let Some(ref mut state) = state.as_mut() {
                    if state.framerate.is_some() {
                        gst::info!(
                            CAT,
                            imp = self,
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
                let pad = self
                    .audio_sinkpad
                    .downcast_ref::<super::TranscriberSinkPad>()
                    .unwrap();
                let ps = pad.imp().state.lock().unwrap();
                let pad_state = ps.as_ref().unwrap();
                if msg.src() == pad_state.transcriber.as_ref().map(|t| t.upcast_ref()) {
                    gst::error!(
                        CAT,
                        imp = self,
                        "Transcriber has posted an error ({m:?}), going back to passthrough",
                    );
                    drop(ps);
                    self.settings.lock().unwrap().passthrough = true;
                    self.obj().notify("passthrough");
                    self.obj().call_async(move |bin| {
                        let thiz = bin.imp();
                        thiz.block_and_update(true);
                    });
                } else {
                    drop(ps);
                    self.parent_handle_message(msg);
                }
            }
            _ => self.parent_handle_message(msg),
        }
    }
}

#[derive(Debug, Clone)]
struct TranscriberSinkPadSettings {
    translation_languages: Option<gst::Structure>,
    language_code: String,
    mode: Cea608Mode,
}

impl Default for TranscriberSinkPadSettings {
    fn default() -> Self {
        Self {
            translation_languages: None,
            language_code: String::from(DEFAULT_INPUT_LANG_CODE),
            mode: DEFAULT_MODE,
        }
    }
}

struct TranscriberSinkPadState {
    clocksync: gst::Element,
    identity: gst::Element,
    audio_tee: gst::Element,
    transcription_bin: gst::Bin,
    transcriber_aconv: gst::Element,
    transcriber_resample: gst::Element,
    transcriber: Option<gst::Element>,
    queue_passthrough: gst::Element,
    transcription_channels: HashMap<String, TranscriptionChannel>,
    srcpad_name: Option<String>,
}

impl TranscriberSinkPadState {
    fn try_new() -> Result<Self, Error> {
        Ok(Self {
            clocksync: gst::ElementFactory::make("clocksync").build()?,
            identity: gst::ElementFactory::make("identity")
                // We need to do that otherwise downstream may block for up to
                // latency long until the allocation makes it through all branches.
                // Audio buffer pools are fortunately not the most critical :)
                .property("drop-allocation", true)
                .build()?,
            audio_tee: gst::ElementFactory::make("tee")
                // Protect passthrough enable (and resulting dynamic reconfigure)
                // from non-streaming thread
                .property("allow-not-linked", true)
                .build()?,
            transcription_bin: gst::Bin::new(),
            transcriber_resample: gst::ElementFactory::make("audioresample").build()?,
            transcriber_aconv: gst::ElementFactory::make("audioconvert").build()?,
            transcriber: gst::ElementFactory::make("awstranscriber")
                .name("transcriber")
                .build()
                .ok(),
            queue_passthrough: gst::ElementFactory::make("queue").build()?,
            transcription_channels: HashMap::new(),
            srcpad_name: None,
        })
    }
}

pub struct TranscriberSinkPad {
    state: Mutex<Result<TranscriberSinkPadState, Error>>,
    settings: Mutex<TranscriberSinkPadSettings>,
}

#[glib::object_subclass]
impl ObjectSubclass for TranscriberSinkPad {
    const NAME: &'static str = "GstTranscriberSinkPad";
    type Type = super::TranscriberSinkPad;
    type ParentType = gst::GhostPad;

    fn new() -> Self {
        Self {
            state: Mutex::new(TranscriberSinkPadState::try_new()),
            settings: Mutex::new(TranscriberSinkPadSettings::default()),
        }
    }
}

impl ObjectImpl for TranscriberSinkPad {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecBoxed::builder::<gst::Structure>("translation-languages")
                    .nick("Translation languages")
                    .blurb("A map of language codes to caption channels, e.g. translation-languages=\"languages, transcript={CC1, 708_1}, fr={708_2, CC3}\" will map the French translation to CC1/service 1 and the original transcript to CC3/service 2")
                    .mutable_playing()
                    .build(),
                glib::ParamSpecString::builder("language-code")
                    .nick("Language Code")
                    .blurb("The language of the input stream")
                    .default_value(Some(DEFAULT_INPUT_LANG_CODE))
                    .mutable_playing()
                    .build(),
                glib::ParamSpecEnum::builder_with_default("mode", DEFAULT_MODE)
                    .nick("Mode")
                    .blurb("Which closed caption mode to operate in")
                    .mutable_playing()
                    .build(),
                glib::ParamSpecObject::builder::<gst::Element>("transcriber")
                    .nick("Transcriber")
                    .blurb("The transcriber element to use")
                    .mutable_ready()
                    .build(),
        ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "translation-languages" => {
                let mut settings = self.settings.lock().unwrap();
                settings.translation_languages = value
                    .get::<Option<gst::Structure>>()
                    .expect("type checked upstream");
                gst::debug!(
                    CAT,
                    imp = self,
                    "Updated translation-languages {:?}",
                    settings.translation_languages
                );

                drop(settings);

                if let Some(this) = self.obj().parent().and_downcast::<super::TranscriberBin>() {
                    this.imp().update_languages(&self.obj(), false);
                }
            }
            "mode" => {
                let mut settings = self.settings.lock().unwrap();

                let old_mode = settings.mode;
                let new_mode = value.get().expect("type checked upstream");
                settings.mode = new_mode;

                if old_mode != new_mode {
                    drop(settings);
                    if let Some(this) = self.obj().parent().and_downcast::<super::TranscriberBin>()
                    {
                        if let Some(state) = this.imp().state.lock().unwrap().as_ref() {
                            let ps = self.state.lock().unwrap();
                            let pad_state = ps.as_ref().unwrap();
                            this.imp().setup_cc_mode(
                                &self.obj(),
                                pad_state,
                                state.mux_method,
                                new_mode,
                            );
                        }
                    }
                }
            }
            "language-code" => {
                let mut settings = self.settings.lock().unwrap();

                let old_code = settings.language_code.clone();
                let new_code = value
                    .get::<Option<String>>()
                    .expect("type checked upstream")
                    .unwrap_or_else(|| String::from(DEFAULT_INPUT_LANG_CODE));
                settings.language_code.clone_from(&new_code);
                if let Some(this) = self.obj().parent().and_downcast::<super::TranscriberBin>() {
                    drop(settings);
                    if new_code != old_code {
                        gst::debug!(
                            CAT,
                            imp = self,
                            "Updating language code {old_code} -> {new_code}",
                        );

                        this.imp().update_languages(&self.obj(), true)
                    }
                }
            }
            "transcriber" => {
                let mut ps = self.state.lock().unwrap();
                let Ok(pad_state) = ps.as_mut() else {
                    return;
                };
                let old_transcriber = pad_state.transcriber.clone();
                let new_transcriber: Option<gst::Element> =
                    value.get().expect("type checked upstream");
                pad_state.transcriber.clone_from(&new_transcriber);

                if let Some(this) = self.obj().parent().and_downcast::<super::TranscriberBin>() {
                    let mut s = this.imp().state.lock().unwrap();
                    if old_transcriber != new_transcriber {
                        if let Some(ref mut state) = s.as_mut() {
                            match this.imp().relink_transcriber(
                                state,
                                pad_state,
                                old_transcriber.as_ref(),
                            ) {
                                Ok(()) => (),
                                Err(err) => {
                                    gst::error!(CAT, "invalid transcriber: {err}");
                                    drop(s);
                                    *this.imp().state.lock().unwrap() = None;
                                }
                            }
                        }
                    }
                }
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        match pspec.name() {
            "translation-languages" => {
                let settings = self.settings.lock().unwrap();
                settings.translation_languages.to_value()
            }
            "language-code" => {
                let settings = self.settings.lock().unwrap();
                settings.language_code.to_value()
            }
            "mode" => {
                let settings = self.settings.lock().unwrap();
                settings.mode.to_value()
            }
            "transcriber" => {
                let ps = self.state.lock().unwrap();
                match ps.as_ref() {
                    Ok(ps) => ps.transcriber.to_value(),
                    Err(_) => None::<gst::Element>.to_value(),
                }
            }
            _ => unimplemented!(),
        }
    }
}

impl GstObjectImpl for TranscriberSinkPad {}

impl PadImpl for TranscriberSinkPad {}

impl ProxyPadImpl for TranscriberSinkPad {}

impl GhostPadImpl for TranscriberSinkPad {}

#[derive(Debug, Default)]
pub struct TranscriberSrcPad {}

#[glib::object_subclass]
impl ObjectSubclass for TranscriberSrcPad {
    const NAME: &'static str = "GstTranscriberSrcPad";
    type Type = super::TranscriberSrcPad;
    type ParentType = gst::GhostPad;

    fn new() -> Self {
        Default::default()
    }
}

impl ObjectImpl for TranscriberSrcPad {}

impl GstObjectImpl for TranscriberSrcPad {}

impl PadImpl for TranscriberSrcPad {}

impl ProxyPadImpl for TranscriberSrcPad {}

impl GhostPadImpl for TranscriberSrcPad {}
