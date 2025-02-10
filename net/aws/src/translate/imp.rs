// Copyright (C) 2025 Mathieu Duponchelle <mathieu@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

//! AWS Translate element.
//!
//! This element translates text

use super::CAT;
use crate::s3utils::RUNTIME;
use crate::transcriber::{
    translate::{span_tokenize_items, TranslatedItem},
    TranslationTokenizationMethod,
};
use anyhow::{anyhow, Error};
use aws_sdk_s3::config::StalledStreamProtectionConfig;
use aws_sdk_translate::error::ProvideErrorMetadata;
use futures::future::{abortable, AbortHandle};
use gst::subclass::prelude::*;
use gst::{glib, prelude::*};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::LazyLock;
use std::sync::{mpsc, Mutex};

#[allow(deprecated)]
static AWS_BEHAVIOR_VERSION: LazyLock<aws_config::BehaviorVersion> =
    LazyLock::new(aws_config::BehaviorVersion::v2023_11_09);

const DEFAULT_LATENCY: gst::ClockTime = gst::ClockTime::from_seconds(2);
const DEFAULT_REGION: &str = "us-east-1";
const DEFAULT_INPUT_LANG_CODE: &str = "en-US";
const DEFAULT_OUTPUT_LANG_CODE: &str = "fr-FR";
const DEFAULT_TOKENIZATION_METHOD: TranslationTokenizationMethod =
    TranslationTokenizationMethod::SpanBased;

#[derive(Debug, Clone)]
struct Settings {
    latency: gst::ClockTime,
    input_language_code: String,
    output_language_code: String,
    access_key: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,
    tokenization_method: TranslationTokenizationMethod,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            latency: DEFAULT_LATENCY,
            input_language_code: String::from(DEFAULT_INPUT_LANG_CODE),
            output_language_code: String::from(DEFAULT_OUTPUT_LANG_CODE),
            access_key: None,
            secret_access_key: None,
            session_token: None,
            tokenization_method: DEFAULT_TOKENIZATION_METHOD,
        }
    }
}

#[derive(Debug, Clone)]
struct InputItem {
    content: String,
    pts: gst::ClockTime,
    rtime: gst::ClockTime,
    end_pts: gst::ClockTime,
    is_punctuation: bool,
    discont: bool,
}

#[derive(Debug)]
pub struct InputItems(Vec<InputItem>);

impl InputItems {
    fn start_rtime(&self) -> gst::ClockTime {
        self.0.first().unwrap().rtime
    }

    fn start_pts(&self) -> gst::ClockTime {
        self.0.first().unwrap().pts
    }

    fn discont(&self) -> bool {
        self.0.first().unwrap().discont
    }

    fn end_pts(&self) -> gst::ClockTime {
        self.0.last().unwrap().end_pts
    }
}

enum TranslateInput {
    Items(InputItems),
    Gap {
        pts: gst::ClockTime,
        duration: Option<gst::ClockTime>,
    },
    Event(gst::Event),
}

enum TranslateOutput {
    Item(gst::Buffer),
}

struct State {
    // (live, min, max)
    upstream_latency: Option<(bool, gst::ClockTime, Option<gst::ClockTime>)>,
    segment: Option<gst::FormattedSegment<gst::ClockTime>>,
    accumulator: Option<InputItems>,
    client: Option<aws_sdk_translate::Client>,
    send_abort_handle: Option<AbortHandle>,
    translate_tx: Option<mpsc::Sender<TranslateInput>>,
    discont: bool,
    seqnum: gst::Seqnum,
    chained_one: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            upstream_latency: None,
            segment: None,
            accumulator: None,
            client: None,
            send_abort_handle: None,
            translate_tx: None,
            discont: false,
            seqnum: gst::Seqnum::next(),
            chained_one: false,
        }
    }
}

pub struct Translate {
    srcpad: gst::Pad,
    sinkpad: gst::Pad,
    settings: Mutex<Settings>,
    state: Mutex<State>,
    aws_config: Mutex<Option<aws_config::SdkConfig>>,
}

const SPAN_START: &str = "<span>";
const SPAN_END: &str = "</span>";

impl Translate {
    fn upstream_latency(&self) -> Option<(bool, gst::ClockTime, Option<gst::ClockTime>)> {
        if let Some(latency) = self.state.lock().unwrap().upstream_latency {
            return Some(latency);
        }

        let mut peer_query = gst::query::Latency::new();

        let ret = self.sinkpad.peer_query(&mut peer_query);

        if ret {
            let upstream_latency = peer_query.result();
            gst::info!(
                CAT,
                imp = self,
                "queried upstream latency: {upstream_latency:?}"
            );

            self.state.lock().unwrap().upstream_latency = Some(upstream_latency);

            Some(upstream_latency)
        } else {
            gst::trace!(CAT, imp = self, "could not query upstream latency");

            None
        }
    }

    fn sink_event(&self, pad: &gst::Pad, event: gst::Event) -> bool {
        gst::trace!(CAT, obj = pad, "Handling event {event:?}");

        use gst::EventView::*;
        match event.view() {
            FlushStart(_) => {
                gst::info!(CAT, imp = self, "received flush start, disconnecting");
                let ret = gst::Pad::event_default(pad, Some(&*self.obj()), event);
                let _ = self.state.lock().unwrap().translate_tx.take();
                let _ = self.srcpad.pause_task();
                self.disconnect();
                ret
            }
            StreamStart(_) => {
                if let Err(err) = self.start_srcpad_task() {
                    gst::error!(CAT, imp = self, "Failed to start srcpad task: {err}");
                    return false;
                }

                self.state.lock().unwrap().seqnum = event.seqnum();

                gst::debug!(
                    CAT,
                    imp = self,
                    "stored stream start seqnum {:?}",
                    event.seqnum()
                );

                gst::Pad::event_default(pad, Some(&*self.obj()), event)
            }
            Segment(e) => {
                {
                    let mut state = self.state.lock().unwrap();

                    if state.segment.is_some() && state.chained_one {
                        gst::element_imp_error!(
                            self,
                            gst::StreamError::Format,
                            ["Multiple segments not supported"]
                        );
                        return false;
                    }

                    let segment = match e.segment().clone().downcast::<gst::ClockTime>() {
                        Err(segment) => {
                            gst::element_imp_error!(
                                self,
                                gst::StreamError::Format,
                                ["Only Time segments supported, got {:?}", segment.format(),]
                            );
                            return false;
                        }
                        Ok(segment) => segment,
                    };

                    state.segment = Some(segment);

                    gst::debug!(CAT, imp = self, "stored segment {:?}", state.segment);
                }

                gst::Pad::event_default(pad, Some(&*self.obj()), event)
            }
            Caps(_) => {
                let caps = gst::Caps::builder("text/x-raw")
                    .field("format", "utf8")
                    .build();

                let event = gst::event::Caps::builder(&caps)
                    .seqnum(self.state.lock().unwrap().seqnum)
                    .build();

                self.srcpad.push_event(event)
            }
            Gap(gap) => {
                let state = self.state.lock().unwrap();

                let (pts, duration) = gap.get();

                if state.accumulator.is_none() {
                    if let Some(translate_tx) = state.translate_tx.as_ref() {
                        let _ = translate_tx.send(TranslateInput::Gap { pts, duration });
                    }
                }

                true
            }
            Eos(_) => {
                let translate_tx = self.state.lock().unwrap().translate_tx.take();
                if let Some(translate_tx) = translate_tx {
                    gst::debug!(CAT, imp = self, "received EOS, draining");

                    let _ = translate_tx.send(TranslateInput::Items(self.drain(false)));
                }

                true
            }
            CustomDownstream(c) => {
                let Some(s) = c.structure() else {
                    return gst::Pad::event_default(pad, Some(&*self.obj()), event);
                };

                let drain = match s.name().as_str() {
                    "rstranscribe/final-transcript" => {
                        gst::debug!(CAT, imp = self, "transcript is final, draining");
                        true
                    }
                    "rstranscribe/speaker-change" => {
                        gst::debug!(CAT, imp = self, "speaker change, draining");
                        true
                    }
                    _ => false,
                };

                if drain {
                    let items = self.drain(false);

                    if let Some(translate_tx) = self.state.lock().unwrap().translate_tx.as_ref() {
                        let _ = translate_tx.send(TranslateInput::Items(items));
                        let _ = translate_tx.send(TranslateInput::Event(event));
                    }

                    true
                } else {
                    gst::Pad::event_default(pad, Some(&*self.obj()), event)
                }
            }
            _ => gst::Pad::event_default(pad, Some(&*self.obj()), event),
        }
    }

    fn maybe_send(&self) -> Result<gst::FlowSuccess, gst::FlowError> {
        let Some(now) = self.obj().current_running_time() else {
            gst::trace!(
                CAT,
                imp = self,
                "no current running time, we cannot be late"
            );
            return Ok(gst::FlowSuccess::Ok);
        };

        let Some(upstream_latency) = self.upstream_latency() else {
            gst::trace!(CAT, imp = self, "no upstream latency, we cannot be late");
            return Ok(gst::FlowSuccess::Ok);
        };

        let (upstream_live, upstream_min, _) = upstream_latency;

        if !upstream_live {
            gst::trace!(CAT, imp = self, "upstream isn't live, we are not late");
            return Ok(gst::FlowSuccess::Ok);
        }

        loop {
            let start_rtime = self
                .state
                .lock()
                .unwrap()
                .accumulator
                .as_ref()
                .map(|accumulator| accumulator.start_rtime());

            if let Some(start_rtime) = start_rtime {
                if start_rtime + upstream_min < now {
                    gst::debug!(
                        CAT,
                        imp = self,
                        "draining on timeout: {start_rtime} + {upstream_min} < {now}",
                    );
                    self.do_send(self.drain(true))?;
                } else {
                    gst::trace!(
                        CAT,
                        imp = self,
                        "queued content is not late: {start_rtime} + {upstream_min} >= {now}"
                    );
                    return Ok(gst::FlowSuccess::Ok);
                }
            } else {
                gst::trace!(CAT, imp = self, "no queued content, cannot be late");
                return Ok(gst::FlowSuccess::Ok);
            }
        }
    }

    fn do_send(&self, to_translate: InputItems) -> Result<gst::FlowSuccess, gst::FlowError> {
        if to_translate.0.is_empty() {
            gst::trace!(CAT, imp = self, "nothing to send, returning early");
            return Ok(gst::FlowSuccess::Ok);
        }

        let (future, abort_handle) = abortable(self.send(to_translate));

        self.state.lock().unwrap().send_abort_handle = Some(abort_handle);

        match RUNTIME.block_on(future) {
            Err(_) => {
                gst::debug!(CAT, imp = self, "send aborted, returning flushing");
                Err(gst::FlowError::Flushing)
            }
            Ok(res) => match res {
                Err(e) => {
                    gst::element_imp_error!(
                        self,
                        gst::StreamError::Failed,
                        ["Failed sending data: {}", e]
                    );
                    Err(gst::FlowError::Error)
                }
                Ok(mut output) => {
                    for item in output.drain(..) {
                        match item {
                            TranslateOutput::Item(buffer) => {
                                gst::debug!(CAT, imp = self, "pushing {buffer:?}");
                                self.srcpad.push(buffer)?;
                            }
                        }
                    }

                    Ok(gst::FlowSuccess::Ok)
                }
            },
        }
    }

    fn drain(&self, up_to_punctuation: bool) -> InputItems {
        let mut state = self.state.lock().unwrap();

        let Some(accumulator) = state.accumulator.take() else {
            gst::trace!(CAT, imp = self, "accumulator is empty");
            return InputItems(vec![]);
        };

        let items = match up_to_punctuation {
            true => {
                if let Some(punctuation_index) =
                    accumulator.0.iter().rposition(|item| item.is_punctuation)
                {
                    let (items, trailing) = accumulator.0.split_at(punctuation_index + 1);

                    if !trailing.is_empty() {
                        state.accumulator = Some(InputItems(trailing.to_vec()));
                    }

                    gst::log!(CAT, imp = self, "drained up to punctuation: {items:?}");

                    InputItems(items.to_vec())
                } else {
                    gst::log!(CAT, imp = self, "drained all items: {accumulator:?}");
                    accumulator
                }
            }
            false => {
                gst::log!(CAT, imp = self, "drained all items: {accumulator:?}");

                accumulator
            }
        };

        items
    }

    async fn send(&self, to_translate: InputItems) -> Result<Vec<TranslateOutput>, Error> {
        let (input_lang, output_lang, latency, tokenization_method) = {
            let settings = self.settings.lock().unwrap();
            (
                settings.input_language_code.clone(),
                settings.output_language_code.clone(),
                settings.latency,
                settings.tokenization_method,
            )
        };

        let (client, segment) = {
            let mut state = self.state.lock().unwrap();

            state
                .segment
                .as_mut()
                .unwrap()
                .set_position(Some(to_translate.end_pts()));

            (
                state.client.as_ref().unwrap().clone(),
                state.segment.as_ref().unwrap().clone(),
            )
        };

        let mut output = vec![];

        gst::log!(
            CAT,
            imp = self,
            "translating sentence {}",
            to_translate
                .0
                .iter()
                .map(|i| i.content.clone())
                .collect::<Vec<_>>()
                .join(" ")
        );

        let mut ts_duration_list: Vec<(gst::ClockTime, gst::ClockTime)> = vec![];
        let mut content: Vec<String> = vec![];
        let mut it = to_translate.0.iter().peekable();

        while let Some(item) = it.next() {
            let suffix = match it.peek() {
                Some(next_item) => {
                    if next_item.is_punctuation {
                        ""
                    } else {
                        " "
                    }
                }
                None => "",
            };
            ts_duration_list.push((item.pts, item.end_pts - item.pts));
            content.push(match tokenization_method {
                TranslationTokenizationMethod::None => format!("{}{}", item.content, suffix),
                TranslationTokenizationMethod::SpanBased => {
                    format!("{SPAN_START}{}{SPAN_END}{}", item.content, suffix)
                }
            });
        }

        let content: String = content.join("");

        gst::log!(
            CAT,
            imp = self,
            "translating {content} with duration list: {ts_duration_list:?}"
        );

        let translated_text = client
            .translate_text()
            .set_source_language_code(Some(input_lang))
            .set_target_language_code(Some(output_lang.clone()))
            .set_text(Some(content))
            .send()
            .await
            .map_err(|err| anyhow!("{}: {}", err, err.meta()))?
            .translated_text;

        gst::log!(CAT, imp = self, "translation received: {translated_text}");

        let s = gst::Structure::builder("awstranslate/raw")
            .field("translation", &translated_text)
            .field("arrival-time", self.obj().current_running_time())
            .field("start-time", to_translate.start_pts())
            .field("language-code", &output_lang)
            .build();

        let _ = self
            .obj()
            .post_message(gst::message::Element::builder(s).src(&*self.obj()).build());

        let upstream_latency = self.upstream_latency();

        let mut translated_items = match tokenization_method {
            TranslationTokenizationMethod::None => {
                // Push translation as a single item
                let mut ts_duration_iter = ts_duration_list.into_iter().peekable();

                let &(first_pts, _) = ts_duration_iter.peek().expect("at least one item");
                let (last_pts, last_duration) = ts_duration_iter.last().expect("at least one item");

                gst::trace!(
                    CAT,
                    imp = self,
                    "not performing tokenization, pushing single item"
                );

                vec![TranslatedItem {
                    pts: first_pts,
                    duration: last_pts.saturating_sub(first_pts) + last_duration,
                    content: translated_text.clone(),
                }]
            }
            TranslationTokenizationMethod::SpanBased => {
                gst::trace!(CAT, imp = self, "tokenizing from spans");

                span_tokenize_items(&translated_text, ts_duration_list)
            }
        };

        gst::log!(CAT, imp = self, "translated items: {translated_items:?}");

        for mut item in translated_items.drain(..) {
            if let Some((upstream_live, upstream_min, _)) = upstream_latency {
                if upstream_live {
                    if let Some(now) = self.obj().current_running_time() {
                        let start_rtime = segment.to_running_time(item.pts).unwrap();
                        let deadline = start_rtime + upstream_min + latency;

                        if deadline < now {
                            let adjusted_pts = item.pts + now - deadline;
                            gst::warning!(
                                CAT,
                                imp = self,
                                "text translated too late, adjusting timestamp {} -> {adjusted_pts}", item.pts,
                            );
                            item.pts = adjusted_pts;
                        }
                    }
                }
            }

            let mut buf = gst::Buffer::from_mut_slice(item.content.into_bytes());
            {
                let buf_mut = buf.get_mut().unwrap();
                buf_mut.set_pts(item.pts);
                buf_mut.set_duration(item.duration);

                if to_translate.discont() {
                    gst::trace!(CAT, imp = self, "marking buffer discont");
                    buf_mut.set_flags(gst::BufferFlags::DISCONT);
                }
            }

            output.push(TranslateOutput::Item(buf));
        }

        Ok(output)
    }

    fn ensure_connection(&self) -> Result<(), gst::ErrorMessage> {
        let mut state = self.state.lock().unwrap();
        if state.client.is_none() {
            state.client = Some(aws_sdk_translate::Client::new(
                self.aws_config.lock().unwrap().as_ref().expect("prepared"),
            ));
        }
        Ok(())
    }

    fn start_srcpad_task(&self) -> Result<(), gst::LoggableError> {
        gst::debug!(CAT, imp = self, "starting source pad task");

        self.ensure_connection()
            .map_err(|err| gst::loggable_error!(CAT, "Failed to start pad task: {err}"))?;

        let (translate_tx, translate_rx) = mpsc::channel();

        self.state.lock().unwrap().translate_tx = Some(translate_tx);

        let this_weak = self.downgrade();
        let res = self.srcpad.start_task(move || loop {
            let Some(this) = this_weak.upgrade() else {
                break;
            };

            let timeout = match this.upstream_latency() {
                Some((true, _min, _max)) => std::time::Duration::from_millis(100),
                _ => std::time::Duration::MAX,
            };

            gst::trace!(CAT, imp = this, "now waiting with timeout {timeout:?}");

            match translate_rx.recv_timeout(timeout) {
                Ok(input) => {
                    gst::trace!(CAT, imp = this, "received input on translate queue");

                    match input {
                        TranslateInput::Items(to_translate) => {
                            if let Err(err) = this.do_send(to_translate) {
                                if err != gst::FlowError::Flushing {
                                    gst::element_error!(
                                        this.obj(),
                                        gst::StreamError::Failed,
                                        ["Streaming failed: {}", err]
                                    );
                                }
                                let _ = this.srcpad.pause_task();
                            }
                        }
                        TranslateInput::Gap { pts, duration } => {
                            let event = gst::event::Gap::builder(pts)
                                .duration(duration)
                                .seqnum(this.state.lock().unwrap().seqnum)
                                .build();

                            let _ = this.srcpad.push_event(event);
                        }
                        TranslateInput::Event(event) => {
                            gst::debug!(CAT, imp = this, "Forwarding event {event:?}");
                            let _ = this.srcpad.push_event(event);
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    gst::trace!(
                        CAT,
                        imp = this,
                        "timed out waiting for input on translate queue"
                    );

                    if let Err(err) = this.maybe_send() {
                        if err != gst::FlowError::Flushing {
                            gst::element_error!(
                                this.obj(),
                                gst::StreamError::Failed,
                                ["Streaming failed: {}", err]
                            );
                        }
                        let _ = this.srcpad.pause_task();
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    gst::log!(CAT, imp = this, "translate queue disconnected, pushing EOS");

                    let event = gst::event::Eos::builder()
                        .seqnum(this.state.lock().unwrap().seqnum)
                        .build();
                    let _ = this.srcpad.push_event(event);
                    let _ = this.srcpad.pause_task();
                    break;
                }
            }
        });

        if res.is_err() {
            return Err(gst::loggable_error!(CAT, "Failed to start pad task"));
        }

        gst::debug!(CAT, imp = self, "started source pad task");

        Ok(())
    }

    fn disconnect(&self) {
        let mut state = self.state.lock().unwrap();

        if let Some(abort_handle) = state.send_abort_handle.take() {
            gst::info!(CAT, imp = self, "aborting translation sending");
            abort_handle.abort();
        }

        *state = State::default();
    }

    fn sink_chain(
        &self,
        pad: &gst::Pad,
        buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let data = buffer.map_readable().map_err(|_| {
            gst::error!(CAT, obj = pad, "Can't map buffer readable");

            gst::FlowError::Error
        })?;

        let data = String::from_utf8(data.to_vec()).map_err(|err| {
            gst::error!(CAT, obj = pad, "Can't decode utf8: {}", err);

            gst::FlowError::Error
        })?;

        let drained_items = if buffer.flags().contains(gst::BufferFlags::DISCONT) {
            let items = self.drain(false);

            gst::log!(CAT, imp = self, "draining on discont");

            Some(items)
        } else {
            None
        };

        {
            let mut state = self.state.lock().unwrap();

            if let Some(items) = drained_items {
                if let Some(translate_tx) = state.translate_tx.as_ref() {
                    let _ = translate_tx.send(TranslateInput::Items(items));
                }

                state.discont = true;
            }

            let Some(segment) = state.segment.as_ref() else {
                gst::warning!(CAT, imp = self, "dropping buffer before segment");
                return Ok(gst::FlowSuccess::Ok);
            };

            let Some(pts) = buffer.pts() else {
                gst::warning!(CAT, imp = self, "dropping first buffer without a PTS");
                return Ok(gst::FlowSuccess::Ok);
            };

            let end_pts = match buffer.duration() {
                Some(duration) => duration + pts,
                _ => pts,
            };

            let Some(rtime) = segment.to_running_time(pts) else {
                gst::log!(CAT, imp = self, "clipping buffer outside segment");
                return Ok(gst::FlowSuccess::Ok);
            };

            let is_punctuation = data.chars().all(|c| c.is_ascii_punctuation());

            let discont = state.discont;
            state.discont = false;

            let item = InputItem {
                content: data,
                pts,
                rtime,
                end_pts,
                is_punctuation,
                discont,
            };

            if let Some(accumulator) = state.accumulator.as_mut() {
                gst::log!(CAT, imp = self, "queuing item on accumulator: {item:?}");
                accumulator.0.push(item);
            } else {
                gst::log!(
                    CAT,
                    imp = self,
                    "creating new accumulator with item: {item:?}"
                );
                state.accumulator = Some(InputItems(vec![item]));
            }

            state.chained_one = true;

            gst::trace!(
                CAT,
                imp = self,
                "accumulator is now {:#?}",
                state.accumulator
            );

            Ok(gst::FlowSuccess::Ok)
        }
    }

    fn prepare(&self) -> Result<(), gst::ErrorMessage> {
        gst::debug!(CAT, imp = self, "Preparing");

        let (access_key, secret_access_key, session_token) = {
            let settings = self.settings.lock().unwrap();
            (
                settings.access_key.clone(),
                settings.secret_access_key.clone(),
                settings.session_token.clone(),
            )
        };

        gst::log!(CAT, imp = self, "Loading aws config...");
        let _enter_guard = RUNTIME.enter();

        let config_loader = match (access_key, secret_access_key) {
            (Some(key), Some(secret_key)) => {
                gst::log!(CAT, imp = self, "Using settings credentials");
                aws_config::defaults(*AWS_BEHAVIOR_VERSION).credentials_provider(
                    aws_sdk_translate::config::Credentials::new(
                        key,
                        secret_key,
                        session_token,
                        None,
                        "translate",
                    ),
                )
            }
            _ => {
                gst::log!(CAT, imp = self, "Attempting to get credentials from env...");
                aws_config::defaults(*AWS_BEHAVIOR_VERSION)
            }
        };

        let config_loader = config_loader.region(
            aws_config::meta::region::RegionProviderChain::default_provider()
                .or_else(DEFAULT_REGION),
        );

        let config_loader =
            config_loader.stalled_stream_protection(StalledStreamProtectionConfig::disabled());

        let config = futures::executor::block_on(config_loader.load());
        gst::log!(CAT, imp = self, "Using region {}", config.region().unwrap());

        *self.aws_config.lock().unwrap() = Some(config);

        gst::debug!(CAT, imp = self, "Prepared");

        Ok(())
    }

    fn src_query(&self, pad: &gst::Pad, query: &mut gst::QueryRef) -> bool {
        gst::trace!(CAT, obj = pad, "Handling query {:?}", query);

        match query.view_mut() {
            gst::QueryViewMut::Latency(ref mut q) => {
                self.state.lock().unwrap().upstream_latency = None;

                if let Some(upstream_latency) = self.upstream_latency() {
                    let (live, min, max) = upstream_latency;
                    let our_latency = self.settings.lock().unwrap().latency;

                    if live {
                        q.set(true, min + our_latency, max.map(|max| max + our_latency));
                    } else {
                        q.set(live, min, max);
                    }
                    true
                } else {
                    false
                }
            }
            _ => gst::Pad::query_default(pad, Some(&*self.obj()), query),
        }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for Translate {
    const NAME: &'static str = "GstAwsTranslate";
    type Type = super::Translate;
    type ParentType = gst::Element;

    fn with_class(klass: &Self::Class) -> Self {
        let templ = klass.pad_template("sink").unwrap();
        let sinkpad = gst::Pad::builder_from_template(&templ)
            .chain_function(|pad, parent, buffer| {
                Translate::catch_panic_pad_function(
                    parent,
                    || Err(gst::FlowError::Error),
                    |translate| translate.sink_chain(pad, buffer),
                )
            })
            .event_function(|pad, parent, event| {
                Translate::catch_panic_pad_function(
                    parent,
                    || false,
                    |translate| translate.sink_event(pad, event),
                )
            })
            .build();

        let templ = klass.pad_template("src").unwrap();
        let srcpad = gst::PadBuilder::<gst::Pad>::from_template(&templ)
            .query_function(|pad, parent, query| {
                Translate::catch_panic_pad_function(
                    parent,
                    || false,
                    |translate| translate.src_query(pad, query),
                )
            })
            .flags(gst::PadFlags::FIXED_CAPS)
            .build();

        Self {
            srcpad,
            sinkpad,
            settings: Default::default(),
            state: Default::default(),
            aws_config: Mutex::new(None),
        }
    }
}

impl ObjectImpl for Translate {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: LazyLock<Vec<glib::ParamSpec>> = LazyLock::new(|| {
            vec![
                glib::ParamSpecUInt::builder("latency")
                    .nick("Latency")
                    .blurb("Amount of milliseconds to allow AWS Polly")
                    .default_value(DEFAULT_LATENCY.mseconds() as u32)
                    .mutable_ready()
                    .deprecated()
                    .build(),
                glib::ParamSpecString::builder("access-key")
                    .nick("Access Key")
                    .blurb("AWS Access Key")
                    .mutable_ready()
                    .build(),
                glib::ParamSpecString::builder("secret-access-key")
                    .nick("Secret Access Key")
                    .blurb("AWS Secret Access Key")
                    .mutable_ready()
                    .build(),
                glib::ParamSpecString::builder("session-token")
                    .nick("Session Token")
                    .blurb("AWS temporary Session Token from STS")
                    .mutable_ready()
                    .build(),
                glib::ParamSpecString::builder("input-language-code")
                    .nick("Input Language Code")
                    .blurb("The Language of the input stream")
                    .default_value(Some(DEFAULT_INPUT_LANG_CODE))
                    .mutable_ready()
                    .build(),
                glib::ParamSpecString::builder("output-language-code")
                    .nick("Input Language Code")
                    .blurb("The Language of the output stream")
                    .default_value(Some(DEFAULT_INPUT_LANG_CODE))
                    .mutable_ready()
                    .build(),
                glib::ParamSpecEnum::builder("tokenization-method")
                    .nick("Translations tokenization method")
                    .blurb("The tokenization method to apply")
                    .default_value(DEFAULT_TOKENIZATION_METHOD)
                    .mutable_ready()
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
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "latency" => {
                let mut settings = self.settings.lock().unwrap();
                settings.latency = gst::ClockTime::from_mseconds(
                    value.get::<u32>().expect("type checked upstream").into(),
                );
            }
            "access-key" => {
                let mut settings = self.settings.lock().unwrap();
                settings.access_key = value.get().expect("type checked upstream");
            }
            "secret-access-key" => {
                let mut settings = self.settings.lock().unwrap();
                settings.secret_access_key = value.get().expect("type checked upstream");
            }
            "session-token" => {
                let mut settings = self.settings.lock().unwrap();
                settings.session_token = value.get().expect("type checked upstream");
            }
            "input-language-code" => {
                let language_code: String = value.get().expect("type checked upstream");
                let mut settings = self.settings.lock().unwrap();
                settings.input_language_code = language_code;
            }
            "output-language-code" => {
                let language_code: String = value.get().expect("type checked upstream");
                let mut settings = self.settings.lock().unwrap();
                settings.output_language_code = language_code;
            }
            "tokenization-method" => {
                self.settings.lock().unwrap().tokenization_method = value.get().unwrap()
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
            "access-key" => {
                let settings = self.settings.lock().unwrap();
                settings.access_key.to_value()
            }
            "secret-access-key" => {
                let settings = self.settings.lock().unwrap();
                settings.secret_access_key.to_value()
            }
            "session-token" => {
                let settings = self.settings.lock().unwrap();
                settings.session_token.to_value()
            }
            "input-language-code" => {
                let settings = self.settings.lock().unwrap();
                settings.input_language_code.to_value()
            }
            "output-language-code" => {
                let settings = self.settings.lock().unwrap();
                settings.output_language_code.to_value()
            }
            "tokenization-method" => self.settings.lock().unwrap().tokenization_method.to_value(),
            _ => unimplemented!(),
        }
    }
}

impl GstObjectImpl for Translate {}

impl ElementImpl for Translate {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: LazyLock<gst::subclass::ElementMetadata> = LazyLock::new(|| {
            gst::subclass::ElementMetadata::new(
                "Aws Translator",
                "Text/Filter",
                "Translates text",
                "Mathieu Duponchelle <mathieu@centricular.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: LazyLock<Vec<gst::PadTemplate>> = LazyLock::new(|| {
            let sink_caps = gst::Caps::builder("text/x-raw")
                .field("format", "utf8")
                .build();
            let sink_pad_template = gst::PadTemplate::new(
                "sink",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &sink_caps,
            )
            .unwrap();

            let src_caps = gst::Caps::builder("text/x-raw")
                .field("format", "utf8")
                .build();
            let src_pad_template = gst::PadTemplate::new(
                "src",
                gst::PadDirection::Src,
                gst::PadPresence::Always,
                &src_caps,
            )
            .unwrap();

            vec![src_pad_template, sink_pad_template]
        });

        PAD_TEMPLATES.as_ref()
    }

    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        gst::info!(CAT, imp = self, "Changing state {transition:?}");

        match transition {
            gst::StateChange::NullToReady => {
                self.prepare().map_err(|err| {
                    self.post_error_message(err);
                    gst::StateChangeError
                })?;
            }
            gst::StateChange::PausedToReady => {
                self.disconnect();
                let _ = self.srcpad.stop_task();
            }
            _ => (),
        }

        self.parent_change_state(transition)
    }

    fn provide_clock(&self) -> Option<gst::Clock> {
        Some(gst::SystemClock::obtain())
    }
}
