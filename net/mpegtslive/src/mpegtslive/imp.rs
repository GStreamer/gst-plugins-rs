// Copyright (C) 2024 Edward Hervey <edward@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

/**
 * SECTION:element-mpegtslivesrc
 * @see_also: udpsrc, srtsrtc, tsdemux
 *
 * Clock provider from live MPEG-TS sources.
 *
 * This element allows wrapping an existing live "mpeg-ts source" (udpsrc,
 * srtsrc,...) and providing a clock based on the actual PCR of the stream.
 *
 * Combined with tsdemux ignore-pcr=True downstream of it, this allows playing
 * back the content at the same rate as the (remote) provider and not modify the
 * original timestamps.
 *
 * Since: plugins-rs-0.13.0
 */
use anyhow::{bail, Context, Result};

use bitstream_io::{BigEndian, BitRead, BitReader};

use gst::{glib, prelude::*, subclass::prelude::*};

use std::{
    mem,
    ops::{Add, ControlFlow},
    sync::LazyLock,
    sync::Mutex,
};

use super::parser::*;

static CAT: LazyLock<gst::DebugCategory> = LazyLock::new(|| {
    gst::DebugCategory::new(
        "mpegtslivesrc",
        gst::DebugColorFlags::empty(),
        Some("MPEG-TS Live Source"),
    )
});

#[derive(Clone, Copy, Debug)]
struct MpegTsPcr {
    // Raw PCR value
    value: u64,
    // Number of wraparounds to apply
    wraparound: u64,
}

impl MpegTsPcr {
    // Maximum PCR value
    const MAX: u64 = ((1 << 33) * 300) - 1;
    const RATE: u64 = 27_000_000;

    // Create a new PCR given the 27MHz unit.
    // Can be provided values exceed MAX_PCR and will automatically calculate
    // the number of wraparound involved
    fn new(value: u64) -> MpegTsPcr {
        MpegTsPcr {
            value: value % (Self::MAX + 1),
            wraparound: value / (Self::MAX + 1),
        }
    }

    // Create a new PCR given the 27MHz unit and the latest PCR observed.
    // The wraparound will be based on the provided reference PCR
    //
    // If a discontinuity greater than 15s is detected, no value will be
    // returned
    //
    // Note, this constructor will clamp value to be within MAX_PCR
    fn new_with_reference(
        imp: &MpegTsLiveSource,
        value: u64,
        reference: &MpegTsPcr,
    ) -> Option<MpegTsPcr> {
        // Clamp our value to maximum
        let value = value % (Self::MAX + 1);
        let ref_value = reference.value;

        // Fast path, within 15s
        if value.abs_diff(ref_value) <= (15 * Self::RATE) {
            return Some(MpegTsPcr {
                value,
                wraparound: reference.wraparound,
            });
        };

        // new value wrapped around
        if (value + Self::MAX + 1).abs_diff(ref_value) <= 15 * Self::RATE {
            gst::debug!(
                CAT,
                imp = imp,
                "Wraparound detected %{value} vs %{ref_value}"
            );
            return Some(MpegTsPcr {
                value,
                wraparound: reference.wraparound + 1,
            });
        };

        // new value went below 0
        if value.abs_diff(ref_value + Self::MAX + 1) <= 15 * Self::RATE {
            gst::debug!(
                CAT,
                imp = imp,
                "Backward PCR within tolerance detected %{value} vs %{ref_value}"
            );
            return Some(MpegTsPcr {
                value,
                wraparound: reference.wraparound - 1,
            });
        }

        gst::debug!(CAT, imp = imp, "Discont detected %{value} vs %{ref_value}");
        None
    }

    // Full value with wraparound in 27MHz units
    fn to_units(self) -> u64 {
        self.wraparound * (Self::MAX + 1) + self.value
    }

    fn saturating_sub(self, other: MpegTsPcr) -> MpegTsPcr {
        MpegTsPcr::new(self.to_units().saturating_sub(other.to_units()))
    }
}

impl Add for MpegTsPcr {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        MpegTsPcr::new(self.to_units() + other.to_units())
    }
}

impl From<MpegTsPcr> for gst::ClockTime {
    fn from(value: MpegTsPcr) -> gst::ClockTime {
        gst::ClockTime::from_nseconds(
            value
                .to_units()
                .mul_div_floor(1000, 27)
                .expect("failed to convert"),
        )
    }
}

impl From<gst::ClockTime> for MpegTsPcr {
    fn from(value: gst::ClockTime) -> MpegTsPcr {
        MpegTsPcr::new(
            value
                .nseconds()
                .mul_div_floor(27, 1000)
                .expect("Failed to convert"),
        )
    }
}

#[derive(Default)]
struct State {
    // Controlled source element
    source: Option<gst::Element>,

    // Last observed PCR (for handling wraparound)
    last_seen_pcr: Option<MpegTsPcr>,

    // First observed PCR since discont and associated external clock time
    base_pcr: Option<MpegTsPcr>,
    base_external: Option<gst::ClockTime>,

    // If the next outgoing packet should have the discont flag set
    discont_pending: bool,

    // Section parser for PAT
    pat_parser: SectionParser,
    // Current PAT, first program is the selected one
    pat: Option<ProgramAccessTable>,

    // Section parser for PMT
    pmt_parser: SectionParser,
    // Currently selected PMT
    pmt: Option<ProgramMappingTable>,
}

impl State {
    /// Store PCR / internal (monotonic) clock time observation
    fn store_observation(
        &mut self,
        imp: &MpegTsLiveSource,
        pcr: u64,
        observation_internal: gst::ClockTime,
    ) {
        // If this is the first PCR we observe:
        // * Remember the PCR *and* the associated internal (monotonic) == external (scaled
        //   monotonic) clock value when capture
        // * Store base_pcr = pcr, base_external = observation_internal

        // If we have a PCR we need to store an observation
        // * Subtract the base PCR from that value and add the base external clock value
        //   * observation_external = pcr - base_pcr + base_external
        // * Store (observation_internal, observation_external)

        let new_pcr: MpegTsPcr;

        if let (Some(base_pcr), Some(base_external), Some(last_seen_pcr)) =
            (self.base_pcr, self.base_external, self.last_seen_pcr)
        {
            gst::trace!(
                CAT,
                imp = imp,
                "pcr:{pcr}, observation_internal:{observation_internal}"
            );

            let mut handled_pcr = MpegTsPcr::new_with_reference(imp, pcr, &last_seen_pcr);
            if let Some(new_pcr) = handled_pcr {
                // First check if this is more than 1s off from the current clock calibration and
                // if so consider it a discontinuity too.
                let (cinternal, cexternal, cnum, cdenom) = imp.external_clock.calibration();

                let expected_external = gst::Clock::adjust_with_calibration(
                    observation_internal,
                    cinternal,
                    cexternal,
                    cnum,
                    cdenom,
                );
                let observation_external =
                    gst::ClockTime::from(new_pcr.saturating_sub(base_pcr)) + base_external;
                if expected_external.absdiff(observation_external) >= gst::ClockTime::SECOND {
                    gst::warning!(
                        CAT,
                        imp = imp,
                        "New PCR clock estimation {observation_external} too far from old estimation {expected_external}: {}",
                        observation_external.into_positive() - expected_external,
                    );
                    handled_pcr = None;
                }
            }

            if let Some(handled_pcr) = handled_pcr {
                new_pcr = handled_pcr;
                gst::trace!(
                    CAT,
                    imp = imp,
                    "Adding new observation internal: {} -> external: {}",
                    observation_internal,
                    gst::ClockTime::from(new_pcr.saturating_sub(base_pcr)) + base_external,
                );
                imp.external_clock.add_observation(
                    observation_internal,
                    gst::ClockTime::from(new_pcr.saturating_sub(base_pcr)) + base_external,
                );
            } else {
                let (cinternal, cexternal, cnum, cdenom) = imp.external_clock.calibration();
                let base_external = gst::Clock::adjust_with_calibration(
                    observation_internal,
                    cinternal,
                    cexternal,
                    cnum,
                    cdenom,
                );
                gst::warning!(
                    CAT,
                    imp = imp,
                    "DISCONT detected, Picking new reference times (pcr:{pcr:#?}, observation_internal:{observation_internal}, base_external:{base_external}",
                );
                new_pcr = MpegTsPcr::new(pcr);
                self.base_pcr = Some(new_pcr);
                self.base_external = Some(base_external);
                imp.external_clock
                    .set_calibration(observation_internal, base_external, 1, 1);
                // Hack to flush out observations, we set the window-size to the
                // same value
                imp.external_clock
                    .set_window_size(imp.external_clock.window_size());
                self.discont_pending = true;
            }
        } else {
            gst::debug!(
                CAT,
                imp = imp,
                "Picking initial reference times (pcr:{pcr:#?}, observation_internal:{observation_internal}"
            );
            new_pcr = MpegTsPcr::new(pcr);
            self.base_pcr = Some(new_pcr);
            self.base_external = Some(observation_internal);
            self.discont_pending = true;
        }
        self.last_seen_pcr = Some(new_pcr);
    }

    /// Parses and handles a section
    fn handle_section(
        &mut self,
        imp: &MpegTsLiveSource,
        header: &PacketHeader,
        payload: &[u8],
    ) -> Result<()> {
        // Read PAT or our selected program's PMT
        if header.pid == 0x00_00 {
            self.pat_parser.push(header, payload);

            loop {
                match self.pat_parser.parse() {
                    Ok(Some(Section::ProgramAccessTable {
                        table_header,
                        table_syntax_section,
                        pat,
                    })) => {
                        gst::trace!(
                            CAT,
                            imp = imp,
                            "Parsed PAT: {table_header:?} {table_syntax_section:?} {pat:?}"
                        );

                        if pat.is_empty() {
                            gst::warning!(CAT, imp = imp, "No programs in PAT");
                            continue;
                        } else if pat.len() > 1 {
                            gst::warning!(
                                    CAT,
                                    imp = imp,
                                    "MPEG-TS stream with multiple programs - timing will be wrong for all but first program",
                                );
                        }

                        let selected_pat = &pat[0];
                        if header.pid == 0x00_00 && Some(selected_pat) != self.pat.as_ref() {
                            gst::trace!(
                                CAT,
                                imp = imp,
                                "Selecting program with PID {} and program number {}",
                                selected_pat.program_map_pid,
                                selected_pat.program_num,
                            );
                            self.pat = Some(selected_pat.clone());
                            self.pmt_parser.clear();
                            self.pmt = None;
                            self.last_seen_pcr = None;
                        }
                    }
                    Ok(Some(section)) => {
                        gst::trace!(
                            CAT,
                            imp = imp,
                            "Parsed unhandled section {section:?} on PAT PID"
                        );
                    }
                    Ok(None) => break,
                    Err(err) => {
                        gst::warning!(CAT, imp = imp, "Failed parsing section: {err:?}");
                    }
                }
            }
        } else if self.pat.as_ref().map(|pat| pat.program_map_pid) == Some(header.pid) {
            self.pmt_parser.push(header, payload);

            loop {
                match self.pmt_parser.parse() {
                    Ok(Some(Section::ProgramMappingTable {
                        table_header,
                        table_syntax_section,
                        pmt,
                    })) => {
                        gst::trace!(
                            CAT,
                            imp = imp,
                            "Parsed PMT: {table_header:?} {table_syntax_section:?} {pmt:?}"
                        );

                        if self.pat.as_ref().map(|pat| pat.program_num)
                            == Some(table_syntax_section.table_id_extension)
                            && self.pmt.as_ref() != Some(&pmt)
                        {
                            gst::trace!(CAT, imp = imp, "Selecting PCR PID {}", pmt.pcr_pid);
                            self.pmt = Some(pmt);
                            self.last_seen_pcr = None;
                        }
                    }
                    Ok(Some(section)) => {
                        gst::trace!(
                            CAT,
                            imp = imp,
                            "Parsed unhandled section {section:?} on PMT PID"
                        );
                    }
                    Ok(None) => break,
                    Err(err) => {
                        gst::warning!(CAT, imp = imp, "Failed parsing section: {err:?}");
                    }
                }
            }
        }

        Ok(())
    }

    /// Parses an MPEG-TS packet and updates the internal state
    fn handle_packet(
        &mut self,
        imp: &MpegTsLiveSource,
        slice: &[u8],
        monotonic_time: Option<gst::ClockTime>,
    ) -> Result<()> {
        let mut reader = BitReader::endian(slice, BigEndian);

        let header = reader.parse::<PacketHeader>().context("packet_header")?;

        // Skip corrupted packets
        if header.tei {
            return Ok(());
        }

        // Skip scrambled packets
        if header.tsc != 0 {
            return Ok(());
        }

        // Read adaptation field if present
        if header.afc & 0x2 != 0 {
            let length = reader.read_to::<u8>().context("af_length")? as usize;
            let af = *reader.reader().unwrap();
            if af.len() < length {
                bail!("too short adaptation field");
            }
            let af = &af[..length];
            reader.skip(8 * length as u32).context("af")?;

            // Parse adaption field and update PCR if it's the PID of our selected program
            if self.pmt.as_ref().map(|pmt| pmt.pcr_pid) == Some(header.pid) {
                let mut af_reader = BitReader::endian(af, BigEndian);
                let adaptation_field = af_reader.parse::<AdaptionField>().context("af")?;

                // PCR present
                if let Some(pcr) = adaptation_field.pcr {
                    if let Some(monotonic_time) = monotonic_time {
                        self.store_observation(imp, pcr, monotonic_time);
                    } else {
                        gst::warning!(
                            CAT,
                            imp = imp,
                            "Can't handle PCR without packet capture time"
                        );
                    }
                }
            }
        }

        // Read payload if payload if present
        if header.afc & 0x1 != 0 {
            let new_payload = *reader.reader().unwrap();

            if header.pid == 0x00_00
                || self.pat.as_ref().map(|pat| pat.program_map_pid) == Some(header.pid)
            {
                self.handle_section(imp, &header, new_payload)?;
            }

            // Skip everything else
        }

        Ok(())
    }

    fn handle_buffer(
        &mut self,
        imp: &MpegTsLiveSource,
        buffer: &gst::Buffer,
        monotonic_time: Option<gst::ClockTime>,
    ) -> Result<()> {
        let Ok(map) = buffer.map_readable() else {
            return Ok(());
        };

        // Find sync byte
        let Some(pos) = map.iter().position(|&b| b == 0x47) else {
            bail!("Couldn't find sync byte");
        };

        for chunk in map[pos..].chunks_exact(188) {
            self.handle_packet(imp, chunk, monotonic_time)
                .context("handling buffer")?;
        }
        Ok(())
    }
}

// Struct containing all the element data
pub struct MpegTsLiveSource {
    srcpad: gst::GhostPad,

    // Clock set on source element
    internal_clock: gst::SystemClock,

    // Clock we control and expose
    external_clock: gst::SystemClock,

    state: Mutex<State>,
}

impl MpegTsLiveSource {
    // process a buffer to extract the PCR
    fn chain(
        &self,
        pad: &gst::ProxyPad,
        mut buffer: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let mut state = self.state.lock().unwrap();

        let base_time = self.obj().base_time().expect("No base time on element");
        let mut monotonic_time = None;
        let buffer_timestamp = buffer.dts_or_pts();

        if let Some(pts) = buffer_timestamp {
            monotonic_time = Some(pts + base_time);
        };

        // Parse packets
        if let Err(err) = state.handle_buffer(self, &buffer, monotonic_time) {
            gst::warning!(CAT, imp = self, "Failed handling buffer: {err:?}");
        }

        if mem::take(&mut state.discont_pending) {
            let buffer = buffer.make_mut();
            buffer.set_flags(gst::BufferFlags::DISCONT);
        }

        // Update buffer timestamp if present
        if let Some(pts) = buffer_timestamp {
            let buffer = buffer.make_mut();
            let new_pts = self
                .external_clock
                .adjust_unlocked(pts + base_time)
                .expect("Couldn't adjust {pts}")
                .saturating_sub(base_time);
            gst::debug!(
                CAT,
                imp = self,
                "Updating buffer pts from {pts} to {:?}",
                new_pts
            );
            buffer.set_pts(new_pts);
            buffer.set_dts(new_pts);
        };

        gst::ProxyPad::chain_default(pad, Some(&*self.obj()), buffer)
    }

    fn chain_list(
        &self,
        pad: &gst::ProxyPad,
        mut bufferlist: gst::BufferList,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let mut state = self.state.lock().unwrap();
        let base_time = self.obj().base_time().expect("No base time on element");

        // The last monotonic time
        let mut monotonic_time = None;

        bufferlist.make_mut().foreach_mut(|mut buffer, _idx| {
            let this_buffer_timestamp = buffer.dts_or_pts();

            // Grab latest buffer timestamp, we want to use the "latest" one for
            // our observations. Depending on the use-cases, this might only be
            // present on the first buffer of the list or on all
            if let Some(pts) = this_buffer_timestamp {
                monotonic_time = Some(pts + base_time);
            };

            // Parse packets
            if let Err(err) = state.handle_buffer(self, &buffer, monotonic_time) {
                gst::warning!(CAT, imp = self, "Failed handling buffer: {err:?}");
            }

            if mem::take(&mut state.discont_pending) {
                let buffer = buffer.make_mut();
                buffer.set_flags(gst::BufferFlags::DISCONT);
            }

            // Update buffer timestamp if present
            if let Some(pts) = this_buffer_timestamp {
                let buffer = buffer.make_mut();
                let new_pts = self
                    .external_clock
                    .adjust_unlocked(pts + base_time)
                    .expect("Couldn't adjust {pts}")
                    .saturating_sub(base_time);
                gst::debug!(
                    CAT,
                    imp = self,
                    "Updating buffer pts from {pts} to {:?}",
                    new_pts
                );
                buffer.set_pts(new_pts);
                buffer.set_dts(new_pts);
            };
            ControlFlow::Continue(Some(buffer))
        });

        gst::ProxyPad::chain_list_default(pad, Some(&*self.obj()), bufferlist)
    }
}

#[glib::object_subclass]
impl ObjectSubclass for MpegTsLiveSource {
    const NAME: &'static str = "GstMpegTsLiveSource";
    type Type = super::MpegTsLiveSource;
    type ParentType = gst::Bin;

    fn with_class(klass: &Self::Class) -> Self {
        let templ = klass.pad_template("src").unwrap();
        let srcpad = gst::GhostPad::builder_from_template(&templ)
            .name(templ.name())
            .proxy_pad_chain_function(move |pad, parent, buffer| {
                let parent = parent.and_then(|p| p.parent());
                MpegTsLiveSource::catch_panic_pad_function(
                    parent.as_ref(),
                    || Err(gst::FlowError::Error),
                    |imp| imp.chain(pad, buffer),
                )
            })
            .proxy_pad_chain_list_function(move |pad, parent, bufferlist| {
                let parent = parent.and_then(|p| p.parent());
                MpegTsLiveSource::catch_panic_pad_function(
                    parent.as_ref(),
                    || Err(gst::FlowError::Error),
                    |imp| imp.chain_list(pad, bufferlist),
                )
            })
            .flags(
                gst::PadFlags::PROXY_CAPS
                    | gst::PadFlags::PROXY_ALLOCATION
                    | gst::PadFlags::PROXY_SCHEDULING,
            )
            .build();
        let internal_clock = gst::Object::builder::<gst::SystemClock>()
            .name("mpegts-internal-clock")
            .property("clock-type", gst::ClockType::Monotonic)
            .build()
            .unwrap();
        let external_clock = gst::Object::builder::<gst::SystemClock>()
            .name("mpegts-live-clock")
            .property("clock-type", gst::ClockType::Monotonic)
            .build()
            .unwrap();
        // Return an instance of our struct
        Self {
            srcpad,
            internal_clock,
            external_clock,
            state: Mutex::new(State::default()),
        }
    }
}

impl ObjectImpl for MpegTsLiveSource {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: LazyLock<Vec<glib::ParamSpec>> = LazyLock::new(|| {
            vec![
                glib::ParamSpecObject::builder::<gst::Element>("source")
                    .nick("Source")
                    .blurb("Source element")
                    .mutable_ready()
                    .readwrite()
                    .build(),
                glib::ParamSpecInt::builder("window-size")
                    .nick("Window Size")
                    .blurb("The size of the window used to calculate rate and offset")
                    .minimum(2)
                    .maximum(1024)
                    .default_value(32)
                    .readwrite()
                    .build(),
            ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "source" => {
                let mut state = self.state.lock().unwrap();
                if let Some(existing_source) = state.source.take() {
                    let _ = self.obj().remove(&existing_source);
                    let _ = self.srcpad.set_target(None::<&gst::Pad>);
                }
                if let Some(source) = value
                    .get::<Option<gst::Element>>()
                    .expect("type checked upstream")
                {
                    if self.obj().add(&source).is_err() {
                        gst::warning!(CAT, imp = self, "Failed to add source");
                        return;
                    };
                    if source.set_clock(Some(&self.internal_clock)).is_err() {
                        gst::warning!(CAT, imp = self, "Failed to set clock on source");
                        return;
                    };

                    let Some(target_pad) = source.static_pad("src") else {
                        gst::warning!(CAT, imp = self, "Source element has no 'src' pad");
                        return;
                    };
                    if self.srcpad.set_target(Some(&target_pad)).is_err() {
                        gst::warning!(CAT, imp = self, "Failed to set ghost pad target");
                        return;
                    }
                    state.source = Some(source);
                } else {
                    state.source = None;
                }
            }
            "window-size" => {
                self.external_clock.set_window_size(value.get().unwrap());
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        match pspec.name() {
            "source" => self.state.lock().unwrap().source.to_value(),
            "window-size" => self.external_clock.window_size().to_value(),
            _ => unimplemented!(),
        }
    }

    fn constructed(&self) {
        self.parent_constructed();
        let obj = self.obj();
        obj.set_element_flags(
            gst::ElementFlags::PROVIDE_CLOCK
                | gst::ElementFlags::REQUIRE_CLOCK
                | gst::ElementFlags::SOURCE,
        );
        obj.set_suppressed_flags(
            gst::ElementFlags::SOURCE
                | gst::ElementFlags::SINK
                | gst::ElementFlags::PROVIDE_CLOCK
                | gst::ElementFlags::REQUIRE_CLOCK,
        );
        obj.add_pad(&self.srcpad).unwrap();
    }
}

impl GstObjectImpl for MpegTsLiveSource {}

impl ElementImpl for MpegTsLiveSource {
    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        if transition == gst::StateChange::ReadyToPaused
            && self
                .state
                .lock()
                .expect("Couldn't get state")
                .source
                .is_none()
        {
            gst::error!(CAT, "No source to control");
            return Err(gst::StateChangeError);
        }
        let ret = self.parent_change_state(transition)?;
        if transition == gst::StateChange::ReadyToPaused
            && ret != gst::StateChangeSuccess::NoPreroll
        {
            gst::error!(CAT, "We can only control live sources");
            return Err(gst::StateChangeError);
        } else if transition == gst::StateChange::PausedToReady {
            self.external_clock.set_calibration(
                gst::ClockTime::from_nseconds(0),
                gst::ClockTime::from_nseconds(0),
                1,
                1,
            );
            // Hack to flush out observations, we set the window-size to the
            // same value
            self.external_clock
                .set_window_size(self.external_clock.window_size());

            *self.state.lock().unwrap() = State::default();
        }
        Ok(ret)
    }

    fn set_clock(&self, clock: Option<&gst::Clock>) -> bool {
        // We only accept our clock
        if let Some(proposed) = clock {
            if *proposed != self.external_clock {
                return false;
            }
        }
        true
    }

    fn provide_clock(&self) -> Option<gst::Clock> {
        Some(self.external_clock.clone().upcast())
    }

    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: LazyLock<gst::subclass::ElementMetadata> = LazyLock::new(|| {
            gst::subclass::ElementMetadata::new(
                "MpegTsLiveSource",
                "Network",
                "Wrap MPEG-TS sources and provide a live clock",
                "Edward Hervey <edward@centricular.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: LazyLock<Vec<gst::PadTemplate>> = LazyLock::new(|| {
            let src_pad_template = gst::PadTemplate::new(
                "src",
                gst::PadDirection::Src,
                gst::PadPresence::Always,
                &gst::Caps::new_any(),
            )
            .unwrap();

            vec![src_pad_template]
        });

        PAD_TEMPLATES.as_ref()
    }
}

impl BinImpl for MpegTsLiveSource {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_basic_test() {
        // Smallest value
        let pcr = MpegTsPcr::new(0);
        assert_eq!(pcr.value, 0);
        assert_eq!(pcr.wraparound, 0);

        // Biggest (non-wrapped) value
        let mut pcr = MpegTsPcr::new(MpegTsPcr::MAX);
        assert_eq!(pcr.value, MpegTsPcr::MAX);
        assert_eq!(pcr.wraparound, 0);

        // a 33bit value overflows into 0
        pcr = MpegTsPcr::new((1u64 << 33) * 300);
        assert_eq!(pcr.value, 0);
        assert_eq!(pcr.wraparound, 1);

        // Adding one to biggest value overflows
        pcr = MpegTsPcr::new(MpegTsPcr::MAX + 1);
        assert_eq!(pcr.value, 0);
        assert_eq!(pcr.wraparound, 1);
    }

    #[test]
    fn pcr_wraparound_test() {
        gst::init().unwrap();
        crate::plugin_register_static().expect("mpegtslivesrc test");

        let element = gst::ElementFactory::make("mpegtslivesrc")
            .build()
            .unwrap()
            .downcast::<super::super::MpegTsLiveSource>()
            .unwrap();
        let imp = element.imp();

        // Basic test going forward within 15s
        let ref_pcr = MpegTsPcr {
            value: 360 * MpegTsPcr::RATE,
            wraparound: 100,
        };
        let pcr = MpegTsPcr::new_with_reference(imp, 370 * MpegTsPcr::RATE, &ref_pcr);
        assert!(pcr.is_some());
        if let Some(pcr) = pcr {
            assert_eq!(pcr.value, 370 * MpegTsPcr::RATE);
            assert_eq!(pcr.wraparound, ref_pcr.wraparound);
        };

        // Discont
        let pcr = MpegTsPcr::new_with_reference(imp, 344 * MpegTsPcr::RATE, &ref_pcr);
        assert!(pcr.is_none());

        let pcr = MpegTsPcr::new_with_reference(imp, 386 * MpegTsPcr::RATE, &ref_pcr);
        assert!(pcr.is_none());

        // Wraparound, ref is 10s before MAX
        let ref_pcr = MpegTsPcr {
            value: MpegTsPcr::MAX - 10 * MpegTsPcr::RATE,
            wraparound: 600,
        };
        let pcr = MpegTsPcr::new_with_reference(imp, 0, &ref_pcr);
        assert!(pcr.is_some());
        if let Some(pcr) = pcr {
            assert_eq!(pcr.value, 0);
            assert_eq!(pcr.wraparound, ref_pcr.wraparound + 1);
        };

        // Discont
        let pcr = MpegTsPcr::new_with_reference(imp, 10 * MpegTsPcr::RATE, &ref_pcr);
        assert!(pcr.is_none());

        // reference is 5s after wraparound
        let ref_pcr = MpegTsPcr {
            value: 5 * MpegTsPcr::RATE,
            wraparound: 600,
        };
        // value is 5s before wraparound
        let pcr =
            MpegTsPcr::new_with_reference(imp, MpegTsPcr::MAX + 1 - 5 * MpegTsPcr::RATE, &ref_pcr);
        assert!(pcr.is_some());
        if let Some(pcr) = pcr {
            assert_eq!(pcr.value, MpegTsPcr::MAX + 1 - 5 * MpegTsPcr::RATE);
            assert_eq!(pcr.wraparound, ref_pcr.wraparound - 1);
        }
    }
}
