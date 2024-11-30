// Copyright (C) 2019 Philippe Normand <philn@igalia.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use gst::glib;
use gst::prelude::*;
use gst::subclass::prelude::*;
use gst_video::prelude::*;
use gst_video::subclass::prelude::*;

use std::sync::LazyLock;

use std::sync::{Mutex, MutexGuard};

#[glib::flags(name = "GstDav1dInloopFilterType")]
pub(crate) enum InloopFilterType {
    #[flags_value(name = "Enable deblocking filter", nick = "deblock")]
    DEBLOCK = dav1d::InloopFilterType::DEBLOCK.bits(),
    #[flags_value(
        name = "Enable Constrained Directional Enhancement Filter",
        nick = "cdef"
    )]
    CDEF = dav1d::InloopFilterType::CDEF.bits(),
    #[flags_value(name = "Enable loop restoration filter", nick = "restoration")]
    RESTORATION = dav1d::InloopFilterType::RESTORATION.bits(),
}

impl From<InloopFilterType> for dav1d::InloopFilterType {
    fn from(inloop_filter_type: InloopFilterType) -> Self {
        let mut dav1d_inloop_filter_type = dav1d::InloopFilterType::empty();
        if inloop_filter_type.contains(InloopFilterType::DEBLOCK) {
            dav1d_inloop_filter_type.set(dav1d::InloopFilterType::DEBLOCK, true);
        }
        if inloop_filter_type.contains(InloopFilterType::CDEF) {
            dav1d_inloop_filter_type.set(dav1d::InloopFilterType::CDEF, true);
        }
        if inloop_filter_type.contains(InloopFilterType::RESTORATION) {
            dav1d_inloop_filter_type.set(dav1d::InloopFilterType::RESTORATION, true);
        }

        dav1d_inloop_filter_type
    }
}

const DEFAULT_N_THREADS: u32 = 0;
const DEFAULT_MAX_FRAME_DELAY: i64 = -1;
const DEFAULT_APPLY_GRAIN: bool = false;
const DEFAULT_INLOOP_FILTERS: InloopFilterType = InloopFilterType::empty();

struct State {
    decoder: dav1d::Decoder,
    input_state: gst_video::VideoCodecState<'static, gst_video::video_codec_state::Readable>,
    output_info: Option<gst_video::VideoInfo>,
    video_meta_supported: bool,
    n_cpus: usize,
}

// We make our own settings object so we don't have to deal with a Sync impl for dav1d::Settings
struct Settings {
    n_threads: u32,
    max_frame_delay: i64,
    apply_grain: bool,
    inloop_filters: InloopFilterType,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            n_threads: DEFAULT_N_THREADS,
            max_frame_delay: DEFAULT_MAX_FRAME_DELAY,
            apply_grain: DEFAULT_APPLY_GRAIN,
            inloop_filters: DEFAULT_INLOOP_FILTERS,
        }
    }
}

#[derive(Default)]
pub struct Dav1dDec {
    state: Mutex<Option<State>>,
    settings: Mutex<Settings>,
}

static CAT: LazyLock<gst::DebugCategory> = LazyLock::new(|| {
    gst::DebugCategory::new(
        "dav1ddec",
        gst::DebugColorFlags::empty(),
        Some("Dav1d AV1 decoder"),
    )
});

impl Dav1dDec {
    // FIXME: drop this once we have API from dav1d to query this value
    // https://code.videolan.org/videolan/dav1d/-/merge_requests/1407
    fn estimate_frame_delay(&self, max_frame_delay: u32, n_threads: u32) -> u32 {
        if max_frame_delay > 0 {
            std::cmp::min(max_frame_delay, n_threads)
        } else {
            let n_tc = n_threads as f64;
            std::cmp::min(8, n_tc.sqrt().ceil() as u32)
        }
    }

    fn gst_video_format_from_dav1d_picture(&self, pic: &dav1d::Picture) -> gst_video::VideoFormat {
        let bpc = pic.bits_per_component();
        let format_desc = match (pic.pixel_layout(), bpc) {
            (dav1d::PixelLayout::I400, Some(dav1d::BitsPerComponent(8))) => "GRAY8",
            #[cfg(target_endian = "little")]
            (dav1d::PixelLayout::I400, Some(dav1d::BitsPerComponent(16))) => "GRAY16_LE",
            #[cfg(target_endian = "big")]
            (dav1d::PixelLayout::I400, Some(dav1d::BitsPerComponent(16))) => "GRAY16_BE",
            // (dav1d::PixelLayout::I400, Some(dav1d::BitsPerComponent(10))) => "GRAY10_LE32",
            (dav1d::PixelLayout::I420, _) => "I420",
            (dav1d::PixelLayout::I422, Some(dav1d::BitsPerComponent(8))) => "Y42B",
            (dav1d::PixelLayout::I422, _) => "I422",
            (dav1d::PixelLayout::I444, _) => "Y444",
            (layout, bpc) => {
                gst::warning!(
                    CAT,
                    imp = self,
                    "Unsupported dav1d format {:?}/{:?}",
                    layout,
                    bpc
                );
                return gst_video::VideoFormat::Unknown;
            }
        };

        let f = if format_desc.starts_with("GRAY") {
            format_desc.into()
        } else {
            match bpc {
                Some(b) => match b.0 {
                    8 => format_desc.into(),
                    _ => {
                        let endianness = if cfg!(target_endian = "little") {
                            "LE"
                        } else {
                            "BE"
                        };
                        format!("{f}_{b}{e}", f = format_desc, b = b.0, e = endianness)
                    }
                },
                None => format_desc.into(),
            }
        };
        f.parse::<gst_video::VideoFormat>().unwrap_or_else(|_| {
            gst::warning!(CAT, imp = self, "Unsupported dav1d format: {}", f);
            gst_video::VideoFormat::Unknown
        })
    }

    fn colorimetry_from_dav1d_picture(
        &self,
        pic: &dav1d::Picture,
    ) -> Option<gst_video::VideoColorimetry> {
        use dav1d::pixel;

        let range = match pic.color_range() {
            pixel::YUVRange::Limited => gst_video::VideoColorRange::Range16_235,
            pixel::YUVRange::Full => gst_video::VideoColorRange::Range0_255,
        };

        let matrix = match pic.matrix_coefficients() {
            pixel::MatrixCoefficients::Identity => gst_video::VideoColorMatrix::Rgb,
            pixel::MatrixCoefficients::BT709 => gst_video::VideoColorMatrix::Bt709,
            pixel::MatrixCoefficients::Unspecified => gst_video::VideoColorMatrix::Bt709,
            pixel::MatrixCoefficients::BT470M => gst_video::VideoColorMatrix::Fcc,
            pixel::MatrixCoefficients::BT470BG => gst_video::VideoColorMatrix::Bt601,
            pixel::MatrixCoefficients::ST240M => gst_video::VideoColorMatrix::Smpte240m,
            pixel::MatrixCoefficients::BT2020NonConstantLuminance => {
                gst_video::VideoColorMatrix::Bt2020
            }
            _ => {
                gst::warning!(
                    CAT,
                    imp = self,
                    "Unsupported dav1d colorimetry matrix coefficients"
                );
                return None;
            }
        };

        let transfer = match pic.transfer_characteristic() {
            pixel::TransferCharacteristic::BT1886 => gst_video::VideoTransferFunction::Bt709,
            pixel::TransferCharacteristic::Unspecified => gst_video::VideoTransferFunction::Bt709,
            pixel::TransferCharacteristic::BT470M => gst_video::VideoTransferFunction::Bt709,
            pixel::TransferCharacteristic::BT470BG => gst_video::VideoTransferFunction::Gamma28,
            pixel::TransferCharacteristic::ST170M => gst_video::VideoTransferFunction::Bt601,
            pixel::TransferCharacteristic::ST240M => gst_video::VideoTransferFunction::Smpte240m,
            pixel::TransferCharacteristic::Linear => gst_video::VideoTransferFunction::Gamma10,
            pixel::TransferCharacteristic::Logarithmic100 => {
                gst_video::VideoTransferFunction::Log100
            }
            pixel::TransferCharacteristic::Logarithmic316 => {
                gst_video::VideoTransferFunction::Log316
            }
            pixel::TransferCharacteristic::SRGB => gst_video::VideoTransferFunction::Srgb,
            pixel::TransferCharacteristic::BT2020Ten => gst_video::VideoTransferFunction::Bt202010,
            pixel::TransferCharacteristic::BT2020Twelve => {
                gst_video::VideoTransferFunction::Bt202012
            }
            pixel::TransferCharacteristic::PerceptualQuantizer => {
                gst_video::VideoTransferFunction::Smpte2084
            }
            pixel::TransferCharacteristic::HybridLogGamma => {
                gst_video::VideoTransferFunction::AribStdB67
            }
            _ => {
                gst::warning!(
                    CAT,
                    imp = self,
                    "Unsupported dav1d colorimetry transfer function"
                );
                return None;
            }
        };

        let primaries = match pic.color_primaries() {
            pixel::ColorPrimaries::BT709 => gst_video::VideoColorPrimaries::Bt709,
            pixel::ColorPrimaries::Unspecified => gst_video::VideoColorPrimaries::Bt709,
            pixel::ColorPrimaries::BT470M => gst_video::VideoColorPrimaries::Bt470m,
            pixel::ColorPrimaries::BT470BG => gst_video::VideoColorPrimaries::Bt470bg,
            pixel::ColorPrimaries::ST240M => gst_video::VideoColorPrimaries::Smpte240m,
            pixel::ColorPrimaries::Film => gst_video::VideoColorPrimaries::Film,
            pixel::ColorPrimaries::BT2020 => gst_video::VideoColorPrimaries::Bt2020,
            pixel::ColorPrimaries::ST428 => gst_video::VideoColorPrimaries::Smptest428,
            pixel::ColorPrimaries::P3DCI => gst_video::VideoColorPrimaries::Smpterp431,
            pixel::ColorPrimaries::P3Display => gst_video::VideoColorPrimaries::Smpteeg432,
            pixel::ColorPrimaries::Tech3213 => gst_video::VideoColorPrimaries::Ebu3213,
            _ => {
                gst::warning!(CAT, imp = self, "Unsupported dav1d color primaries");
                return None;
            }
        };
        Some(gst_video::VideoColorimetry::new(
            range, matrix, transfer, primaries,
        ))
    }

    fn chroma_site_from_dav1d_picture(
        &self,
        pic: &dav1d::Picture,
    ) -> Option<gst_video::VideoChromaSite> {
        use dav1d::pixel;
        match pic.pixel_layout() {
            dav1d::PixelLayout::I420 | dav1d::PixelLayout::I422 => match pic.chroma_location() {
                pixel::ChromaLocation::Center => Some(gst_video::VideoChromaSite::JPEG),
                pixel::ChromaLocation::Left => Some(gst_video::VideoChromaSite::MPEG2),
                _ => None,
            },
            _ => None,
        }
    }

    fn handle_resolution_change<'s>(
        &'s self,
        mut state_guard: MutexGuard<'s, Option<State>>,
        pic: &dav1d::Picture,
    ) -> Result<MutexGuard<'s, Option<State>>, gst::FlowError> {
        let state = state_guard.as_ref().unwrap();

        let format = self.gst_video_format_from_dav1d_picture(pic);
        if format == gst_video::VideoFormat::Unknown {
            return Err(gst::FlowError::NotNegotiated);
        }

        let need_negotiate = {
            match state.output_info {
                Some(ref i) => {
                    (i.width() != pic.width())
                        || (i.height() != pic.height() || (i.format() != format))
                }
                None => true,
            }
        };
        if !need_negotiate {
            return Ok(state_guard);
        }

        gst::info!(
            CAT,
            imp = self,
            "Negotiating format {:?} picture dimensions {}x{}",
            format,
            pic.width(),
            pic.height()
        );

        let input_state = state.input_state.clone();
        let input_info = input_state.info();
        let input_caps = input_state.caps().ok_or(gst::FlowError::NotNegotiated)?;
        let input_structure = input_caps
            .structure(0)
            .ok_or(gst::FlowError::NotNegotiated)?;
        let input_colorimetry = input_info.colorimetry();

        drop(state_guard);

        let instance = self.obj();
        let mut output_state =
            instance.set_output_state(format, pic.width(), pic.height(), Some(&input_state))?;
        let mut info_builder = gst_video::VideoInfo::builder(format, pic.width(), pic.height());
        let mut update_output_state = false;

        let colorimetry = self.colorimetry_from_dav1d_picture(pic);
        if !input_structure.has_field("colorimetry")
            || input_colorimetry.range() == gst_video::VideoColorRange::Unknown
            || input_colorimetry.matrix() == gst_video::VideoColorMatrix::Unknown
            || input_colorimetry.transfer() == gst_video::VideoTransferFunction::Unknown
            || input_colorimetry.primaries() == gst_video::VideoColorPrimaries::Unknown
        {
            if let Some(colorimetry) = colorimetry.as_ref() {
                info_builder = info_builder.colorimetry(colorimetry);
                update_output_state = true;
            }
        }

        if !input_structure.has_field("chroma-site") {
            if let Some(chroma_site) = self.chroma_site_from_dav1d_picture(pic) {
                info_builder = info_builder.chroma_site(chroma_site);
                update_output_state = true;
            }
        }

        if update_output_state {
            let info = info_builder
                .build()
                .map_err(|_| gst::FlowError::NotNegotiated)?;
            output_state.set_info(info);
        }

        instance.negotiate(output_state)?;
        let out_state = instance.output_state().unwrap();

        state_guard = self.state.lock().unwrap();
        let state = state_guard.as_mut().ok_or(gst::FlowError::Flushing)?;
        state.output_info = Some(out_state.info());

        Ok(state_guard)
    }

    fn flush_decoder(&self, state: &mut State) {
        gst::info!(CAT, imp = self, "Flushing decoder");

        state.decoder.flush();
    }

    fn send_data(
        &self,
        state_guard: &mut MutexGuard<Option<State>>,
        input_buffer: gst::Buffer,
        frame: gst_video::VideoCodecFrame,
    ) -> Result<std::ops::ControlFlow<(), ()>, gst::FlowError> {
        gst::trace!(
            CAT,
            imp = self,
            "Sending data to decoder for frame {}",
            frame.system_frame_number()
        );

        let state = state_guard.as_mut().ok_or(gst::FlowError::Flushing)?;

        let timestamp = frame.dts().map(|ts| *ts as i64);
        let duration = frame.duration().map(|d| *d as i64);

        let frame_number = Some(frame.system_frame_number() as i64);

        let input_data = input_buffer
            .into_mapped_buffer_readable()
            .map_err(|_| gst::FlowError::Error)?;

        match state
            .decoder
            .send_data(input_data, frame_number, timestamp, duration)
        {
            Ok(()) => {
                gst::trace!(CAT, imp = self, "Decoder returned OK");
                Ok(std::ops::ControlFlow::Break(()))
            }
            Err(dav1d::Error::Again) => {
                gst::trace!(CAT, imp = self, "Decoder returned EAGAIN");
                Ok(std::ops::ControlFlow::Continue(()))
            }
            Err(dav1d::Error::InvalidArgument) => {
                gst::trace!(CAT, imp = self, "Decoder returned EINVAL");
                gst_video::video_decoder_error!(
                    &*self.obj(),
                    1,
                    gst::LibraryError::Encode,
                    ["Bitstream error"]
                )?;
                Ok(std::ops::ControlFlow::Continue(()))
            }
            Err(err) => {
                gst::error!(CAT, "Sending data failed (error code: {})", err);
                self.obj().release_frame(frame);
                gst_video::video_decoder_error!(
                    &*self.obj(),
                    1,
                    gst::StreamError::Decode,
                    ["Sending data failed (error code {})", err]
                )
                .map(|_| std::ops::ControlFlow::Break(()))
            }
        }
    }

    fn send_pending_data(
        &self,
        state_guard: &mut MutexGuard<Option<State>>,
    ) -> Result<std::ops::ControlFlow<(), ()>, gst::FlowError> {
        gst::trace!(CAT, imp = self, "Sending pending data to decoder");

        let state = state_guard.as_mut().ok_or(gst::FlowError::Flushing)?;

        match state.decoder.send_pending_data() {
            Ok(()) => {
                gst::trace!(CAT, imp = self, "Decoder returned OK");
                Ok(std::ops::ControlFlow::Break(()))
            }
            Err(err) if err.is_again() => {
                gst::trace!(CAT, imp = self, "Decoder returned EAGAIN");
                Ok(std::ops::ControlFlow::Continue(()))
            }
            Err(err) => {
                gst::error!(CAT, "Sending data failed (error code: {})", err);
                gst_video::video_decoder_error!(
                    &*self.obj(),
                    1,
                    gst::StreamError::Decode,
                    ["Sending data failed (error code {})", err]
                )
                .map(|_| std::ops::ControlFlow::Break(()))
            }
        }
    }

    fn decoded_picture_as_buffer(
        &self,
        state_guard: &mut MutexGuard<Option<State>>,
        pic: &dav1d::Picture,
        output_state: gst_video::VideoCodecState<gst_video::video_codec_state::Readable>,
    ) -> Result<gst::Buffer, gst::FlowError> {
        let mut offsets = vec![];
        let mut strides = vec![];
        let mut acc_offset: usize = 0;

        let state = state_guard.as_mut().ok_or(gst::FlowError::Flushing)?;
        let video_meta_supported = state.video_meta_supported;

        let info = output_state.info();
        let mut out_buffer = gst::Buffer::new();
        let mut_buffer = out_buffer.get_mut().unwrap();

        let components = if info.is_yuv() {
            const YUV_COMPONENTS: [dav1d::PlanarImageComponent; 3] = [
                dav1d::PlanarImageComponent::Y,
                dav1d::PlanarImageComponent::U,
                dav1d::PlanarImageComponent::V,
            ];
            &YUV_COMPONENTS[..]
        } else if info.is_gray() {
            const GRAY_COMPONENTS: [dav1d::PlanarImageComponent; 1] =
                [dav1d::PlanarImageComponent::Y];

            &GRAY_COMPONENTS[..]
        } else {
            unreachable!();
        };
        for &component in components {
            let dest_stride: u32 = info.stride()[component as usize].try_into().unwrap();
            let plane = pic.plane(component);
            let (src_stride, height) = pic.plane_data_geometry(component);
            let mem = if video_meta_supported || src_stride == dest_stride {
                gst::Memory::from_slice(plane)
            } else {
                gst::trace!(
                    gst::CAT_PERFORMANCE,
                    imp = self,
                    "Copying decoded video frame component {:?}",
                    component
                );

                let src_slice = plane.as_ref();
                let mem = gst::Memory::with_size((dest_stride * height) as usize);
                let mut writable_mem = mem
                    .into_mapped_memory_writable()
                    .map_err(|_| gst::FlowError::Error)?;
                let len = std::cmp::min(src_stride, dest_stride) as usize;

                for (out_line, in_line) in writable_mem
                    .as_mut_slice()
                    .chunks_exact_mut(dest_stride.try_into().unwrap())
                    .zip(src_slice.chunks_exact(src_stride.try_into().unwrap()))
                {
                    out_line.copy_from_slice(&in_line[..len]);
                }
                writable_mem.into_memory()
            };
            let mem_size = mem.size();
            mut_buffer.append_memory(mem);

            strides.push(src_stride as i32);
            offsets.push(acc_offset);
            acc_offset += mem_size;
        }

        if video_meta_supported {
            gst_video::VideoMeta::add_full(
                out_buffer.get_mut().unwrap(),
                gst_video::VideoFrameFlags::empty(),
                info.format(),
                info.width(),
                info.height(),
                &offsets,
                &strides[..],
            )
            .unwrap();
        }

        let duration = pic.duration() as u64;
        if duration > 0 {
            out_buffer
                .get_mut()
                .unwrap()
                .set_duration(duration.nseconds());
        }

        Ok(out_buffer)
    }

    fn handle_picture<'s>(
        &'s self,
        mut state_guard: MutexGuard<'s, Option<State>>,
        pic: &dav1d::Picture,
    ) -> Result<MutexGuard<'s, Option<State>>, gst::FlowError> {
        gst::trace!(CAT, imp = self, "Handling picture {}", pic.offset());

        state_guard = self.handle_resolution_change(state_guard, pic)?;

        let instance = self.obj();
        let output_state = instance
            .output_state()
            .expect("Output state not set. Shouldn't happen!");
        let offset = pic.offset() as i32;

        let frame = instance.frame(offset);
        if let Some(mut frame) = frame {
            let output_buffer =
                self.decoded_picture_as_buffer(&mut state_guard, pic, output_state)?;
            frame.set_output_buffer(output_buffer);
            drop(state_guard);
            instance.finish_frame(frame)?;
            Ok(self.state.lock().unwrap())
        } else {
            gst::warning!(CAT, imp = self, "No frame found for offset {}", offset);
            Ok(state_guard)
        }
    }

    fn pending_picture(
        &self,
        state_guard: &mut MutexGuard<Option<State>>,
    ) -> Result<Option<dav1d::Picture>, gst::FlowError> {
        gst::trace!(CAT, imp = self, "Retrieving pending picture");

        let state = state_guard.as_mut().ok_or(gst::FlowError::Flushing)?;

        match state.decoder.get_picture() {
            Ok(pic) => {
                gst::trace!(CAT, imp = self, "Retrieved picture {}", pic.offset());
                Ok(Some(pic))
            }
            Err(err) if err.is_again() => {
                gst::trace!(CAT, imp = self, "Decoder needs more data");
                Ok(None)
            }
            Err(err) => {
                gst::error!(
                    CAT,
                    imp = self,
                    "Retrieving decoded picture failed (error code {})",
                    err
                );

                gst_video::video_decoder_error!(
                    &*self.obj(),
                    1,
                    gst::StreamError::Decode,
                    ["Retrieving decoded picture failed (error code {})", err]
                )
                .map(|_| None)
            }
        }
    }

    fn forward_pending_pictures<'s>(
        &'s self,
        mut state_guard: MutexGuard<'s, Option<State>>,
        drain: bool,
    ) -> Result<MutexGuard<'s, Option<State>>, gst::FlowError> {
        // dav1d wants to have get_picture() called a second time after it return EAGAIN to
        // actually drain all pending pictures.
        let mut call_twice = drain;

        loop {
            while let Some(pic) = self.pending_picture(&mut state_guard)? {
                state_guard = self.handle_picture(state_guard, &pic)?;
                call_twice = false;
                if !drain {
                    break;
                }
            }

            if !call_twice {
                break;
            }
            call_twice = false;
        }

        Ok(state_guard)
    }
}

fn video_output_formats() -> impl IntoIterator<Item = gst_video::VideoFormat> {
    [
        gst_video::VideoFormat::Gray8,
        #[cfg(target_endian = "little")]
        gst_video::VideoFormat::Gray16Le,
        #[cfg(target_endian = "big")]
        gst_video::VideoFormat::Gray16Be,
        // #[cfg(target_endian = "little")]
        // gst_video::VideoFormat::Gray10Le32,
        gst_video::VideoFormat::I420,
        gst_video::VideoFormat::Y42b,
        gst_video::VideoFormat::Y444,
        #[cfg(target_endian = "little")]
        gst_video::VideoFormat::I42010le,
        #[cfg(target_endian = "little")]
        gst_video::VideoFormat::I42210le,
        #[cfg(target_endian = "little")]
        gst_video::VideoFormat::Y44410le,
        #[cfg(target_endian = "big")]
        gst_video::VideoFormat::I42010be,
        #[cfg(target_endian = "big")]
        gst_video::VideoFormat::I42210be,
        #[cfg(target_endian = "big")]
        gst_video::VideoFormat::Y44410be,
        #[cfg(target_endian = "little")]
        gst_video::VideoFormat::I42012le,
        #[cfg(target_endian = "little")]
        gst_video::VideoFormat::I42212le,
        #[cfg(target_endian = "little")]
        gst_video::VideoFormat::Y44412le,
        #[cfg(target_endian = "big")]
        gst_video::VideoFormat::I42012be,
        #[cfg(target_endian = "big")]
        gst_video::VideoFormat::I42212be,
        #[cfg(target_endian = "big")]
        gst_video::VideoFormat::Y44412be,
    ]
}

#[glib::object_subclass]
impl ObjectSubclass for Dav1dDec {
    const NAME: &'static str = "GstDav1dDec";
    type Type = super::Dav1dDec;
    type ParentType = gst_video::VideoDecoder;
}

impl ObjectImpl for Dav1dDec {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: LazyLock<Vec<glib::ParamSpec>> = LazyLock::new(|| {
            vec![
                glib::ParamSpecUInt::builder("n-threads")
                    .nick("Number of threads")
                    .blurb("Number of threads to use while decoding (set to 0 to use number of logical cores)")
                    .default_value(DEFAULT_N_THREADS)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecInt64::builder("max-frame-delay")
                    .nick("Maximum frame delay")
                    .blurb("Maximum delay in frames for the decoder (set to 1 for low latency, 0 to be equal to the number of logical cores. -1 to choose between these two based on pipeline liveness)")
                    .minimum(-1)
                    .maximum(u32::MAX.into())
                    .default_value(DEFAULT_MAX_FRAME_DELAY)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecBoolean::builder("apply-grain")
                    .nick("Enable film grain synthesis")
                    .blurb("Enable out-of-loop normative film grain filter")
                    .default_value(DEFAULT_APPLY_GRAIN)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecFlags::builder("inloop-filters")
                    .nick("Inloop filters")
                    .blurb("Flags to enable in-loop post processing filters")
                    .default_value(DEFAULT_INLOOP_FILTERS)
                    .mutable_ready()
                    .build()

            ]
        });

        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        let mut settings = self.settings.lock().unwrap();

        match pspec.name() {
            "n-threads" => {
                settings.n_threads = value.get().expect("type checked upstream");
            }
            "max-frame-delay" => {
                settings.max_frame_delay = value.get().expect("type checked upstream");
            }
            "apply-grain" => {
                settings.apply_grain = value.get().expect("type checked upstream");
            }
            "inloop-filters" => {
                settings.inloop_filters = value.get().expect("type checked upstream");
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        let settings = self.settings.lock().unwrap();

        match pspec.name() {
            "n-threads" => settings.n_threads.to_value(),
            "max-frame-delay" => settings.max_frame_delay.to_value(),
            "apply-grain" => settings.apply_grain.to_value(),
            "inloop-filters" => settings.inloop_filters.to_value(),
            _ => unimplemented!(),
        }
    }
}

impl GstObjectImpl for Dav1dDec {}

impl ElementImpl for Dav1dDec {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: LazyLock<gst::subclass::ElementMetadata> = LazyLock::new(|| {
            gst::subclass::ElementMetadata::new(
                "Dav1d AV1 Decoder",
                "Codec/Decoder/Video",
                "Decode AV1 video streams with dav1d",
                "Philippe Normand <philn@igalia.com>",
            )
        });

        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: LazyLock<Vec<gst::PadTemplate>> = LazyLock::new(|| {
            let sink_caps = if gst::version() >= (1, 19, 0, 0) {
                gst::Caps::builder("video/x-av1")
                    .field("stream-format", "obu-stream")
                    .field("alignment", gst::List::new(["frame", "tu"]))
                    .build()
            } else {
                gst::Caps::builder("video/x-av1").build()
            };
            let sink_pad_template = gst::PadTemplate::new(
                "sink",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &sink_caps,
            )
            .unwrap();

            let src_caps = gst_video::VideoCapsBuilder::new()
                .format_list(video_output_formats())
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
}

impl VideoDecoderImpl for Dav1dDec {
    fn src_query(&self, query: &mut gst::QueryRef) -> bool {
        match query.view_mut() {
            gst::QueryViewMut::Latency(q) => {
                let state_guard = self.state.lock().unwrap();
                let max_frame_delay = {
                    let settings = self.settings.lock().unwrap();
                    settings.max_frame_delay
                };

                match *state_guard {
                    Some(ref state) => match state.output_info {
                        Some(ref info) => {
                            let mut upstream_latency = gst::query::Latency::new();

                            if self.obj().sink_pad().peer_query(&mut upstream_latency) {
                                let (live, mut min, mut max) = upstream_latency.result();
                                // For autodetection: 1 if live, else whatever dav1d gives us
                                let frame_latency: u64 = if max_frame_delay < 0 && live {
                                    1
                                } else {
                                    self.estimate_frame_delay(
                                        max_frame_delay as u32,
                                        state.n_cpus as u32,
                                    )
                                    .into()
                                };

                                let fps_n = match info.fps().numer() {
                                    0 => 30, // Pretend we're at 30fps if we don't know latency,
                                    n => n,
                                };

                                let latency = frame_latency * (info.fps().denom() as u64).seconds()
                                    / (fps_n as u64);

                                gst::debug!(CAT, imp = self, "Reporting latency of {}", latency);

                                min += latency;
                                max = max.opt_add(latency);
                                q.set(live, min, max);

                                true
                            } else {
                                // peer latency query failed
                                false
                            }
                        }
                        // output info not available => fps unknown
                        None => false,
                    },
                    // no state yet
                    None => false,
                }
            }
            _ => VideoDecoderImplExt::parent_src_query(self, query),
        }
    }

    fn stop(&self) -> Result<(), gst::ErrorMessage> {
        {
            let mut state_guard = self.state.lock().unwrap();
            *state_guard = None;
        }

        self.parent_stop()
    }

    fn set_format(
        &self,
        input_state: &gst_video::VideoCodecState<'static, gst_video::video_codec_state::Readable>,
    ) -> Result<(), gst::LoggableError> {
        let mut state_guard = self.state.lock().unwrap();
        let settings = self.settings.lock().unwrap();
        let mut decoder_settings = dav1d::Settings::new();
        let max_frame_delay: u32;
        let n_cpus = num_cpus::get();

        gst::info!(CAT, imp = self, "Detected {} logical CPUs", n_cpus);

        if settings.max_frame_delay == -1 {
            let mut latency_query = gst::query::Latency::new();
            let mut is_live = false;

            if self.obj().sink_pad().peer_query(&mut latency_query) {
                is_live = latency_query.result().0;
            }

            max_frame_delay = u32::from(is_live);
        } else {
            max_frame_delay = settings.max_frame_delay.try_into().unwrap();
        }

        gst::info!(
            CAT,
            imp = self,
            "Creating decoder with n-threads={} and max-frame-delay={}",
            settings.n_threads,
            max_frame_delay
        );
        decoder_settings.set_n_threads(settings.n_threads);
        decoder_settings.set_max_frame_delay(max_frame_delay);
        decoder_settings.set_apply_grain(settings.apply_grain);
        decoder_settings.set_inloop_filters(dav1d::InloopFilterType::from(settings.inloop_filters));

        let decoder = dav1d::Decoder::with_settings(&decoder_settings).map_err(|err| {
            gst::loggable_error!(CAT, "Failed to create decoder instance: {}", err)
        })?;

        *state_guard = Some(State {
            decoder,
            input_state: input_state.clone(),
            output_info: None,
            video_meta_supported: false,
            n_cpus,
        });

        self.parent_set_format(input_state)
    }

    fn handle_frame(
        &self,
        frame: gst_video::VideoCodecFrame,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let input_buffer = frame
            .input_buffer_owned()
            .expect("frame without input buffer");

        {
            let mut state_guard = self.state.lock().unwrap();
            if self.send_data(&mut state_guard, input_buffer, frame)?
                == std::ops::ControlFlow::Continue(())
            {
                loop {
                    state_guard = self.forward_pending_pictures(state_guard, false)?;
                    if self.send_pending_data(&mut state_guard)? == std::ops::ControlFlow::Break(())
                    {
                        break;
                    }
                }
            }
            let _state_guard = self.forward_pending_pictures(state_guard, false)?;
        }

        Ok(gst::FlowSuccess::Ok)
    }

    fn flush(&self) -> bool {
        gst::info!(CAT, imp = self, "Flushing");

        {
            let mut state_guard = self.state.lock().unwrap();
            if let Some(state) = &mut *state_guard {
                self.flush_decoder(state);
            }
        }

        true
    }

    fn drain(&self) -> Result<gst::FlowSuccess, gst::FlowError> {
        gst::info!(CAT, imp = self, "Draining");

        {
            let state_guard = self.state.lock().unwrap();
            if state_guard.is_some() {
                let _state_guard = self.forward_pending_pictures(state_guard, true)?;
            }
        }

        self.parent_drain()
    }

    fn finish(&self) -> Result<gst::FlowSuccess, gst::FlowError> {
        gst::info!(CAT, imp = self, "Finishing");

        {
            let state_guard = self.state.lock().unwrap();
            if state_guard.is_some() {
                let _state_guard = self.forward_pending_pictures(state_guard, true)?;
            }
        }

        self.parent_finish()
    }

    fn decide_allocation(
        &self,
        query: &mut gst::query::Allocation,
    ) -> Result<(), gst::LoggableError> {
        {
            let mut state_guard = self.state.lock().unwrap();
            if let Some(state) = &mut *state_guard {
                state.video_meta_supported = query
                    .find_allocation_meta::<gst_video::VideoMeta>()
                    .is_some();
            }
        }

        self.parent_decide_allocation(query)
    }
}
