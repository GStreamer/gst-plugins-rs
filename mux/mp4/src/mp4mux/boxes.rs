// Copyright (C) 2022 Sebastian Dröge <sebastian@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::prelude::*;

use anyhow::{anyhow, bail, Context, Error};

use std::str::FromStr;

fn write_box<T, F: FnOnce(&mut Vec<u8>) -> Result<T, Error>>(
    vec: &mut Vec<u8>,
    fourcc: impl std::borrow::Borrow<[u8; 4]>,
    content_func: F,
) -> Result<T, Error> {
    // Write zero size ...
    let size_pos = vec.len();
    vec.extend([0u8; 4]);
    vec.extend(fourcc.borrow());

    let res = content_func(vec)?;

    // ... and update it here later.
    let size: u32 = vec
        .len()
        .checked_sub(size_pos)
        .expect("vector shrunk")
        .try_into()
        .context("too big box content")?;
    vec[size_pos..][..4].copy_from_slice(&size.to_be_bytes());

    Ok(res)
}

const FULL_BOX_VERSION_0: u8 = 0;
const FULL_BOX_VERSION_1: u8 = 1;

const FULL_BOX_FLAGS_NONE: u32 = 0;

fn write_full_box<T, F: FnOnce(&mut Vec<u8>) -> Result<T, Error>>(
    vec: &mut Vec<u8>,
    fourcc: impl std::borrow::Borrow<[u8; 4]>,
    version: u8,
    flags: u32,
    content_func: F,
) -> Result<T, Error> {
    write_box(vec, fourcc, move |vec| {
        assert_eq!(flags >> 24, 0);
        vec.extend(((u32::from(version) << 24) | flags).to_be_bytes());
        content_func(vec)
    })
}

/// Creates `ftyp` box
pub(super) fn create_ftyp(variant: super::Variant) -> Result<gst::Buffer, Error> {
    let mut v = vec![];

    let (brand, compatible_brands) = match variant {
        super::Variant::ISO | super::Variant::ONVIF => (b"iso4", vec![b"mp41", b"mp42", b"isom"]),
    };

    write_box(&mut v, b"ftyp", |v| {
        // major brand
        v.extend(brand);
        // minor version
        v.extend(0u32.to_be_bytes());
        // compatible brands
        v.extend(compatible_brands.into_iter().flatten());

        Ok(())
    })?;

    Ok(gst::Buffer::from_mut_slice(v))
}

/// Creates `mdat` box *header*.
pub(super) fn create_mdat_header(size: Option<u64>) -> Result<gst::Buffer, Error> {
    let mut v = vec![];

    if let Some(size) = size {
        if let Ok(size) = u32::try_from(size + 8) {
            v.extend(8u32.to_be_bytes());
            v.extend(b"free");
            v.extend(size.to_be_bytes());
            v.extend(b"mdat");
        } else {
            v.extend(1u32.to_be_bytes());
            v.extend(b"mdat");
            v.extend((size + 16).to_be_bytes());
        }
    } else {
        v.extend(8u32.to_be_bytes());
        v.extend(b"free");
        v.extend(0u32.to_be_bytes());
        v.extend(b"mdat");
    }

    Ok(gst::Buffer::from_mut_slice(v))
}

/// Offset between UNIX epoch and Jan 1 1601 epoch in seconds.
/// 1601 = UNIX + UNIX_1601_OFFSET.
const UNIX_1601_OFFSET: u64 = 11_644_473_600;

/// Creates `moov` box
pub(super) fn create_moov(header: super::Header) -> Result<gst::Buffer, Error> {
    let mut v = vec![];

    write_box(&mut v, b"moov", |v| write_moov(v, &header))?;

    if header.variant == super::Variant::ONVIF {
        write_full_box(
            &mut v,
            b"meta",
            FULL_BOX_VERSION_0,
            FULL_BOX_FLAGS_NONE,
            |v| {
                write_full_box(v, b"hdlr", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
                    // Handler type
                    v.extend(b"null");

                    // Reserved
                    v.extend([0u8; 3 * 4]);

                    // Name
                    v.extend(b"MetadataHandler");

                    Ok(())
                })?;

                write_box(v, b"cstb", |v| {
                    // entry count
                    v.extend(1u32.to_be_bytes());

                    // track id
                    v.extend(0u32.to_be_bytes());

                    // start UTC time in 100ns units since Jan 1 1601
                    // This is the UTC time of the earliest stream, which has to be converted to
                    // the correct epoch and scale.
                    let start_utc_time = header
                        .streams
                        .iter()
                        .map(|s| s.earliest_pts)
                        .min()
                        .unwrap()
                        .nseconds()
                        / 100;
                    let start_utc_time = start_utc_time + UNIX_1601_OFFSET * 10_000_000;
                    v.extend(start_utc_time.to_be_bytes());

                    Ok(())
                })
            },
        )?;
    }

    Ok(gst::Buffer::from_mut_slice(v))
}

struct TrackReference {
    reference_type: [u8; 4],
    track_ids: Vec<u32>,
}

fn write_moov(v: &mut Vec<u8>, header: &super::Header) -> Result<(), Error> {
    use gst::glib;

    let base = glib::DateTime::from_utc(1904, 1, 1, 0, 0, 0.0)?;
    let now = glib::DateTime::now_utc()?;
    let creation_time =
        u64::try_from(now.difference(&base).as_seconds()).expect("time before 1904");

    write_full_box(v, b"mvhd", FULL_BOX_VERSION_1, FULL_BOX_FLAGS_NONE, |v| {
        write_mvhd(v, header, creation_time)
    })?;
    for (idx, stream) in header.streams.iter().enumerate() {
        write_box(v, b"trak", |v| {
            let mut references = Vec::new();

            // Reference the video track for ONVIF metadata tracks
            if header.variant == super::Variant::ONVIF
                && stream.caps.structure(0).unwrap().name() == "application/x-onvif-metadata"
            {
                // Find the first video track
                for (idx, other_stream) in header.streams.iter().enumerate() {
                    let s = other_stream.caps.structure(0).unwrap();

                    if matches!(
                        s.name().as_str(),
                        "video/x-h264" | "video/x-h265" | "image/jpeg"
                    ) {
                        references.push(TrackReference {
                            reference_type: *b"cdsc",
                            track_ids: vec![idx as u32 + 1],
                        });
                        break;
                    }
                }
            }

            write_trak(v, header, idx, stream, creation_time, &references)
        })?;
    }

    Ok(())
}

fn stream_to_timescale(stream: &super::Stream) -> u32 {
    if stream.trak_timescale > 0 {
        stream.trak_timescale
    } else {
        let s = stream.caps.structure(0).unwrap();

        if let Ok(fps) = s.get::<gst::Fraction>("framerate") {
            if fps.numer() == 0 {
                return 10_000;
            }

            if fps.denom() != 1 && fps.denom() != 1001 {
                if let Some(fps) = (fps.denom() as u64)
                    .nseconds()
                    .mul_div_round(1_000_000_000, fps.numer() as u64)
                    .and_then(gst_video::guess_framerate)
                {
                    return (fps.numer() as u32)
                        .mul_div_round(100, fps.denom() as u32)
                        .unwrap_or(10_000);
                }
            }

            if fps.denom() == 1001 {
                fps.numer() as u32
            } else {
                (fps.numer() as u32)
                    .mul_div_round(100, fps.denom() as u32)
                    .unwrap_or(10_000)
            }
        } else if let Ok(rate) = s.get::<i32>("rate") {
            rate as u32
        } else {
            10_000
        }
    }
}

fn header_to_timescale(header: &super::Header) -> u32 {
    if header.movie_timescale > 0 {
        header.movie_timescale
    } else {
        // Use the reference track timescale
        stream_to_timescale(&header.streams[0])
    }
}

fn write_mvhd(v: &mut Vec<u8>, header: &super::Header, creation_time: u64) -> Result<(), Error> {
    let timescale = header_to_timescale(header);

    // Creation time
    v.extend(creation_time.to_be_bytes());
    // Modification time
    v.extend(creation_time.to_be_bytes());
    // Timescale
    v.extend(timescale.to_be_bytes());
    // Duration
    let min_earliest_pts = header.streams.iter().map(|s| s.earliest_pts).min().unwrap();
    let max_end_pts = header
        .streams
        .iter()
        .map(|stream| stream.end_pts)
        .max()
        .unwrap();
    let duration = (max_end_pts - min_earliest_pts)
        .nseconds()
        .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
        .context("too big track duration")?;
    v.extend(duration.to_be_bytes());

    // Rate 1.0
    v.extend((1u32 << 16).to_be_bytes());
    // Volume 1.0
    v.extend((1u16 << 8).to_be_bytes());
    // Reserved
    v.extend([0u8; 2 + 2 * 4]);

    // Matrix
    v.extend(
        [
            (1u32 << 16).to_be_bytes(),
            0u32.to_be_bytes(),
            0u32.to_be_bytes(),
            0u32.to_be_bytes(),
            (1u32 << 16).to_be_bytes(),
            0u32.to_be_bytes(),
            0u32.to_be_bytes(),
            0u32.to_be_bytes(),
            (16384u32 << 16).to_be_bytes(),
        ]
        .into_iter()
        .flatten(),
    );

    // Pre defined
    v.extend([0u8; 6 * 4]);

    // Next track id
    v.extend((header.streams.len() as u32 + 1).to_be_bytes());

    Ok(())
}

const TKHD_FLAGS_TRACK_ENABLED: u32 = 0x1;
const TKHD_FLAGS_TRACK_IN_MOVIE: u32 = 0x2;
const TKHD_FLAGS_TRACK_IN_PREVIEW: u32 = 0x4;

fn write_trak(
    v: &mut Vec<u8>,
    header: &super::Header,
    idx: usize,
    stream: &super::Stream,
    creation_time: u64,
    references: &[TrackReference],
) -> Result<(), Error> {
    write_full_box(
        v,
        b"tkhd",
        FULL_BOX_VERSION_1,
        TKHD_FLAGS_TRACK_ENABLED | TKHD_FLAGS_TRACK_IN_MOVIE | TKHD_FLAGS_TRACK_IN_PREVIEW,
        |v| write_tkhd(v, header, idx, stream, creation_time),
    )?;

    write_box(v, b"mdia", |v| write_mdia(v, header, stream, creation_time))?;
    if !references.is_empty() {
        write_box(v, b"tref", |v| write_tref(v, header, references))?;
    }
    write_box(v, b"edts", |v| write_edts(v, header, stream))?;

    Ok(())
}

fn write_tkhd(
    v: &mut Vec<u8>,
    header: &super::Header,
    idx: usize,
    stream: &super::Stream,
    creation_time: u64,
) -> Result<(), Error> {
    // Creation time
    v.extend(creation_time.to_be_bytes());
    // Modification time
    v.extend(creation_time.to_be_bytes());
    // Track ID
    v.extend((idx as u32 + 1).to_be_bytes());
    // Reserved
    v.extend(0u32.to_be_bytes());
    // Duration

    // Track header duration is in movie header timescale
    let timescale = header_to_timescale(header);

    let min_earliest_pts = header.streams.iter().map(|s| s.earliest_pts).min().unwrap();
    // Duration is the end PTS of this stream up to the beginning of the earliest stream
    let duration = stream.end_pts - min_earliest_pts;
    let duration = duration
        .nseconds()
        .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
        .context("too big track duration")?;
    v.extend(duration.to_be_bytes());

    // Reserved
    v.extend([0u8; 2 * 4]);

    // Layer
    v.extend(0u16.to_be_bytes());
    // Alternate group
    v.extend(0u16.to_be_bytes());

    // Volume
    let s = stream.caps.structure(0).unwrap();
    match s.name().as_str() {
        "audio/mpeg" | "audio/x-opus" | "audio/x-alaw" | "audio/x-mulaw" | "audio/x-adpcm" => {
            v.extend((1u16 << 8).to_be_bytes())
        }
        _ => v.extend(0u16.to_be_bytes()),
    }

    // Reserved
    v.extend([0u8; 2]);

    // Matrix
    v.extend(
        [
            (1u32 << 16).to_be_bytes(),
            0u32.to_be_bytes(),
            0u32.to_be_bytes(),
            0u32.to_be_bytes(),
            (1u32 << 16).to_be_bytes(),
            0u32.to_be_bytes(),
            0u32.to_be_bytes(),
            0u32.to_be_bytes(),
            (16384u32 << 16).to_be_bytes(),
        ]
        .into_iter()
        .flatten(),
    );

    // Width/height
    match s.name().as_str() {
        "video/x-h264" | "video/x-h265" | "video/x-vp8" | "video/x-vp9" | "video/x-av1"
        | "image/jpeg" => {
            let width = s.get::<i32>("width").context("video caps without width")? as u32;
            let height = s
                .get::<i32>("height")
                .context("video caps without height")? as u32;
            let par = s
                .get::<gst::Fraction>("pixel-aspect-ratio")
                .unwrap_or_else(|_| gst::Fraction::new(1, 1));

            let width = std::cmp::min(
                width
                    .mul_div_round(par.numer() as u32, par.denom() as u32)
                    .unwrap_or(u16::MAX as u32),
                u16::MAX as u32,
            );
            let height = std::cmp::min(height, u16::MAX as u32);

            v.extend((width << 16).to_be_bytes());
            v.extend((height << 16).to_be_bytes());
        }
        _ => v.extend([0u8; 2 * 4]),
    }

    Ok(())
}

fn write_mdia(
    v: &mut Vec<u8>,
    header: &super::Header,
    stream: &super::Stream,
    creation_time: u64,
) -> Result<(), Error> {
    write_full_box(v, b"mdhd", FULL_BOX_VERSION_1, FULL_BOX_FLAGS_NONE, |v| {
        write_mdhd(v, header, stream, creation_time)
    })?;
    write_full_box(v, b"hdlr", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
        write_hdlr(v, header, stream)
    })?;

    // TODO: write elng if needed

    write_box(v, b"minf", |v| write_minf(v, header, stream))?;

    Ok(())
}

fn language_code(lang: impl std::borrow::Borrow<[u8; 3]>) -> u16 {
    let lang = lang.borrow();

    // TODO: Need to relax this once we get the language code from tags
    assert!(lang.iter().all(u8::is_ascii_lowercase));

    (((lang[0] as u16 - 0x60) & 0x1F) << 10)
        + (((lang[1] as u16 - 0x60) & 0x1F) << 5)
        + ((lang[2] as u16 - 0x60) & 0x1F)
}

fn write_mdhd(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
    creation_time: u64,
) -> Result<(), Error> {
    let timescale = stream_to_timescale(stream);

    // Creation time
    v.extend(creation_time.to_be_bytes());
    // Modification time
    v.extend(creation_time.to_be_bytes());
    // Timescale
    v.extend(timescale.to_be_bytes());
    // Duration
    let duration = stream
        .chunks
        .iter()
        .flat_map(|c| c.samples.iter().map(|b| b.duration.nseconds()))
        .sum::<u64>()
        .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
        .context("too big track duration")?;
    v.extend(duration.to_be_bytes());

    // Language as ISO-639-2/T
    // TODO: get actual language from the tags
    v.extend(language_code(b"und").to_be_bytes());

    // Pre-defined
    v.extend([0u8; 2]);

    Ok(())
}

fn write_hdlr(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    // Pre-defined
    v.extend([0u8; 4]);

    let s = stream.caps.structure(0).unwrap();
    let (handler_type, name) = match s.name().as_str() {
        "video/x-h264" | "video/x-h265" | "video/x-vp8" | "video/x-vp9" | "video/x-av1"
        | "image/jpeg" => (b"vide", b"VideoHandler\0".as_slice()),
        "audio/mpeg" | "audio/x-opus" | "audio/x-alaw" | "audio/x-mulaw" | "audio/x-adpcm" => {
            (b"soun", b"SoundHandler\0".as_slice())
        }
        "application/x-onvif-metadata" => (b"meta", b"MetadataHandler\0".as_slice()),
        _ => unreachable!(),
    };

    // Handler type
    v.extend(handler_type);

    // Reserved
    v.extend([0u8; 3 * 4]);

    // Name
    v.extend(name);

    Ok(())
}

fn write_minf(
    v: &mut Vec<u8>,
    header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let s = stream.caps.structure(0).unwrap();

    match s.name().as_str() {
        "video/x-h264" | "video/x-h265" | "video/x-vp8" | "video/x-vp9" | "video/x-av1"
        | "image/jpeg" => {
            // Flags are always 1 for unspecified reasons
            write_full_box(v, b"vmhd", FULL_BOX_VERSION_0, 1, |v| write_vmhd(v, header))?
        }
        "audio/mpeg" | "audio/x-opus" | "audio/x-alaw" | "audio/x-mulaw" | "audio/x-adpcm" => {
            write_full_box(v, b"smhd", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
                write_smhd(v, header)
            })?
        }
        "application/x-onvif-metadata" => {
            write_full_box(v, b"nmhd", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |_v| {
                Ok(())
            })?
        }
        _ => unreachable!(),
    }

    write_box(v, b"dinf", |v| write_dinf(v, header))?;

    write_box(v, b"stbl", |v| write_stbl(v, header, stream))?;

    Ok(())
}

fn write_vmhd(v: &mut Vec<u8>, _header: &super::Header) -> Result<(), Error> {
    // Graphics mode
    v.extend([0u8; 2]);

    // opcolor
    v.extend([0u8; 2 * 3]);

    Ok(())
}

fn write_smhd(v: &mut Vec<u8>, _header: &super::Header) -> Result<(), Error> {
    // Balance
    v.extend([0u8; 2]);

    // Reserved
    v.extend([0u8; 2]);

    Ok(())
}

fn write_dinf(v: &mut Vec<u8>, header: &super::Header) -> Result<(), Error> {
    write_full_box(v, b"dref", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
        write_dref(v, header)
    })?;

    Ok(())
}

const DREF_FLAGS_MEDIA_IN_SAME_FILE: u32 = 0x1;

fn write_dref(v: &mut Vec<u8>, _header: &super::Header) -> Result<(), Error> {
    // Entry count
    v.extend(1u32.to_be_bytes());

    write_full_box(
        v,
        b"url ",
        FULL_BOX_VERSION_0,
        DREF_FLAGS_MEDIA_IN_SAME_FILE,
        |_v| Ok(()),
    )?;

    Ok(())
}

fn write_stbl(
    v: &mut Vec<u8>,
    header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    write_full_box(v, b"stsd", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
        write_stsd(v, header, stream)
    })?;
    write_full_box(v, b"stts", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
        write_stts(v, header, stream)
    })?;

    // If there are any composition time offsets we need to write the ctts box. If any are negative
    // we need to write version 1 of the box, otherwise version 0 is sufficient.
    let mut need_ctts = None;
    if stream.delta_frames.requires_dts() {
        for composition_time_offset in stream.chunks.iter().flat_map(|c| {
            c.samples.iter().map(|b| {
                b.composition_time_offset
                    .expect("not all samples have a composition time offset")
            })
        }) {
            if composition_time_offset < 0 {
                need_ctts = Some(1);
                break;
            } else {
                need_ctts = Some(0);
            }
        }
    }
    if let Some(need_ctts) = need_ctts {
        let version = if need_ctts == 0 {
            FULL_BOX_VERSION_0
        } else {
            FULL_BOX_VERSION_1
        };

        write_full_box(v, b"ctts", version, FULL_BOX_FLAGS_NONE, |v| {
            write_ctts(v, header, stream, version)
        })?;

        write_full_box(v, b"cslg", FULL_BOX_VERSION_1, FULL_BOX_FLAGS_NONE, |v| {
            write_cslg(v, header, stream)
        })?;
    }

    // If any sample is not a sync point, write the stss box
    if !stream.delta_frames.intra_only()
        && stream
            .chunks
            .iter()
            .flat_map(|c| c.samples.iter().map(|b| b.sync_point))
            .any(|sync_point| !sync_point)
    {
        write_full_box(v, b"stss", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
            write_stss(v, header, stream)
        })?;
    }

    write_full_box(v, b"stsz", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
        write_stsz(v, header, stream)
    })?;

    write_full_box(v, b"stsc", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
        write_stsc(v, header, stream)
    })?;

    if stream.chunks.last().unwrap().offset > u32::MAX as u64 {
        write_full_box(v, b"co64", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
            write_stco(v, header, stream, true)
        })?;
    } else {
        write_full_box(v, b"stco", FULL_BOX_VERSION_0, FULL_BOX_FLAGS_NONE, |v| {
            write_stco(v, header, stream, false)
        })?;
    }

    Ok(())
}

fn write_stsd(
    v: &mut Vec<u8>,
    header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    // Entry count
    v.extend(1u32.to_be_bytes());

    let s = stream.caps.structure(0).unwrap();
    match s.name().as_str() {
        "video/x-h264" | "video/x-h265" | "video/x-vp8" | "video/x-vp9" | "video/x-av1"
        | "image/jpeg" => write_visual_sample_entry(v, header, stream)?,
        "audio/mpeg" | "audio/x-opus" | "audio/x-alaw" | "audio/x-mulaw" | "audio/x-adpcm" => {
            write_audio_sample_entry(v, header, stream)?
        }
        "application/x-onvif-metadata" => write_xml_meta_data_sample_entry(v, header, stream)?,
        _ => unreachable!(),
    }

    Ok(())
}

fn write_sample_entry_box<T, F: FnOnce(&mut Vec<u8>) -> Result<T, Error>>(
    v: &mut Vec<u8>,
    fourcc: impl std::borrow::Borrow<[u8; 4]>,
    content_func: F,
) -> Result<T, Error> {
    write_box(v, fourcc, move |v| {
        // Reserved
        v.extend([0u8; 6]);

        // Data reference index
        v.extend(1u16.to_be_bytes());

        content_func(v)
    })
}

fn write_visual_sample_entry(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let s = stream.caps.structure(0).unwrap();
    let fourcc = match s.name().as_str() {
        "video/x-h264" => {
            let stream_format = s.get::<&str>("stream-format").context("no stream-format")?;
            match stream_format {
                "avc" => b"avc1",
                "avc3" => b"avc3",
                _ => unreachable!(),
            }
        }
        "video/x-h265" => {
            let stream_format = s.get::<&str>("stream-format").context("no stream-format")?;
            match stream_format {
                "hvc1" => b"hvc1",
                "hev1" => b"hev1",
                _ => unreachable!(),
            }
        }
        "image/jpeg" => b"jpeg",
        "video/x-vp8" => b"vp08",
        "video/x-vp9" => b"vp09",
        "video/x-av1" => b"av01",
        _ => unreachable!(),
    };

    write_sample_entry_box(v, fourcc, move |v| {
        // pre-defined
        v.extend([0u8; 2]);
        // Reserved
        v.extend([0u8; 2]);
        // pre-defined
        v.extend([0u8; 3 * 4]);

        // Width
        let width =
            u16::try_from(s.get::<i32>("width").context("no width")?).context("too big width")?;
        v.extend(width.to_be_bytes());

        // Height
        let height = u16::try_from(s.get::<i32>("height").context("no height")?)
            .context("too big height")?;
        v.extend(height.to_be_bytes());

        // Horizontal resolution
        v.extend(0x00480000u32.to_be_bytes());

        // Vertical resolution
        v.extend(0x00480000u32.to_be_bytes());

        // Reserved
        v.extend([0u8; 4]);

        // Frame count
        v.extend(1u16.to_be_bytes());

        // Compressor name
        v.extend([0u8; 32]);

        // Depth
        v.extend(0x0018u16.to_be_bytes());

        // Pre-defined
        v.extend((-1i16).to_be_bytes());

        // Codec specific boxes
        match s.name().as_str() {
            "video/x-h264" => {
                let codec_data = s
                    .get::<&gst::BufferRef>("codec_data")
                    .context("no codec_data")?;
                let map = codec_data
                    .map_readable()
                    .context("codec_data not mappable")?;
                write_box(v, b"avcC", move |v| {
                    v.extend_from_slice(&map);
                    Ok(())
                })?;
            }
            "video/x-h265" => {
                let codec_data = s
                    .get::<&gst::BufferRef>("codec_data")
                    .context("no codec_data")?;
                let map = codec_data
                    .map_readable()
                    .context("codec_data not mappable")?;
                write_box(v, b"hvcC", move |v| {
                    v.extend_from_slice(&map);
                    Ok(())
                })?;
            }
            "video/x-vp9" => {
                let profile: u8 = match s.get::<&str>("profile").expect("no vp9 profile") {
                    "0" => Some(0),
                    "1" => Some(1),
                    "2" => Some(2),
                    "3" => Some(3),
                    _ => None,
                }
                .context("unsupported vp9 profile")?;
                let colorimetry = gst_video::VideoColorimetry::from_str(
                    s.get::<&str>("colorimetry").expect("no colorimetry"),
                )
                .context("failed to parse colorimetry")?;
                let video_full_range =
                    colorimetry.range() == gst_video::VideoColorRange::Range0_255;
                let chroma_format: u8 =
                    match s.get::<&str>("chroma-format").expect("no chroma-format") {
                        "4:2:0" =>
                        // chroma-site is optional
                        {
                            match s
                                .get::<&str>("chroma-site")
                                .ok()
                                .and_then(|cs| gst_video::VideoChromaSite::from_str(cs).ok())
                            {
                                Some(gst_video::VideoChromaSite::V_COSITED) => Some(0),
                                // COSITED
                                _ => Some(1),
                            }
                        }
                        "4:2:2" => Some(2),
                        "4:4:4" => Some(3),
                        _ => None,
                    }
                    .context("unsupported chroma-format")?;
                let bit_depth: u8 = {
                    let bit_depth_luma = s.get::<u32>("bit-depth-luma").expect("no bit-depth-luma");
                    let bit_depth_chroma = s
                        .get::<u32>("bit-depth-chroma")
                        .expect("no bit-depth-chroma");
                    if bit_depth_luma != bit_depth_chroma {
                        return Err(anyhow!("bit-depth-luma and bit-depth-chroma have different values which is an unsupported configuration"));
                    }
                    bit_depth_luma as u8
                };
                write_full_box(v, b"vpcC", 1, 0, move |v| {
                    v.push(profile);
                    // XXX: hardcoded level 1
                    v.push(10);
                    let mut byte: u8 = 0;
                    byte |= (bit_depth & 0xF) << 4;
                    byte |= (chroma_format & 0x7) << 1;
                    byte |= video_full_range as u8;
                    v.push(byte);
                    v.push(colorimetry.primaries().to_iso() as u8);
                    v.push(colorimetry.transfer().to_iso() as u8);
                    v.push(colorimetry.matrix().to_iso() as u8);
                    // 16-bit length field for codec initialization, unused
                    v.push(0);
                    v.push(0);
                    Ok(())
                })?;
            }
            "video/x-av1" => {
                write_box(v, b"av1C", move |v| {
                    if let Ok(codec_data) = s.get::<&gst::BufferRef>("codec_data") {
                        let map = codec_data
                            .map_readable()
                            .context("codec_data not mappable")?;

                        v.extend_from_slice(&map);
                    } else {
                        let presentation_delay_minus_one =
                            if let Ok(presentation_delay) = s.get::<i32>("presentation-delay") {
                                Some(
                                    (1u8 << 5)
                                        | std::cmp::max(
                                            0xF,
                                            (presentation_delay.saturating_sub(1) & 0xF) as u8,
                                        ),
                                )
                            } else {
                                None
                            };

                        let profile = match s.get::<&str>("profile").unwrap() {
                            "main" => 0,
                            "high" => 1,
                            "professional" => 2,
                            _ => unreachable!(),
                        };

                        let level = 1; // FIXME
                        let tier = 0; // FIXME
                        let (high_bitdepth, twelve_bit) =
                            match s.get::<u32>("bit-depth-luma").unwrap() {
                                8 => (false, false),
                                10 => (true, false),
                                12 => (true, true),
                                _ => unreachable!(),
                            };
                        let (monochrome, chroma_sub_x, chroma_sub_y) =
                            match s.get::<&str>("chroma-format").unwrap() {
                                "4:0:0" => (true, true, true),
                                "4:2:0" => (false, true, true),
                                "4:2:2" => (false, true, false),
                                "4:4:4" => (false, false, false),
                                _ => unreachable!(),
                            };

                        let chrome_sample_position = match s.get::<&str>("chroma-site") {
                            Ok("v-cosited") => 1,
                            Ok("v-cosited+h-cosited") => 2,
                            _ => 0,
                        };

                        let codec_data = [
                            0x80 | 0x01,            // marker | version
                            (profile << 5) | level, // profile | level
                            (tier << 7)
                                | ((high_bitdepth as u8) << 6)
                                | ((twelve_bit as u8) << 5)
                                | ((monochrome as u8) << 4)
                                | ((chroma_sub_x as u8) << 3)
                                | ((chroma_sub_y as u8) << 2)
                                | chrome_sample_position, // tier | high bitdepth | twelve bit | monochrome | chroma sub x |
                            // chroma sub y | chroma sample position
                            if let Some(presentation_delay_minus_one) = presentation_delay_minus_one
                            {
                                0x10 | presentation_delay_minus_one // reserved | presentation delay present | presentation delay
                            } else {
                                0
                            },
                        ];

                        v.extend_from_slice(&codec_data);
                    }

                    Ok(())
                })?;
            }
            "video/x-vp8" | "image/jpeg" => {
                // Nothing to do here
            }
            _ => unreachable!(),
        }

        if let Ok(par) = s.get::<gst::Fraction>("pixel-aspect-ratio") {
            write_box(v, b"pasp", move |v| {
                v.extend((par.numer() as u32).to_be_bytes());
                v.extend((par.denom() as u32).to_be_bytes());
                Ok(())
            })?;
        }

        if let Some(colorimetry) = s
            .get::<&str>("colorimetry")
            .ok()
            .and_then(|c| c.parse::<gst_video::VideoColorimetry>().ok())
        {
            write_box(v, b"colr", move |v| {
                v.extend(b"nclx");
                let (primaries, transfer, matrix) = {
                    (
                        (colorimetry.primaries().to_iso() as u16),
                        (colorimetry.transfer().to_iso() as u16),
                        (colorimetry.matrix().to_iso() as u16),
                    )
                };

                let full_range = match colorimetry.range() {
                    gst_video::VideoColorRange::Range0_255 => 0x80u8,
                    gst_video::VideoColorRange::Range16_235 => 0x00u8,
                    _ => 0x00,
                };

                v.extend(primaries.to_be_bytes());
                v.extend(transfer.to_be_bytes());
                v.extend(matrix.to_be_bytes());
                v.push(full_range);

                Ok(())
            })?;
        }

        if let Ok(cll) = gst_video::VideoContentLightLevel::from_caps(&stream.caps) {
            write_box(v, b"clli", move |v| {
                v.extend((cll.max_content_light_level()).to_be_bytes());
                v.extend((cll.max_frame_average_light_level()).to_be_bytes());
                Ok(())
            })?;
        }

        if let Ok(mastering) = gst_video::VideoMasteringDisplayInfo::from_caps(&stream.caps) {
            write_box(v, b"mdcv", move |v| {
                for primary in mastering.display_primaries() {
                    v.extend(primary.x.to_be_bytes());
                    v.extend(primary.y.to_be_bytes());
                }
                v.extend(mastering.white_point().x.to_be_bytes());
                v.extend(mastering.white_point().y.to_be_bytes());
                v.extend(mastering.max_display_mastering_luminance().to_be_bytes());
                v.extend(mastering.max_display_mastering_luminance().to_be_bytes());
                Ok(())
            })?;
        }

        // Write fiel box for codecs that require it
        if ["image/jpeg"].contains(&s.name().as_str()) {
            let interlace_mode = s
                .get::<&str>("interlace-mode")
                .ok()
                .map(gst_video::VideoInterlaceMode::from_string)
                .unwrap_or(gst_video::VideoInterlaceMode::Progressive);
            let field_order = s
                .get::<&str>("field-order")
                .ok()
                .map(gst_video::VideoFieldOrder::from_string)
                .unwrap_or(gst_video::VideoFieldOrder::Unknown);

            write_box(v, b"fiel", move |v| {
                let (interlace, field_order) = match interlace_mode {
                    gst_video::VideoInterlaceMode::Progressive => (1, 0),
                    gst_video::VideoInterlaceMode::Interleaved
                        if field_order == gst_video::VideoFieldOrder::TopFieldFirst =>
                    {
                        (2, 9)
                    }
                    gst_video::VideoInterlaceMode::Interleaved => (2, 14),
                    _ => (0, 0),
                };

                v.push(interlace);
                v.push(field_order);
                Ok(())
            })?;
        }

        // TODO: write btrt bitrate box based on tags

        Ok(())
    })?;

    Ok(())
}

fn write_audio_sample_entry(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let s = stream.caps.structure(0).unwrap();
    let fourcc = match s.name().as_str() {
        "audio/mpeg" => b"mp4a",
        "audio/x-opus" => b"Opus",
        "audio/x-alaw" => b"alaw",
        "audio/x-mulaw" => b"ulaw",
        "audio/x-adpcm" => {
            let layout = s.get::<&str>("layout").context("no ADPCM layout field")?;

            match layout {
                "g726" => b"ms\x00\x45",
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    };

    let sample_size = match s.name().as_str() {
        "audio/x-adpcm" => {
            let bitrate = s.get::<i32>("bitrate").context("no ADPCM bitrate field")?;
            (bitrate / 8000) as u16
        }
        _ => 16u16,
    };

    write_sample_entry_box(v, fourcc, move |v| {
        // Reserved
        v.extend([0u8; 2 * 4]);

        // Channel count
        let channels = u16::try_from(s.get::<i32>("channels").context("no channels")?)
            .context("too many channels")?;
        v.extend(channels.to_be_bytes());

        // Sample size
        v.extend(sample_size.to_be_bytes());

        // Pre-defined
        v.extend([0u8; 2]);

        // Reserved
        v.extend([0u8; 2]);

        // Sample rate
        let rate = u16::try_from(s.get::<i32>("rate").context("no rate")?).unwrap_or(0);
        v.extend((u32::from(rate) << 16).to_be_bytes());

        // Codec specific boxes
        match s.name().as_str() {
            "audio/mpeg" => {
                let codec_data = s
                    .get::<&gst::BufferRef>("codec_data")
                    .context("no codec_data")?;
                let map = codec_data
                    .map_readable()
                    .context("codec_data not mappable")?;
                if map.len() < 2 {
                    bail!("too small codec_data");
                }
                write_esds_aac(v, &map)?;
            }
            "audio/x-opus" => {
                write_dops(v, &stream.caps)?;
            }
            "audio/x-alaw" | "audio/x-mulaw" | "audio/x-adpcm" => {
                // Nothing to do here
            }
            _ => unreachable!(),
        }

        // If rate did not fit into 16 bits write a full `srat` box
        if rate == 0 {
            let rate = s.get::<i32>("rate").context("no rate")?;
            // FIXME: This is defined as full box?
            write_full_box(
                v,
                b"srat",
                FULL_BOX_VERSION_0,
                FULL_BOX_FLAGS_NONE,
                move |v| {
                    v.extend((rate as u32).to_be_bytes());
                    Ok(())
                },
            )?;
        }

        // TODO: write btrt bitrate box based on tags

        // TODO: chnl box for channel ordering? probably not needed for AAC

        Ok(())
    })?;

    Ok(())
}

fn write_esds_aac(v: &mut Vec<u8>, codec_data: &[u8]) -> Result<(), Error> {
    let calculate_len = |mut len| {
        if len > 260144641 {
            bail!("too big descriptor length");
        }

        if len == 0 {
            return Ok(([0; 4], 1));
        }

        let mut idx = 0;
        let mut lens = [0u8; 4];
        while len > 0 {
            lens[idx] = ((if len > 0x7f { 0x80 } else { 0x00 }) | (len & 0x7f)) as u8;
            idx += 1;
            len >>= 7;
        }

        Ok((lens, idx))
    };

    write_full_box(
        v,
        b"esds",
        FULL_BOX_VERSION_0,
        FULL_BOX_FLAGS_NONE,
        move |v| {
            // Calculate all lengths bottom up

            // Decoder specific info
            let decoder_specific_info_len = calculate_len(codec_data.len())?;

            // Decoder config
            let decoder_config_len =
                calculate_len(13 + 1 + decoder_specific_info_len.1 + codec_data.len())?;

            // SL config
            let sl_config_len = calculate_len(1)?;

            // ES descriptor
            let es_descriptor_len = calculate_len(
                3 + 1
                    + decoder_config_len.1
                    + 13
                    + 1
                    + decoder_specific_info_len.1
                    + codec_data.len()
                    + 1
                    + sl_config_len.1
                    + 1,
            )?;

            // ES descriptor tag
            v.push(0x03);

            // Length
            v.extend_from_slice(&es_descriptor_len.0[..(es_descriptor_len.1)]);

            // Track ID
            v.extend(1u16.to_be_bytes());
            // Flags
            v.push(0u8);

            // Decoder config descriptor
            v.push(0x04);

            // Length
            v.extend_from_slice(&decoder_config_len.0[..(decoder_config_len.1)]);

            // Object type ESDS_OBJECT_TYPE_MPEG4_P3
            v.push(0x40);
            // Stream type ESDS_STREAM_TYPE_AUDIO
            v.push((0x05 << 2) | 0x01);

            // Buffer size db?
            v.extend([0u8; 3]);

            // Max bitrate
            v.extend(0u32.to_be_bytes());

            // Avg bitrate
            v.extend(0u32.to_be_bytes());

            // Decoder specific info
            v.push(0x05);

            // Length
            v.extend_from_slice(&decoder_specific_info_len.0[..(decoder_specific_info_len.1)]);
            v.extend_from_slice(codec_data);

            // SL config descriptor
            v.push(0x06);

            // Length: 1 (tag) + 1 (length) + 1 (predefined)
            v.extend_from_slice(&sl_config_len.0[..(sl_config_len.1)]);

            // Predefined
            v.push(0x02);
            Ok(())
        },
    )
}

fn write_dops(v: &mut Vec<u8>, caps: &gst::Caps) -> Result<(), Error> {
    let rate;
    let channels;
    let channel_mapping_family;
    let stream_count;
    let coupled_count;
    let pre_skip;
    let output_gain;
    let mut channel_mapping = [0; 256];

    // TODO: Use audio clipping meta to calculate pre_skip

    if let Some(header) = caps
        .structure(0)
        .unwrap()
        .get::<gst::ArrayRef>("streamheader")
        .ok()
        .and_then(|a| a.get(0).and_then(|v| v.get::<gst::Buffer>().ok()))
    {
        (
            rate,
            channels,
            channel_mapping_family,
            stream_count,
            coupled_count,
            pre_skip,
            output_gain,
        ) = gst_pbutils::codec_utils_opus_parse_header(&header, Some(&mut channel_mapping))
            .unwrap();
    } else {
        (
            rate,
            channels,
            channel_mapping_family,
            stream_count,
            coupled_count,
        ) = gst_pbutils::codec_utils_opus_parse_caps(caps, Some(&mut channel_mapping)).unwrap();
        output_gain = 0;
        pre_skip = 0;
    }

    write_box(v, b"dOps", move |v| {
        // Version number
        v.push(0);
        v.push(channels);
        v.extend(pre_skip.to_be_bytes());
        v.extend(rate.to_be_bytes());
        v.extend(output_gain.to_be_bytes());
        v.push(channel_mapping_family);
        if channel_mapping_family > 0 {
            v.push(stream_count);
            v.push(coupled_count);
            v.extend(&channel_mapping[..channels as usize]);
        }

        Ok(())
    })
}

fn write_xml_meta_data_sample_entry(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let s = stream.caps.structure(0).unwrap();
    let namespace = match s.name().as_str() {
        "application/x-onvif-metadata" => b"http://www.onvif.org/ver10/schema",
        _ => unreachable!(),
    };

    write_sample_entry_box(v, b"metx", move |v| {
        // content_encoding, empty string
        v.push(0);

        // namespace
        v.extend_from_slice(namespace);
        v.push(0);

        // schema_location, empty string list
        v.push(0);

        Ok(())
    })?;

    Ok(())
}

fn write_stts(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let timescale = stream_to_timescale(stream);

    let entry_count_position = v.len();
    // Entry count, rewritten in the end
    v.extend(0u32.to_be_bytes());

    let mut last_duration: Option<u32> = None;
    let mut sample_count = 0u32;
    let mut num_entries = 0u32;
    for duration in stream
        .chunks
        .iter()
        .flat_map(|c| c.samples.iter().map(|b| b.duration))
    {
        let duration = u32::try_from(
            duration
                .nseconds()
                .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
                .context("too big sample duration")?,
        )
        .context("too big sample duration")?;

        if last_duration.map_or(true, |last_duration| last_duration != duration) {
            if let Some(last_duration) = last_duration {
                v.extend(sample_count.to_be_bytes());
                v.extend(last_duration.to_be_bytes());
                num_entries += 1;
            }

            last_duration = Some(duration);
            sample_count = 1;
        } else {
            sample_count += 1;
        }
    }

    if let Some(last_duration) = last_duration {
        v.extend(sample_count.to_be_bytes());
        v.extend(last_duration.to_be_bytes());
        num_entries += 1;
    }

    // Rewrite entry count
    v[entry_count_position..][..4].copy_from_slice(&num_entries.to_be_bytes());

    Ok(())
}

fn write_ctts(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
    version: u8,
) -> Result<(), Error> {
    let timescale = stream_to_timescale(stream);

    let entry_count_position = v.len();
    // Entry count, rewritten in the end
    v.extend(0u32.to_be_bytes());

    let mut last_composition_time_offset = None;
    let mut sample_count = 0u32;
    let mut num_entries = 0u32;
    for composition_time_offset in stream
        .chunks
        .iter()
        .flat_map(|c| c.samples.iter().map(|b| b.composition_time_offset))
    {
        let composition_time_offset = composition_time_offset
            .expect("not all samples have a composition time offset")
            .mul_div_round(timescale as i64, gst::ClockTime::SECOND.nseconds() as i64)
            .context("too big sample composition time offset")?;

        if last_composition_time_offset.map_or(true, |last_composition_time_offset| {
            last_composition_time_offset != composition_time_offset
        }) {
            if let Some(last_composition_time_offset) = last_composition_time_offset {
                v.extend(sample_count.to_be_bytes());
                if version == FULL_BOX_VERSION_0 {
                    let last_composition_time_offset = u32::try_from(last_composition_time_offset)
                        .context("too big sample composition time offset")?;

                    v.extend(last_composition_time_offset.to_be_bytes());
                } else {
                    let last_composition_time_offset = i32::try_from(last_composition_time_offset)
                        .context("too big sample composition time offset")?;
                    v.extend(last_composition_time_offset.to_be_bytes());
                }
                num_entries += 1;
            }

            last_composition_time_offset = Some(composition_time_offset);
            sample_count = 1;
        } else {
            sample_count += 1;
        }
    }

    if let Some(last_composition_time_offset) = last_composition_time_offset {
        v.extend(sample_count.to_be_bytes());
        if version == FULL_BOX_VERSION_0 {
            let last_composition_time_offset = u32::try_from(last_composition_time_offset)
                .context("too big sample composition time offset")?;

            v.extend(last_composition_time_offset.to_be_bytes());
        } else {
            let last_composition_time_offset = i32::try_from(last_composition_time_offset)
                .context("too big sample composition time offset")?;
            v.extend(last_composition_time_offset.to_be_bytes());
        }
        num_entries += 1;
    }

    // Rewrite entry count
    v[entry_count_position..][..4].copy_from_slice(&num_entries.to_be_bytes());

    Ok(())
}

fn write_cslg(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let timescale = stream_to_timescale(stream);

    let (min_ctts, max_ctts) = stream
        .chunks
        .iter()
        .flat_map(|c| {
            c.samples.iter().map(|b| {
                b.composition_time_offset
                    .expect("not all samples have a composition time offset")
            })
        })
        .fold((None, None), |(min, max), ctts| {
            (
                if min.map_or(true, |min| ctts < min) {
                    Some(ctts)
                } else {
                    min
                },
                if max.map_or(true, |max| ctts > max) {
                    Some(ctts)
                } else {
                    max
                },
            )
        });
    let min_ctts = min_ctts
        .unwrap()
        .mul_div_round(timescale as i64, gst::ClockTime::SECOND.nseconds() as i64)
        .context("too big composition time offset")?;
    let max_ctts = max_ctts
        .unwrap()
        .mul_div_round(timescale as i64, gst::ClockTime::SECOND.nseconds() as i64)
        .context("too big composition time offset")?;

    // Composition to DTS shift
    v.extend((-min_ctts).to_be_bytes());

    // least decode to display delta
    v.extend(min_ctts.to_be_bytes());

    // greatest decode to display delta
    v.extend(max_ctts.to_be_bytes());

    // composition start time
    let composition_start_time = stream
        .earliest_pts
        .nseconds()
        .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
        .context("too earliest PTS")?;
    v.extend(composition_start_time.to_be_bytes());

    // composition end time
    let composition_end_time = stream
        .end_pts
        .nseconds()
        .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
        .context("too end PTS")?;
    v.extend(composition_end_time.to_be_bytes());

    Ok(())
}

fn write_stss(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let entry_count_position = v.len();
    // Entry count, rewritten in the end
    v.extend(0u32.to_be_bytes());

    let mut num_entries = 0u32;
    for (idx, _sync_point) in stream
        .chunks
        .iter()
        .flat_map(|c| c.samples.iter().map(|b| b.sync_point))
        .enumerate()
        .filter(|(_idx, sync_point)| *sync_point)
    {
        v.extend((idx as u32 + 1).to_be_bytes());
        num_entries += 1;
    }

    // Rewrite entry count
    v[entry_count_position..][..4].copy_from_slice(&num_entries.to_be_bytes());

    Ok(())
}

fn write_stsz(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let first_sample_size = stream.chunks[0].samples[0].size;

    if stream
        .chunks
        .iter()
        .flat_map(|c| c.samples.iter().map(|b| b.size))
        .all(|size| size == first_sample_size)
    {
        // Sample size
        v.extend(first_sample_size.to_be_bytes());

        // Sample count
        let sample_count = stream
            .chunks
            .iter()
            .map(|c| c.samples.len() as u32)
            .sum::<u32>();
        v.extend(sample_count.to_be_bytes());
    } else {
        // Sample size
        v.extend(0u32.to_be_bytes());

        // Sample count, will be rewritten later
        let sample_count_position = v.len();
        let mut sample_count = 0u32;
        v.extend(0u32.to_be_bytes());

        for size in stream
            .chunks
            .iter()
            .flat_map(|c| c.samples.iter().map(|b| b.size))
        {
            v.extend(size.to_be_bytes());
            sample_count += 1;
        }

        v[sample_count_position..][..4].copy_from_slice(&sample_count.to_be_bytes());
    }

    Ok(())
}

fn write_stsc(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    let entry_count_position = v.len();
    // Entry count, rewritten in the end
    v.extend(0u32.to_be_bytes());

    let mut num_entries = 0u32;
    let mut first_chunk = 1u32;
    let mut samples_per_chunk: Option<u32> = None;
    for (idx, chunk) in stream.chunks.iter().enumerate() {
        if samples_per_chunk.map_or(true, |samples_per_chunk| {
            samples_per_chunk != chunk.samples.len() as u32
        }) {
            if let Some(samples_per_chunk) = samples_per_chunk {
                v.extend(first_chunk.to_be_bytes());
                v.extend(samples_per_chunk.to_be_bytes());
                // sample description index
                v.extend(1u32.to_be_bytes());
                num_entries += 1;
            }
            samples_per_chunk = Some(chunk.samples.len() as u32);
            first_chunk = idx as u32 + 1;
        }
    }

    if let Some(samples_per_chunk) = samples_per_chunk {
        v.extend(first_chunk.to_be_bytes());
        v.extend(samples_per_chunk.to_be_bytes());
        // sample description index
        v.extend(1u32.to_be_bytes());
        num_entries += 1;
    }

    // Rewrite entry count
    v[entry_count_position..][..4].copy_from_slice(&num_entries.to_be_bytes());

    Ok(())
}

fn write_stco(
    v: &mut Vec<u8>,
    _header: &super::Header,
    stream: &super::Stream,
    co64: bool,
) -> Result<(), Error> {
    // Entry count
    v.extend((stream.chunks.len() as u32).to_be_bytes());

    for chunk in &stream.chunks {
        if co64 {
            v.extend(chunk.offset.to_be_bytes());
        } else {
            v.extend(u32::try_from(chunk.offset).unwrap().to_be_bytes());
        }
    }

    Ok(())
}

fn write_tref(
    v: &mut Vec<u8>,
    _header: &super::Header,
    references: &[TrackReference],
) -> Result<(), Error> {
    for reference in references {
        write_box(v, reference.reference_type, |v| {
            for track_id in &reference.track_ids {
                v.extend(track_id.to_be_bytes());
            }

            Ok(())
        })?;
    }

    Ok(())
}

fn write_edts(
    v: &mut Vec<u8>,
    header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    write_full_box(v, b"elst", FULL_BOX_VERSION_1, 0, |v| {
        write_elst(v, header, stream)
    })?;

    Ok(())
}

fn write_elst(
    v: &mut Vec<u8>,
    header: &super::Header,
    stream: &super::Stream,
) -> Result<(), Error> {
    // In movie header timescale
    let timescale = header_to_timescale(header);

    let min_earliest_pts = header.streams.iter().map(|s| s.earliest_pts).min().unwrap();

    if min_earliest_pts != stream.earliest_pts {
        let gap = (stream.earliest_pts - min_earliest_pts)
            .nseconds()
            .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
            .context("too big gap")?;

        if gap > 0 {
            // Entry count
            v.extend(2u32.to_be_bytes());

            // First entry for the gap

            // Edit duration
            v.extend(gap.to_be_bytes());

            // Media time
            v.extend((-1i64).to_be_bytes());

            // Media rate
            v.extend(1u16.to_be_bytes());
            v.extend(0u16.to_be_bytes());
        } else {
            // Entry count
            v.extend(1u32.to_be_bytes());
        }
    } else {
        // Entry count
        v.extend(1u32.to_be_bytes());
    }

    // Edit duration
    let duration = (stream.end_pts - stream.earliest_pts)
        .nseconds()
        .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
        .context("too big track duration")?;
    v.extend(duration.to_be_bytes());

    // Media time
    if let Some(start_dts) = stream.start_dts {
        let shift = (gst::Signed::Positive(stream.earliest_pts) - start_dts)
            .nseconds()
            .positive()
            .unwrap_or(0)
            .mul_div_round(timescale as u64, gst::ClockTime::SECOND.nseconds())
            .context("too big track duration")?;

        v.extend(shift.to_be_bytes());
    } else {
        v.extend(0u64.to_be_bytes());
    }

    // Media rate
    v.extend(1u16.to_be_bytes());
    v.extend(0u16.to_be_bytes());

    Ok(())
}
