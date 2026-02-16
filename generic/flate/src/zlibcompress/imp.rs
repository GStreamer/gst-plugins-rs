// Copyright (C) 2026 Collabora Ltd
//   @author: Daniel Morin <daniel.morin@collabora.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::glib;
use gst::prelude::*;
use gst::subclass::prelude::*;
use gst_base::subclass::prelude::*;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::{Cursor, Write};
use std::sync::LazyLock;
use std::sync::Mutex;

static CAT: LazyLock<gst::DebugCategory> = LazyLock::new(|| {
    gst::DebugCategory::new(
        "zlibcompress",
        gst::DebugColorFlags::empty(),
        Some("Zlib Compressor Element"),
    )
});

const DEFAULT_COMPRESSION_LEVEL: u32 = 6;

#[derive(Debug, Clone, Copy)]
struct Settings {
    compression_level: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            compression_level: DEFAULT_COMPRESSION_LEVEL,
        }
    }
}

#[derive(Default)]
pub struct ZlibCompress {
    settings: Mutex<Settings>,
}

impl ZlibCompress {
    fn compress_data(data: &[u8], level: u32, out: &mut [u8]) -> Result<usize, std::io::Error> {
        // ZlibEncoder will use Cursor::write to write compressed data to `out` which is done as
        // part of `write_all()` bellow.
        //
        // From the 'Write' trait: "A return value of Ok(0) typically means that the underlying
        // object is no longer able to accept bytes and will likely not be able to in the future
        // as well, or that the buffer provided is empty."
        //
        // `write_all()`, from Write trait, detect this specific Result value and return Err(Error::WRITE_ALL_EOF)
        // when it happen, which compress_data return to caller.
        // https://doc.rust-lang.org/nightly/src/std/io/mod.rs.html#1878-1880
        let mut encoder = ZlibEncoder::new(Cursor::new(out), Compression::new(level.min(9)));
        encoder.write_all(data)?;
        Ok(encoder.finish()?.position() as usize)
    }
}

#[glib::object_subclass]
impl ObjectSubclass for ZlibCompress {
    const NAME: &'static str = "GstZlibCompress";
    type Type = super::ZlibCompress;
    type ParentType = gst_base::BaseTransform;
}

impl ObjectImpl for ZlibCompress {
    fn properties() -> &'static [glib::ParamSpec] {
        static PROPERTIES: LazyLock<Vec<glib::ParamSpec>> = LazyLock::new(|| {
            vec![
                glib::ParamSpecUInt::builder("level")
                    .nick("Compression Level")
                    .blurb("Compression level (0=fast, 9=best)")
                    .minimum(0)
                    .maximum(9)
                    .default_value(DEFAULT_COMPRESSION_LEVEL)
                    .mutable_playing()
                    .build(),
            ]
        });
        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        match pspec.name() {
            "level" => {
                let mut settings = self.settings.lock().unwrap();
                settings.compression_level = value.get().expect("Invalid value");
                gst::debug!(
                    CAT,
                    imp = self,
                    "Compression level changed to {len}",
                    len = settings.compression_level
                );
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        match pspec.name() {
            "level" => self.settings.lock().unwrap().compression_level.to_value(),
            _ => unimplemented!(),
        }
    }
}

impl GstObjectImpl for ZlibCompress {}

impl ElementImpl for ZlibCompress {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: LazyLock<gst::subclass::ElementMetadata> = LazyLock::new(|| {
            gst::subclass::ElementMetadata::new(
                "Zlib Compressor",
                "Encoder/Generic",
                "Compress data using zlib",
                "Daniel Morin <daniel.morin@collabora.com>",
            )
        });
        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: LazyLock<Vec<gst::PadTemplate>> = LazyLock::new(|| {
            let sink_caps = gst::Caps::new_any();
            let sink_pad_template = gst::PadTemplate::new(
                "sink",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &sink_caps,
            )
            .unwrap();

            // Template caps without original-caps field. 'original-caps' will
            // be added during negotiation.
            let src_caps = gst::Caps::builder("application/x-zlib-compressed").build();
            let src_pad_template = gst::PadTemplate::new(
                "src",
                gst::PadDirection::Src,
                gst::PadPresence::Always,
                &src_caps,
            )
            .unwrap();

            vec![sink_pad_template, src_pad_template]
        });
        PAD_TEMPLATES.as_ref()
    }
}

impl BaseTransformImpl for ZlibCompress {
    const MODE: gst_base::subclass::BaseTransformMode =
        gst_base::subclass::BaseTransformMode::NeverInPlace;
    const PASSTHROUGH_ON_SAME_CAPS: bool = false;
    const TRANSFORM_IP_ON_PASSTHROUGH: bool = false;

    fn transform_caps(
        &self,
        direction: gst::PadDirection,
        caps: &gst::Caps,
        filter: Option<&gst::Caps>,
    ) -> Option<gst::Caps> {
        let other_caps = match direction {
            gst::PadDirection::Sink => {
                if caps.is_any() {
                    gst::Caps::builder("application/x-zlib-compressed").build()
                } else {
                    // Embed the upstream caps directly as a GstCaps-typed field.
                    gst::Caps::builder("application/x-zlib-compressed")
                        .field("original-caps", caps)
                        .build()
                }
            }
            gst::PadDirection::Src => {
                if caps.is_any() {
                    gst::Caps::new_any()
                } else {
                    // Handle cases where downstream has caps with multiple
                    // original-caps possibilities to propagate them upstream.
                    let recovered = caps
                        .iter()
                        .filter_map(|s| s.get::<gst::Caps>("original-caps").ok())
                        .fold(gst::Caps::new_empty(), |mut acc, c| {
                            acc.get_mut().unwrap().append(c);
                            acc
                        });
                    if recovered.is_empty() {
                        gst::Caps::new_any()
                    } else {
                        recovered
                    }
                }
            }
            _ => return None,
        };

        gst::debug!(
            CAT,
            imp = self,
            "Transformed caps from {caps} to {other_caps} in direction {direction:?}"
        );

        if let Some(f) = filter {
            Some(f.intersect_with_mode(&other_caps, gst::CapsIntersectMode::First))
        } else {
            Some(other_caps)
        }
    }

    fn transform_size(
        &self,
        _direction: gst::PadDirection,
        _caps: &gst::Caps,
        size: usize,
        _othercaps: &gst::Caps,
    ) -> Option<usize> {
        // Conservative worst-case upper bound for zlib output.
        Some(size + (size / 10) + 1024)
    }

    fn transform(
        &self,
        inbuf: &gst::Buffer,
        outbuf: &mut gst::BufferRef,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let level = self.settings.lock().unwrap().compression_level;

        let inmap = inbuf.map_readable().map_err(|_| {
            gst::error!(CAT, imp = self, "Failed to map input buffer readable");
            gst::FlowError::Error
        })?;

        // outbuf is pre-allocated by transform_size, compress directly into it and shrink.
        let mut outmap = outbuf.map_writable().map_err(|_| {
            gst::error!(CAT, imp = self, "Failed to map output buffer writable");
            gst::FlowError::Error
        })?;

        // Outmap is pre-allocated to a conservative upper bound of uncompressed size +
        // (10% of uncompressed size) + 1024 in `transform_size()`. In the unlikely
        // event that compress_data() fails, it returns a std::io::Error that is
        // mapped below to a gst::FlowError::Error and logged.
        let written = Self::compress_data(&inmap, level, &mut outmap).map_err(|err| {
            gst::error!(CAT, imp = self, "Compression failed: {err}");
            gst::FlowError::Error
        })?;

        gst::trace!(
            CAT,
            imp = self,
            "Compressed {len} → {written} bytes ({ratio:.1}%)",
            len = inmap.len(),
            ratio = written as f64 / inmap.len().max(1) as f64 * 100.0,
        );

        drop(outmap);
        outbuf.set_size(written);

        Ok(gst::FlowSuccess::Ok)
    }

    fn src_event(&self, event: gst::Event) -> bool {
        match event.view() {
            gst::EventView::Seek(_) => {
                gst::debug!(CAT, imp = self, "Refusing seek event on compressed stream");
                false
            }
            _ => self.parent_src_event(event),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify that compress_data returns an error when the output buffer is too
    // small to hold the compressed result.
    #[test]
    fn test_compress_data_output_too_small() {
        let data = vec![0u8; 1024];
        let mut out = vec![0u8; 1];
        let result = ZlibCompress::compress_data(&data, 6, &mut out);
        assert!(
            result.is_err(),
            "compress_data must fail when output buffer is too small"
        );
    }
}
