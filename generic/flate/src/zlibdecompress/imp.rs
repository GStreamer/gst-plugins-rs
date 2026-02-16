// Copyright (C) 2026 Collabora Ltd
//   @author: Daniel Morin <daniel.morin@collabora.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::glib;
use gst::subclass::prelude::*;
use gst_base::subclass::prelude::*;

use std::sync::LazyLock;
use std::sync::Mutex;

static CAT: LazyLock<gst::DebugCategory> = LazyLock::new(|| {
    gst::DebugCategory::new(
        "zlibdecompress",
        gst::DebugColorFlags::empty(),
        Some("Zlib Decompressor Element"),
    )
});

struct State {
    // Accumulates bytes from upstream across buffer boundaries.
    // We need to support arbitrary-sized chunks that
    // do not align with zlib stream boundaries.
    adapter: gst_base::UniqueAdapter,
}

impl Default for State {
    fn default() -> Self {
        State {
            adapter: gst_base::UniqueAdapter::new(),
        }
    }
}

pub struct ZlibDecompress {
    state: Mutex<State>,
}

impl Default for ZlibDecompress {
    fn default() -> Self {
        ZlibDecompress {
            state: Mutex::new(State::default()),
        }
    }
}

impl ZlibDecompress {
    // Returns:
    //   Ok(Some((decompressed, consumed))) — a complete stream was found;
    //       `consumed` bytes were used from the front of `data` (may be less
    //       than data.len() when data spans multiple streams).
    //   Ok(None)  — not enough data, caller should accumulate more bytes.
    //   Err(_)    — corrupt stream, pipeline should error.
    fn try_decompress(data: &[u8]) -> Result<Option<(Vec<u8>, usize)>, gst::FlowError> {
        let mut decomp = flate2::Decompress::new(true);

        // Pre-allocate
        let mut output = Vec::with_capacity(data.len() * 4);

        loop {
            let in_pos = decomp.total_in() as usize;
            let out_pos = decomp.total_out() as usize;

            if output.len() == out_pos {
                output.resize(out_pos + 65536, 0);
            }

            let status = decomp
                .decompress(
                    &data[in_pos..],
                    &mut output[out_pos..],
                    flate2::FlushDecompress::None,
                )
                .map_err(|_| gst::FlowError::Error)?;

            let new_in_pos = decomp.total_in() as usize;

            match status {
                flate2::Status::StreamEnd => {
                    output.truncate(decomp.total_out() as usize);
                    return Ok(Some((output, new_in_pos)));
                }
                flate2::Status::Ok | flate2::Status::BufError => {
                    if new_in_pos == in_pos {
                        // Need more data
                        return Ok(None);
                    }
                }
            }
        }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for ZlibDecompress {
    const NAME: &'static str = "GstZlibDecompress";
    type Type = super::ZlibDecompress;
    type ParentType = gst_base::BaseTransform;
}

impl ObjectImpl for ZlibDecompress {}

impl GstObjectImpl for ZlibDecompress {}

impl ElementImpl for ZlibDecompress {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static ELEMENT_METADATA: LazyLock<gst::subclass::ElementMetadata> = LazyLock::new(|| {
            gst::subclass::ElementMetadata::new(
                "Zlib Decompressor",
                "Decoder/Generic",
                "Decompress data using zlib",
                "Daniel Morin <daniel.morin@collabora.com>",
            )
        });
        Some(&*ELEMENT_METADATA)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static PAD_TEMPLATES: LazyLock<Vec<gst::PadTemplate>> = LazyLock::new(|| {
            let sink_caps = gst::Caps::builder_full()
                .structure(gst::Structure::builder("application/x-zlib-compressed").build())
                .build();
            let sink_pad_template = gst::PadTemplate::new(
                "sink",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &sink_caps,
            )
            .unwrap();

            // ANY: srcpad caps are determined at runtime from original-caps field,
            // or resolved by downstream negotiation when original-caps is absent.
            let src_caps = gst::Caps::new_any();
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

impl BaseTransformImpl for ZlibDecompress {
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
                let original = caps
                    .structure(0)
                    .and_then(|s| s.get::<gst::Caps>("original-caps").ok());

                match original {
                    Some(c) => {
                        gst::debug!(CAT, imp = self, "Srcpad caps from original-caps: {c}");
                        c
                    }
                    None => {
                        gst::debug!(
                            CAT,
                            imp = self,
                            "No original-caps in sinkpad caps; srcpad remains ANY"
                        );
                        gst::Caps::new_any()
                    }
                }
            }
            gst::PadDirection::Src => {
                if caps.is_any() {
                    gst::Caps::builder("application/x-zlib-compressed").build()
                } else {
                    gst::Caps::builder("application/x-zlib-compressed")
                        .field("original-caps", caps)
                        .build()
                }
            }
            _ => return None,
        };

        gst::debug!(
            CAT,
            imp = self,
            "Transformed caps from {caps} to {other_caps} in direction {direction:?}",
        );

        if let Some(f) = filter {
            Some(f.intersect_with_mode(&other_caps, gst::CapsIntersectMode::First))
        } else {
            Some(other_caps)
        }
    }

    fn stop(&self) -> Result<(), gst::ErrorMessage> {
        self.state.lock().unwrap().adapter.clear();
        Ok(())
    }

    // Push the incoming buffer into the adapter.
    // On discontinuity, clear any accumulated bytes first to avoid
    // attempting to decompress across a stream boundary.
    //
    // We check the buffer's DISCONT flag rather than the `is_discont`
    // parameter from BaseTransform.  BaseTransform keeps its internal
    // `priv->discont` set to TRUE until a buffer is actually pushed downstream,
    // so when our decompressor returns NoOutput while accumulating partial
    // data every subsequent chunk is reported as discont — causing the adapter
    // to be cleared on each chunk and breaking multi-chunk reassembly.
    fn submit_input_buffer(
        &self,
        _is_discont: bool,
        inbuf: gst::Buffer,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let mut state = self.state.lock().unwrap();
        if inbuf.flags().contains(gst::BufferFlags::DISCONT) {
            gst::debug!(CAT, imp = self, "Discontinuity: clearing adapter");
            state.adapter.clear();
        }
        state.adapter.push(inbuf);
        Ok(gst::FlowSuccess::Ok)
    }

    // Try to decompress one complete zlib stream from the adapter.
    // BaseTransform calls this in a loop until NoOutput is returned, so if
    // the adapter contains multiple complete streams , all are decompressed in
    // sequence without waiting for new input.
    fn generate_output(
        &self,
    ) -> Result<gst_base::subclass::base_transform::GenerateOutputSuccess, gst::FlowError> {
        use gst_base::subclass::base_transform::GenerateOutputSuccess;

        let mut state = self.state.lock().unwrap();

        let available = state.adapter.available();
        if available == 0 {
            return Ok(GenerateOutputSuccess::NoOutput);
        }

        let data_map = state.adapter.map(available).map_err(|_| {
            gst::error!(CAT, imp = self, "Failed to map adapter data");
            gst::FlowError::Error
        })?;

        match Self::try_decompress(&data_map).inspect_err(|_| {
            gst::error!(CAT, imp = self, "Decompression error: corrupted stream");
        })? {
            Some((decompressed, consumed)) => {
                drop(data_map);

                // Peek at the source buffer before flushing to copy attached metas and timing.
                let src_buf = state.adapter.buffer_fast(consumed).ok();

                // Capture timing of the consumed range before flushing.
                let (pts, _) = state.adapter.prev_pts_at_offset(0);
                let (dts, _) = state.adapter.prev_dts_at_offset(0);
                let duration = src_buf.as_ref().and_then(|b| b.duration());
                state.adapter.flush(consumed);

                gst::trace!(
                    CAT,
                    imp = self,
                    "Decompressed {len} bytes (consumed {consumed} of {available} available)",
                    len = decompressed.len(),
                );

                let mut outbuf = gst::Buffer::from_mut_slice(decompressed);
                {
                    let outbuf = outbuf.get_mut().unwrap();
                    outbuf.set_pts(pts);
                    outbuf.set_dts(dts);
                    outbuf.set_duration(duration);
                    if let Some(src) = src_buf
                        && let Err(e) = src.copy_into(outbuf, gst::BufferCopyFlags::META, ..)
                    {
                        gst::debug!(CAT, imp = self, "Could not copy buffer metas: {e}");
                    }
                }

                Ok(GenerateOutputSuccess::Buffer(outbuf))
            }
            None => {
                gst::trace!(
                    CAT,
                    imp = self,
                    "Incomplete stream ({available} bytes available), waiting for more data"
                );
                Ok(GenerateOutputSuccess::NoOutput)
            }
        }
    }

    fn sink_event(&self, event: gst::Event) -> bool {
        if let gst::EventView::FlushStop(_) = event.view() {
            gst::debug!(CAT, imp = self, "flush-stop event: clearing adapter");
            self.state.lock().unwrap().adapter.clear();
        }
        self.parent_sink_event(event)
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
