// Copyright (C) 2026 Collabora Ltd
//   @author: Daniel Morin <daniel.morin@collabora.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

/**
 * SECTION:element-zlibcompress
 *
 * Compress data using the zlib algorithm.
 *
 * This element can compress any data stream. Unless the compressed stream will
 * be multiplexed into a container, using GStreamer Data Protocol (GDP) is
 * recommended to avoid the need for out-of-band signalling of caps after
 * decompression.
 *
 * The srcpad caps will be `application/x-zlib-compressed` with an
 * `original-caps` field carrying the sinkpad caps, allowing `zlibdecompress`
 * to restore the original caps without any out-of-band information.
 *
 * Examples
 *
 * Using GDP (caps preserved in-band)
 * ```text
 * ... ! zlibcompress ! gdppay ! filesink location=/path/to/file
 * ```text
 *
 * Without GDP (caps must be known downstream)
 * ```text
 * ... ! zlibcompress ! filesink location=/path/to/file
 * ... ! zlibcompress ! zlibdecompress ! ...
 * ```text
 *
 * See Also
 * `zlibdecompress`
 */
use gst::glib;
use gst::prelude::*;

mod imp;

glib::wrapper! {
    pub struct ZlibCompress(ObjectSubclass<imp::ZlibCompress>) @extends gst_base::BaseTransform, gst::Element, gst::Object;
}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "zlibcompress",
        gst::Rank::NONE,
        ZlibCompress::static_type(),
    )
}
