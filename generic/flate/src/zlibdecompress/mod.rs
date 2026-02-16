// Copyright (C) 2026 Collabora Ltd
//   @author: Daniel Morin <daniel.morin@collabora.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

/**
 * SECTION:element-zlibdecompress
 *
 * Decompress data compressed by the zlib algorithm.
 *
 * This element decompresses streams produced by `zlibcompress`. When the
 * compressed stream has `original-caps` (set by `zlibcompress`), the
 * srcpad caps are restored automatically without any out-of-band information.
 * When `original-caps` is absent, caps must be supplied downstream, for
 * example via a GDP depayloader or an explicit caps filter.
 *
 * Examples
 *
 * Using GDP (caps restored in-band)
 * ```text
 * filesrc location=/path/to/file ! zlibdecompress ! gdpdepay ! ...
 * filesrc location=/path/to/file ! gdpdepay ! zlibdecompress ! ...
 * ```text
 *
 * Without GDP (caps filter required)
 * ```text
 * filesrc location=/path/to/file ! zlibdecompress \
 *   ! "video/x-raw, format=RGB, width=320, height=240, framerate=30/1" ! ...
 * ```text
 *
 * Direct with zlibcompress (original-caps flow through automatically)
 * ```text
 * ... ! zlibcompress ! zlibdecompress ! ...
 * ```text
 *
 * See Also
 * `zlibcompress`
 */
use gst::glib;
use gst::prelude::*;

mod imp;

glib::wrapper! {
    pub struct ZlibDecompress(ObjectSubclass<imp::ZlibDecompress>) @extends gst_base::BaseTransform, gst::Element, gst::Object;
}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "zlibdecompress",
        gst::Rank::NONE,
        ZlibDecompress::static_type(),
    )
}
