// Copyright (C) 2021 Mathieu Duponchelle <mathieu@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

// Example command-line:
//
// gst-launch-1.0 filesrc location=animated.webp ! webpdec-rs ! videoconvert ! autovideosink

use gst::glib;
use gst::prelude::*;

mod imp;

glib::wrapper! {
    pub struct WebPDec(ObjectSubclass<imp::WebPDec>) @extends gst::Element, gst::Object;
}

// GStreamer elements need to be thread-safe. For the private implementation this is automatically
// enforced but for the public wrapper type we need to specify this manually.
unsafe impl Send for WebPDec {}
unsafe impl Sync for WebPDec {}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "webpdec-rs",
        gst::Rank::Primary,
        WebPDec::static_type(),
    )
}
