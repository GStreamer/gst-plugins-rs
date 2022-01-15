// Copyright (C) 2017,2018 Sebastian Dröge <sebastian@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::glib;
use gst::prelude::*;

mod imp;
mod ring_buffer;

glib::wrapper! {
    pub struct AudioEcho(ObjectSubclass<imp::AudioEcho>) @extends gst_base::BaseTransform, gst::Element, gst::Object;
}

unsafe impl Send for AudioEcho {}
unsafe impl Sync for AudioEcho {}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "rsaudioecho",
        gst::Rank::None,
        AudioEcho::static_type(),
    )
}
