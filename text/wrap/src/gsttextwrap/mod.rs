// Copyright (C) 2020 Mathieu Duponchelle <mathieu@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::glib;
use gst::prelude::*;

mod imp;

glib::wrapper! {
    pub struct TextWrap(ObjectSubclass<imp::TextWrap>) @extends gst::Element, gst::Object;
}

unsafe impl Send for TextWrap {}
unsafe impl Sync for TextWrap {}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "textwrap",
        gst::Rank::None,
        TextWrap::static_type(),
    )
}
