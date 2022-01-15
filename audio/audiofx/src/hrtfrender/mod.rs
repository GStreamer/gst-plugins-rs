// Copyright (C) 2021 Tomasz Andrzejak <andreiltd@gmail.com>
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
    pub struct HrtfRender(ObjectSubclass<imp::HrtfRender>) @extends gst_base::BaseTransform, gst::Element, gst::Object;
}

unsafe impl Send for HrtfRender {}
unsafe impl Sync for HrtfRender {}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "hrtfrender",
        gst::Rank::None,
        HrtfRender::static_type(),
    )
}
