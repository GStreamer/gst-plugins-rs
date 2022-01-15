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
    pub struct JsonGstParse(ObjectSubclass<imp::JsonGstParse>) @extends gst::Element, gst::Object;
}

unsafe impl Send for JsonGstParse {}
unsafe impl Sync for JsonGstParse {}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "jsongstparse",
        gst::Rank::Primary,
        JsonGstParse::static_type(),
    )
}
