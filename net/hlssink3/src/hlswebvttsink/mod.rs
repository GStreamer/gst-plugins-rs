// Copyright (C) 2026 Seungha Yang <seungha@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0
#![allow(clippy::non_send_fields_in_send_ty, unused_doc_comments)]

use crate::HlsBaseSink;
use gst::glib;
use gst::prelude::*;

mod imp;

glib::wrapper! {
    pub struct HlsWebvttSink(ObjectSubclass<imp::HlsWebvttSink>) @extends HlsBaseSink, gst::Bin, gst::Element, gst::Object;
}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "hlswebvttsink",
        gst::Rank::NONE,
        HlsWebvttSink::static_type(),
    )?;

    Ok(())
}
