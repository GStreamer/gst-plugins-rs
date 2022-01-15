// Copyright (C) 2017 Author: Arun Raghavan <arun@arunraghavan.net>
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
    pub struct S3Src(ObjectSubclass<imp::S3Src>) @extends gst_base::BaseSrc, gst::Element, gst::Object;
}

unsafe impl Send for S3Src {}
unsafe impl Sync for S3Src {}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "rusotos3src",
        gst::Rank::Primary,
        S3Src::static_type(),
    )
}
