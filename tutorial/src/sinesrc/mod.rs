// Copyright (C) 2020 Sebastian Dröge <sebastian@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT/Apache-2.0

use gst::glib;
use gst::prelude::*;

mod imp;

// The public Rust wrapper type for our element
glib::wrapper! {
    pub struct SineSrc(ObjectSubclass<imp::SineSrc>) @extends gst_base::BaseSrc, gst::Element, gst::Object;
}

// GStreamer elements need to be thread-safe. For the private implementation this is automatically
// enforced but for the public wrapper type we need to specify this manually.
unsafe impl Send for SineSrc {}
unsafe impl Sync for SineSrc {}

// Registers the type for our element, and then registers in GStreamer under
// the name "sinesrc" for being able to instantiate it via e.g.
// gst::ElementFactory::make().
pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "rssinesrc",
        gst::Rank::None,
        SineSrc::static_type(),
    )
}
