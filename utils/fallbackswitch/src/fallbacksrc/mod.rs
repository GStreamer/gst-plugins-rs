// Copyright (C) 2020 Sebastian Dröge <sebastian@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

use gst::glib;
use gst::prelude::*;

mod custom_source;
mod imp;
mod video_fallback;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy, glib::Enum)]
#[repr(u32)]
#[enum_type(name = "GstFallbackSourceRetryReason")]
enum RetryReason {
    None,
    Error,
    Eos,
    StateChangeFailure,
    Timeout,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy, glib::Enum)]
#[repr(u32)]
#[enum_type(name = "GstFallbackSourceStatus")]
enum Status {
    Stopped,
    Buffering,
    Retrying,
    Running,
}

glib::wrapper! {
    pub struct FallbackSrc(ObjectSubclass<imp::FallbackSrc>) @extends gst::Bin, gst::Element, gst::Object;
}

// GStreamer elements need to be thread-safe. For the private implementation this is automatically
// enforced but for the public wrapper type we need to specify this manually.
unsafe impl Send for FallbackSrc {}
unsafe impl Sync for FallbackSrc {}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "fallbacksrc",
        gst::Rank::None,
        FallbackSrc::static_type(),
    )
}
