// Copyright (C) 2016-2017 Sebastian Dröge <sebastian@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT/Apache-2.0
#![allow(clippy::non_send_fields_in_send_ty)]

use gst::glib;

mod file_location;
mod filesink;
mod filesrc;

fn plugin_init(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    filesink::register(plugin)?;
    filesrc::register(plugin)?;
    Ok(())
}

gst::plugin_define!(
    rsfile,
    env!("CARGO_PKG_DESCRIPTION"),
    plugin_init,
    concat!(env!("CARGO_PKG_VERSION"), "-", env!("COMMIT_ID")),
    "MIT/X11",
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_REPOSITORY"),
    env!("BUILD_REL_DATE")
);
