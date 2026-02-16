// Copyright (C) 2026 Collabora Ltd
//   @author: Daniel Morin <daniel.morin@collabora.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0

#![allow(clippy::non_send_fields_in_send_ty, unused_doc_comments)]

/**
 * plugin-flate:
 *
 * Since: plugins-rs-0.16
 */
use gst::glib;

mod zlibcompress;
mod zlibdecompress;

fn plugin_init(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    zlibcompress::register(plugin)?;
    zlibdecompress::register(plugin)?;
    Ok(())
}

gst::plugin_define!(
    flate,
    env!("CARGO_PKG_DESCRIPTION"),
    plugin_init,
    concat!(env!("CARGO_PKG_VERSION"), "-", env!("COMMIT_ID")),
    "MPL-2.0",
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_REPOSITORY"),
    env!("BUILD_REL_DATE")
);
