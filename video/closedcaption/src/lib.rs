// Copyright (C) 2018 Sebastian Dröge <sebastian@centricular.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// <https://mozilla.org/MPL/2.0/>.
//
// SPDX-License-Identifier: MPL-2.0
#![allow(clippy::non_send_fields_in_send_ty)]
#![recursion_limit = "128"]

use gst::glib;

#[allow(non_camel_case_types, non_upper_case_globals, unused)]
#[allow(clippy::redundant_static_lifetimes, clippy::unreadable_literal)]
#[allow(clippy::useless_transmute, clippy::trivially_copy_pass_by_ref)]
mod ffi;

mod caption_frame;
mod ccdetect;
mod ccutils;
mod cea608overlay;
mod cea608tojson;
mod cea608tott;
mod jsontovtt;
mod line_reader;
mod mcc_enc;
mod mcc_parse;
mod parser_utils;
mod scc_enc;
mod scc_parse;
mod transcriberbin;
mod tttocea608;
mod tttojson;
mod ttutils;

fn plugin_init(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    mcc_parse::register(plugin)?;
    mcc_enc::register(plugin)?;
    scc_parse::register(plugin)?;
    scc_enc::register(plugin)?;
    cea608tott::register(plugin)?;
    tttocea608::register(plugin)?;
    cea608overlay::register(plugin)?;
    ccdetect::register(plugin)?;
    tttojson::register(plugin)?;
    cea608tojson::register(plugin)?;
    jsontovtt::register(plugin)?;
    transcriberbin::register(plugin)?;
    Ok(())
}

gst::plugin_define!(
    rsclosedcaption,
    env!("CARGO_PKG_DESCRIPTION"),
    plugin_init,
    concat!(env!("CARGO_PKG_VERSION"), "-", env!("COMMIT_ID")),
    // FIXME: MPL-2.0 is only allowed since 1.18.3 (as unknown) and 1.20 (as known)
    "MPL",
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_REPOSITORY"),
    env!("BUILD_REL_DATE")
);
