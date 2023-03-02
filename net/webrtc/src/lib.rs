// SPDX-License-Identifier: MPL-2.0
#![allow(clippy::non_send_fields_in_send_ty, unused_doc_comments)]

/**
 * plugin-rswebrtc:
 *
 * Since: plugins-rs-0.9
 */
use gst::glib;

mod signaller;
pub mod utils;
pub mod webrtcsink;
pub mod webrtcsrc;

fn plugin_init(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    webrtcsink::register(plugin)?;
    webrtcsrc::register(Some(plugin))?;

    Ok(())
}

gst::plugin_define!(
    rswebrtc,
    env!("CARGO_PKG_DESCRIPTION"),
    plugin_init,
    concat!(env!("CARGO_PKG_VERSION"), "-", env!("COMMIT_ID")),
    "MPL-2.0",
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_REPOSITORY"),
    env!("BUILD_REL_DATE")
);
