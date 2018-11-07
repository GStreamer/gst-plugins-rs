// Copyright (C) 2016-2017 Sebastian Dröge <sebastian@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![crate_type = "cdylib"]

#[macro_use]
extern crate gst_plugin;
extern crate gst_plugin_simple;
#[macro_use]
extern crate gstreamer as gst;
extern crate url;

use gst_plugin_simple::sink::*;
use gst_plugin_simple::source::*;

mod filesink;
mod filesrc;

use filesink::FileSink;
use filesrc::FileSrc;

fn plugin_init(plugin: &gst::Plugin) -> bool {
    source_register(
        plugin,
        SourceInfo {
            name: "rsfilesrc".into(),
            long_name: "File Source".into(),
            description: "Reads local files".into(),
            classification: "Source/File".into(),
            author: "Sebastian Dröge <sebastian@centricular.com>".into(),
            rank: 256 + 100,
            create_instance: FileSrc::new_boxed,
            protocols: vec!["file".into()],
            push_only: false,
        },
    );

    sink_register(
        plugin,
        SinkInfo {
            name: "rsfilesink".into(),
            long_name: "File Sink".into(),
            description: "Writes to local files".into(),
            classification: "Sink/File".into(),
            author: "Luis de Bethencourt <luisbg@osg.samsung.com>".into(),
            rank: 256 + 100,
            create_instance: FileSink::new_boxed,
            protocols: vec!["file".into()],
        },
    );

    true
}

plugin_define!(
    b"rsfile\0",
    b"Rust File Plugin\0",
    plugin_init,
    b"1.0\0",
    b"MIT/X11\0",
    b"rsfile\0",
    b"rsfile\0",
    b"https://gitlab.freedesktop.org/gstreamer/gst-plugin-rs\0",
    b"2016-12-08\0"
);
