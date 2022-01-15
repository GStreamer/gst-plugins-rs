// Copyright (C) 2020 Markus Ebner <info@ebner-markus.de>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use gst::prelude::*;

const ENCODE_PIPELINE: &str = "videotestsrc is-live=false num-buffers=100 ! videoconvert ! gifenc ! filesink location=test.gif";

fn main() {
    gst::init().unwrap();
    gstgif::plugin_register_static().expect("Failed to register gif plugin");

    let pipeline = gst::parse_launch(ENCODE_PIPELINE).unwrap();
    let bus = pipeline.bus().unwrap();

    pipeline
        .set_state(gst::State::Playing)
        .expect("Failed to set pipeline state to playing");

    for msg in bus.iter_timed(gst::ClockTime::NONE) {
        use gst::MessageView;

        match msg.view() {
            MessageView::Eos(..) => break,
            MessageView::Error(err) => {
                println!(
                    "Error from {:?}: {} ({:?})",
                    err.src().map(|s| s.path_string()),
                    err.error(),
                    err.debug()
                );
                break;
            }
            _ => (),
        }
    }
    pipeline
        .set_state(gst::State::Null)
        .expect("Failed to set pipeline state to null");
}
