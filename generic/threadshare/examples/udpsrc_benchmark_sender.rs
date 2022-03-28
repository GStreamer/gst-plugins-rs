// Copyright (C) 2018 Sebastian Dröge <sebastian@centricular.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Library General Public
// License as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Library General Public License for more details.
//
// You should have received a copy of the GNU Library General Public
// License along with this library; if not, write to the
// Free Software Foundation, Inc., 51 Franklin Street, Suite 500,
// Boston, MA 02110-1335, USA.
//
// SPDX-License-Identifier: LGPL-2.1-or-later

use std::net;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{env, thread, time};

fn main() {
    let args = env::args().collect::<Vec<_>>();
    assert!(args.len() > 1);
    let n_streams: u16 = args[1].parse().unwrap();

    if args.len() > 2 && args[2] == "rtp" {
        send_rtp_buffers(n_streams);
    } else {
        send_raw_buffers(n_streams);
    }
}

fn send_raw_buffers(n_streams: u16) {
    let buffer = [0; 160];
    let socket = net::UdpSocket::bind("0.0.0.0:0").unwrap();

    let ipaddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let destinations = (40000..(40000 + n_streams))
        .map(|port| SocketAddr::new(ipaddr, port))
        .collect::<Vec<_>>();

    let wait = time::Duration::from_millis(20);

    thread::sleep(time::Duration::from_millis(1000));

    loop {
        let now = time::Instant::now();

        for dest in &destinations {
            socket.send_to(&buffer, dest).unwrap();
        }

        let elapsed = now.elapsed();
        if elapsed < wait {
            thread::sleep(wait - elapsed);
        }
    }
}

fn send_rtp_buffers(n_streams: u16) {
    use gst::glib;
    use gst::prelude::*;

    gst::init().unwrap();

    #[cfg(debug_assertions)]
    {
        use std::path::Path;

        let mut path = Path::new("target/debug");
        if !path.exists() {
            path = Path::new("../../target/debug");
        }

        gst::Registry::get().scan_path(path);
    }
    #[cfg(not(debug_assertions))]
    {
        use std::path::Path;

        let mut path = Path::new("target/release");
        if !path.exists() {
            path = Path::new("../../target/release");
        }

        gst::Registry::get().scan_path(path);
    }

    let l = glib::MainLoop::new(None, false);
    let pipeline = gst::Pipeline::new(None);
    for i in 0..n_streams {
        let src =
            gst::ElementFactory::make("audiotestsrc", Some(format!("audiotestsrc-{}", i).as_str()))
                .unwrap();
        src.set_property("is-live", true);

        let enc =
            gst::ElementFactory::make("alawenc", Some(format!("alawenc-{}", i).as_str())).unwrap();
        let pay =
            gst::ElementFactory::make("rtppcmapay", Some(format!("rtppcmapay-{}", i).as_str()))
                .unwrap();
        let sink = gst::ElementFactory::make("ts-udpsink", Some(format!("udpsink-{}", i).as_str()))
            .unwrap();
        sink.set_property("clients", format!("127.0.0.1:{}", i + 40000));
        sink.set_property("context", "context-udpsink");
        sink.set_property("context-wait", 20u32);

        let elements = &[&src, &enc, &pay, &sink];
        pipeline.add_many(elements).unwrap();
        gst::Element::link_many(elements).unwrap();
    }

    pipeline.set_state(gst::State::Playing).unwrap();
    l.run();
}
