use gst::glib;
use once_cell::sync::Lazy;

mod args;
use args::*;

#[macro_use]
mod macros;

mod sink;
mod src;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "ts-standalone-main",
        gst::DebugColorFlags::empty(),
        Some("Thread-sharing standalone test main"),
    )
});

fn plugin_init(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    src::register(plugin)?;
    sink::async_mutex::register(plugin)?;
    sink::sync_mutex::register(plugin)?;
    sink::task::register(plugin)?;

    Ok(())
}

gst::plugin_define!(
    threadshare_standalone_test,
    env!("CARGO_PKG_DESCRIPTION"),
    plugin_init,
    concat!(env!("CARGO_PKG_VERSION"), "-", env!("COMMIT_ID")),
    "LGPL",
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_REPOSITORY"),
    env!("BUILD_REL_DATE")
);

fn main() {
    use gst::prelude::*;
    use std::time::Instant;

    gst::init().unwrap();
    self::plugin_register_static().unwrap();

    #[cfg(debug_assertions)]
    gst::warning!(CAT, "RUNNING DEBUG BUILD");

    let args = args();

    let pipeline = gst::Pipeline::default();

    for i in 0..args.streams {
        let ctx_name = format!("standalone {}", i % args.groups);

        let src = gst::ElementFactory::make(src::ELEMENT_NAME)
            .name(format!("src-{i}").as_str())
            .property("context", &ctx_name)
            .property("context-wait", args.wait)
            .property("push-period", args.push_period)
            .property("num-buffers", args.num_buffers)
            .build()
            .unwrap();

        let sink = gst::ElementFactory::make(args.sink.element_name())
            .name(format!("sink-{i}").as_str())
            .property("context", &ctx_name)
            .property("context-wait", args.wait)
            .build()
            .unwrap();

        if i == 0 {
            src.set_property("main-elem", true);
            sink.set_property("main-elem", true);

            if !args.disable_stats_log {
                // Don't use the last 5 secs in stats
                // otherwise we get outliers when reaching EOS.
                // Note that stats don't start before the 20 first seconds
                // and we get 50 buffers per sec.
                const BUFFERS_BEFORE_LOGS: i32 = 20 * 50;
                const BUFFERS_TO_SKIP: i32 = BUFFERS_BEFORE_LOGS + 5 * 50;
                if args.num_buffers > BUFFERS_TO_SKIP {
                    sink.set_property("push-period", args.push_period);
                    sink.set_property("logs-stats", true);
                    let max_buffers = args.num_buffers - BUFFERS_TO_SKIP;
                    sink.set_property("max-buffers", max_buffers);
                } else {
                    gst::warning!(CAT, "Not enough buffers to log, disabling stats");
                }
            }
        }

        let elements = &[&src, &sink];
        pipeline.add_many(elements).unwrap();
        gst::Element::link_many(elements).unwrap();
    }

    let l = glib::MainLoop::new(None, false);

    let bus = pipeline.bus().unwrap();
    let terminated_count = Arc::new(AtomicU32::new(0));
    let l_clone = l.clone();
    bus.add_watch(move |_, msg| {
        use gst::MessageView;
        match msg.view() {
            MessageView::Eos(_) => {
                // Actually, we don't post EOS (see sinks impl).
                gst::info!(CAT, "Received eos");
                l_clone.quit();

                glib::Continue(false)
            }
            MessageView::Error(msg) => {
                if let gst::MessageView::Error(msg) = msg.message().view() {
                    if msg.error().matches(gst::LibraryError::Shutdown) {
                        if terminated_count.fetch_add(1, Ordering::SeqCst) == args.streams - 1 {
                            gst::info!(CAT, "Received all shutdown requests");
                            l_clone.quit();

                            return glib::Continue(false);
                        } else {
                            return glib::Continue(true);
                        }
                    }
                }

                gst::error!(
                    CAT,
                    "Error from {:?}: {} ({:?})",
                    msg.src().map(|s| s.path_string()),
                    msg.error(),
                    msg.debug()
                );
                l_clone.quit();

                glib::Continue(false)
            }
            _ => glib::Continue(true),
        }
    })
    .expect("Failed to add bus watch");

    gst::info!(CAT, "Switching to Ready");
    let start = Instant::now();
    pipeline.set_state(gst::State::Ready).unwrap();
    gst::info!(CAT, "Switching to Ready took {:.2?}", start.elapsed());

    gst::info!(CAT, "Switching to Playing");
    let start = Instant::now();
    pipeline.set_state(gst::State::Playing).unwrap();
    gst::info!(CAT, "Switching to Playing took {:.2?}", start.elapsed());

    l.run();

    gst::info!(CAT, "Switching to Ready");
    let stop = Instant::now();
    pipeline.set_state(gst::State::Ready).unwrap();
    gst::info!(CAT, "Switching to Ready took {:.2?}", stop.elapsed());

    gst::info!(CAT, "Shutting down");
    let stop = Instant::now();
    pipeline.set_state(gst::State::Null).unwrap();
    gst::info!(CAT, "Shutting down took {:.2?}", stop.elapsed());
}
