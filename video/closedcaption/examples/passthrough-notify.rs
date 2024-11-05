// This example creates a pipeline that will decode a file, pipe its audio
// and video streams through transcriberbin, and display the result
// with closed captions overlaid.
//
// At first the (AWS) transcriber will not have its access keys set, which
// means it should automatically go to passthrough=true.
//
// At this point we set the access keys and disable passthrough again.
//
// The expected result is for the terminal to display
// "Access key set, disabling passthrough" and for closed captions to be
// overlaid over the video.

use anyhow::Error;
use clap::Parser;
use gst::glib;
use gst::prelude::*;

#[derive(Debug, Default, Clone, clap::Parser)]
struct Args {
    #[clap(long, help = "URI to transcribe")]
    pub uri: String,

    #[clap(long, help = "Access key ID")]
    pub access_key_id: String,

    #[clap(long, help = "Secret access key")]
    pub secret_access_key: String,
}

fn link_video_stream(
    pipeline: &gst::Pipeline,
    transcriberbin: &gst::Element,
    pad: &gst::Pad,
) -> Result<(), Error> {
    let conv = gst::ElementFactory::make("videoconvert").build()?;

    pipeline.add(&conv)?;

    conv.sync_state_with_parent()?;

    pad.link(&conv.static_pad("sink").unwrap())?;

    conv.link_pads(None, transcriberbin, Some("sink_video"))?;

    Ok(())
}

fn link_audio_stream(
    pipeline: &gst::Pipeline,
    transcriberbin: &gst::Element,
    pad: &gst::Pad,
) -> Result<(), Error> {
    let conv = gst::ElementFactory::make("audioconvert").build()?;

    pipeline.add(&conv)?;

    conv.sync_state_with_parent()?;

    pad.link(&conv.static_pad("sink").unwrap())?;

    conv.link_pads(None, transcriberbin, Some("sink_audio"))?;

    Ok(())
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    gst::init()?;

    let pipeline = gst::Pipeline::builder().build();

    let uridecodebin = gst::ElementFactory::make("uridecodebin")
        .property("uri", &args.uri)
        .build()?;
    let transcriberbin = gst::ElementFactory::make("transcriberbin").build()?;
    let asink = gst::ElementFactory::make("fakesink").build()?;
    let overlay = gst::ElementFactory::make("cea608overlay").build()?;
    let vconv = gst::ElementFactory::make("videoconvert").build()?;
    let vsink = gst::ElementFactory::make("autovideosink").build()?;

    uridecodebin.connect_pad_added(glib::clone!(
        #[weak]
        pipeline,
        #[weak]
        transcriberbin,
        move |_element, pad| {
            if pad
                .current_caps()
                .map(|c| c.structure(0).unwrap().name().starts_with("video/"))
                .unwrap_or(false)
            {
                link_video_stream(&pipeline, &transcriberbin, pad)
                    .expect("Failed to link video stream");
            } else {
                link_audio_stream(&pipeline, &transcriberbin, pad)
                    .expect("Failed to link audio stream");
            }
        }
    ));

    transcriberbin
        .static_pad("sink_audio")
        .unwrap()
        .connect_closure(
            "notify::passthrough",
            false,
            glib::closure!(
                #[strong]
                args,
                move |pad: &gst::Pad, _pspec: &gst::glib::ParamSpec| {
                    let passthrough = pad.property::<bool>("passthrough");
                    if passthrough {
                        let transcriber = pad.property::<gst::Element>("transcriber");
                        transcriber.set_property("access-key", &args.access_key_id);
                        transcriber.set_property("secret-access-key", &args.secret_access_key);

                        eprintln!(
                            "Access key set, disabling passthrough, transcriber state: {:?}",
                            transcriber.state(gst::ClockTime::NONE)
                        );

                        pad.set_property("passthrough", false);
                    }
                }
            ),
        );

    pipeline.add_many([
        &uridecodebin,
        &transcriberbin,
        &asink,
        &overlay,
        &vconv,
        &vsink,
    ])?;

    transcriberbin.link_pads(Some("src_audio"), &asink, None)?;
    transcriberbin.link_pads(Some("src_video"), &overlay, None)?;

    gst::Element::link_many([&overlay, &vconv, &vsink])?;

    pipeline.set_state(gst::State::Playing)?;

    let bus = pipeline.bus().expect("Pipeline should have a bus");

    for msg in bus.iter_timed(gst::ClockTime::NONE) {
        use gst::MessageView;

        match msg.view() {
            MessageView::Eos(..) => {
                println!("EOS");
                break;
            }
            MessageView::StateChanged(sc) => {
                if msg.src() == Some(pipeline.upcast_ref()) {
                    pipeline.debug_to_dot_file(
                        gst::DebugGraphDetails::all(),
                        format!("{}-{:?}-{:?}", pipeline.name(), sc.old(), sc.current()),
                    );
                }
            }
            MessageView::Error(err) => {
                pipeline.debug_to_dot_file(gst::DebugGraphDetails::ALL, "error");
                pipeline.set_state(gst::State::Null)?;
                eprintln!(
                    "Got error from {}: {} ({})",
                    msg.src()
                        .map(|s| String::from(s.path_string()))
                        .unwrap_or_else(|| "None".into()),
                    err.error(),
                    err.debug().unwrap_or_else(|| "".into()),
                );
                break;
            }
            _ => (),
        }
    }

    pipeline.set_state(gst::State::Null)?;

    Ok(())
}
