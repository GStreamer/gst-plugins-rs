// Copyright (C) 2020 Markus Ebner <info@ebner-markus.de>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use atomic_refcell::AtomicRefCell;
use gif::SetParameter;
use glib::subclass;
use glib::subclass::prelude::*;
use gst::subclass::prelude::*;
use gst_video::prelude::*;
use gst_video::subclass::prelude::*;
use gstreamer_video as gst_video;
use once_cell::sync::Lazy;
use std::{
    io,
    io::Write,
    sync::{Arc, Mutex},
};

const DEFAULT_REPEAT: i32 = 0;

/// The gif::Encoder requires a std::io::Write implementation, to which it
/// can save the generated gif. This struct is used as a temporary cache, into
/// which the encoder can write encoded frames, such that we can read them back
/// and commit them to the gstreamer pipeline.
struct CacheBuffer {
    buffer: AtomicRefCell<Vec<u8>>,
}
impl CacheBuffer {
    pub fn new() -> Self {
        Self {
            buffer: AtomicRefCell::new(Vec::new()),
        }
    }
    pub fn clear(&self) {
        self.buffer.borrow_mut().clear();
    }
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut buffer = self.buffer.borrow_mut();
        buffer.write(buf)
    }
    pub fn consume(&self) -> Vec<u8> {
        let mut buffer = self.buffer.borrow_mut();
        std::mem::replace(&mut *buffer, Vec::new())
    }
}
/// Writer for a CacheBuffer instance. This class is passed to the gif::Encoder.
/// Everything written to the CacheBufferWriter is stored in the underlying CacheBuffer.
struct CacheBufferWriter {
    cache_buffer: Arc<CacheBuffer>,
}
impl CacheBufferWriter {
    pub fn new(cache_buffer: Arc<CacheBuffer>) -> Self {
        Self { cache_buffer }
    }
}
impl Write for CacheBufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.cache_buffer.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Settings {
    repeat: i32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            repeat: DEFAULT_REPEAT,
        }
    }
}

static PROPERTIES: [subclass::Property; 1] = [subclass::Property("repeat", |name| {
    glib::ParamSpec::int(
        name,
        "Repeat",
        "Repeat (-1 to loop forever, 0 .. n finite repetitions)",
        -1,
        std::u16::MAX as i32,
        DEFAULT_REPEAT,
        glib::ParamFlags::READWRITE,
    )
})];

struct State {
    video_info: gst_video::VideoInfo,
    cache: Arc<CacheBuffer>,
    gif_pts: Option<gst::ClockTime>,
    last_actual_pts: gst::ClockTime,
    context: Option<gif::Encoder<CacheBufferWriter>>,
}
impl State {
    pub fn new(video_info: gst_video::VideoInfo) -> Self {
        Self {
            video_info,
            cache: Arc::new(CacheBuffer::new()),
            gif_pts: None,
            last_actual_pts: gst::ClockTime::none(),
            context: None,
        }
    }
    pub fn reset(&mut self, settings: Settings) {
        self.cache.clear();
        self.gif_pts = None;
        self.last_actual_pts = gst::ClockTime::none();
        // initialize and configure encoder with a CacheBufferWriter pointing
        // to our CacheBuffer instance
        let mut encoder = gif::Encoder::new(
            CacheBufferWriter::new(self.cache.clone()),
            self.video_info.width() as u16,
            self.video_info.height() as u16,
            &[],
        )
        .expect("Failed to initialize GIF encoder");
        match settings.repeat {
            -1 => encoder.set(gif::Repeat::Infinite),
            _ => encoder.set(gif::Repeat::Finite(settings.repeat as u16)),
        }
        .expect("Failed to configure encoder");
        self.context = Some(encoder);
    }
}

struct GifEnc {
    state: AtomicRefCell<Option<State>>,
    settings: Mutex<Settings>,
}

static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new("gifenc", gst::DebugColorFlags::empty(), Some("GIF encoder"))
});

impl ObjectSubclass for GifEnc {
    const NAME: &'static str = "GifEnc";
    type ParentType = gst_video::VideoEncoder;
    type Instance = gst::subclass::ElementInstanceStruct<Self>;
    type Class = subclass::simple::ClassStruct<Self>;

    glib_object_subclass!();

    fn new() -> Self {
        Self {
            state: AtomicRefCell::new(None),
            settings: Mutex::new(Default::default()),
        }
    }

    fn class_init(klass: &mut subclass::simple::ClassStruct<Self>) {
        klass.set_metadata(
            "GIF encoder",
            "Encoder/Video",
            "GIF encoder",
            "Markus Ebner <info@ebner-markus.de>",
        );

        let sink_caps = gst::Caps::new_simple(
            "video/x-raw",
            &[
                (
                    "format",
                    &gst::List::new(&[
                        &gst_video::VideoFormat::Rgb.to_str(),
                        &gst_video::VideoFormat::Rgba.to_str(),
                    ]),
                ),
                ("width", &gst::IntRange::<i32>::new(1, std::u16::MAX as i32)),
                (
                    "height",
                    &gst::IntRange::<i32>::new(1, std::u16::MAX as i32),
                ),
                (
                    "framerate",
                    &gst::FractionRange::new(
                        gst::Fraction::new(1, 1),
                        // frame-delay timing in gif is a multiple of 10ms -> max 100fps
                        gst::Fraction::new(100, 1),
                    ),
                ),
            ],
        );
        let sink_pad_template = gst::PadTemplate::new(
            "sink",
            gst::PadDirection::Sink,
            gst::PadPresence::Always,
            &sink_caps,
        )
        .unwrap();
        klass.add_pad_template(sink_pad_template);

        let src_caps = gst::Caps::new_simple("image/gif", &[]);
        let src_pad_template = gst::PadTemplate::new(
            "src",
            gst::PadDirection::Src,
            gst::PadPresence::Always,
            &src_caps,
        )
        .unwrap();
        klass.add_pad_template(src_pad_template);

        klass.install_properties(&PROPERTIES);
    }
}

impl ObjectImpl for GifEnc {
    glib_object_impl!();

    fn set_property(&self, _obj: &glib::Object, id: usize, value: &glib::Value) {
        let prop = &PROPERTIES[id];

        match *prop {
            subclass::Property("repeat", ..) => {
                let mut settings = self.settings.lock().unwrap();
                settings.repeat = value.get_some().expect("type checked upstream");
            }
            _ => unimplemented!(),
        }
    }

    fn get_property(&self, _obj: &glib::Object, id: usize) -> Result<glib::Value, ()> {
        let prop = &PROPERTIES[id];

        match *prop {
            subclass::Property("repeat", ..) => {
                let settings = self.settings.lock().unwrap();
                Ok(settings.repeat.to_value())
            }
            _ => unimplemented!(),
        }
    }
}

impl ElementImpl for GifEnc {}

impl VideoEncoderImpl for GifEnc {
    fn stop(&self, _element: &gst_video::VideoEncoder) -> Result<(), gst::ErrorMessage> {
        *self.state.borrow_mut() = None;
        Ok(())
    }

    fn set_format(
        &self,
        element: &gst_video::VideoEncoder,
        state: &gst_video::VideoCodecState<'static, gst_video::video_codec_state::Readable>,
    ) -> Result<(), gst::LoggableError> {
        self.flush_encoder(element)
            .map_err(|_| gst_loggable_error!(CAT, "Failed to drain"))?;

        let video_info = state.get_info();
        gst_debug!(CAT, obj: element, "Setting format {:?}", video_info);

        {
            let mut state = State::new(video_info);
            let settings = self.settings.lock().unwrap();
            state.reset(*settings);
            *self.state.borrow_mut() = Some(state);
        }

        let output_state = element
            .set_output_state(gst::Caps::new_simple("image/gif", &[]), Some(state))
            .map_err(|_| gst_loggable_error!(CAT, "Failed to set output state"))?;
        element
            .negotiate(output_state)
            .map_err(|_| gst_loggable_error!(CAT, "Failed to negotiate"))?;

        self.parent_set_format(element, state)
    }

    fn finish(
        &self,
        element: &gst_video::VideoEncoder,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        self.flush_encoder(element)
    }

    fn handle_frame(
        &self,
        element: &gst_video::VideoEncoder,
        mut frame: gst_video::VideoCodecFrame,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let mut state_guard = self.state.borrow_mut();
        let state = state_guard.as_mut().ok_or(gst::FlowError::NotNegotiated)?;

        gst_debug!(
            CAT,
            obj: element,
            "Sending frame {}",
            frame.get_system_frame_number()
        );

        let input_buffer = frame
            .get_input_buffer()
            .expect("frame without input buffer");

        {
            let in_frame = gst_video::VideoFrameRef::from_buffer_ref_readable(
                &*input_buffer,
                &state.video_info,
            )
            .map_err(|_| {
                gst_element_error!(
                    element,
                    gst::CoreError::Failed,
                    ["Failed to map output buffer readable"]
                );
                gst::FlowError::Error
            })?;

            let frame_width = in_frame.info().width();
            let frame_height = in_frame.info().height();

            // Calculate delay to new frame by calculating the difference between the current actual
            // presentation timestamp of the last frame within the gif, and the pts of the new frame.
            // This results in variable frame delays in the gif - but an overall constant fps.
            state.last_actual_pts = in_frame.buffer().get_pts();
            if state.gif_pts.is_none() {
                // First frame: use pts of first input frame as origin
                state.gif_pts = Some(in_frame.buffer().get_pts());
            }
            let frame_delay = in_frame.buffer().get_pts() - state.gif_pts.unwrap();
            if frame_delay.is_none() {
                gst_element_error!(
                    element,
                    gst::CoreError::Failed,
                    ["No PTS set on input frame. Unable to calculate proper frame timing."]
                );
                return Err(gst::FlowError::Error);
            }

            let mut raw_frame = get_tightly_packed_framebuffer(&in_frame);
            let mut gif_frame = match in_frame.info().format() {
                gst_video::VideoFormat::Rgb => {
                    gif::Frame::from_rgb_speed(
                        frame_width as u16,
                        frame_height as u16,
                        &raw_frame,
                        10, // TODO: Export option for this quality/speed tradeoff
                    )
                }
                gst_video::VideoFormat::Rgba => {
                    gif::Frame::from_rgba_speed(
                        frame_width as u16,
                        frame_height as u16,
                        &mut raw_frame,
                        10, //TODO: Export option for this quality/speed tradeoff
                    )
                }
                _ => unreachable!(),
            };

            // apply encoding settings to frame (gif uses multiples of 10ms as frame_delay)
            // use float arithmetic with rounding for this calculation, since small stuttering
            // is probably less visible than the large stuttering when a complete 10ms have to
            // "catch up".
            gif_frame.delay = (frame_delay.mseconds().unwrap() as f32 / 10.0).round() as u16;
            state.gif_pts.replace(
                state.gif_pts.unwrap() + gst::ClockTime::from_mseconds(gif_frame.delay as u64 * 10),
            );

            // encode new frame
            let context = state.context.as_mut().unwrap();
            if let Err(e) = context.write_frame(&gif_frame) {
                gst_element_error!(element, gst::CoreError::Failed, [&e.to_string()]);
                return Err(gst::FlowError::Error);
            }
        }

        // The encoder directly outputs one frame for each input frame
        // Since the output is directly available, we can re-use the input frame
        // to push results to the pipeline
        let buffer = state.cache.consume();

        // Avoid keeping the state locked while calling finish_frame()
        drop(state_guard);

        let output_buffer = gst::Buffer::from_mut_slice(buffer);
        // Currently not using incremental frames -> every frame is a keyframe
        frame.set_flags(gst_video::VideoCodecFrameFlags::SYNC_POINT);
        frame.set_output_buffer(output_buffer);
        element.finish_frame(Some(frame))
    }
}

impl GifEnc {
    fn flush_encoder(
        &self,
        element: &gst_video::VideoEncoder,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        gst_debug!(CAT, obj: element, "Flushing");

        let trailer_buffer = self.state.borrow_mut().as_mut().map(|state| {
            // Drop encoder to flush and take flushed data (gif trailer)
            state.context = None;
            let buffer = state.cache.consume();
            // reset internal state
            let settings = self.settings.lock().unwrap();
            // manually produce a
            let mut trailer_buffer = gst::Buffer::from_mut_slice(buffer);
            {
                let trailer_buffer = trailer_buffer.get_mut().unwrap();
                trailer_buffer.set_pts(state.last_actual_pts);
            }

            // Initialize the encoder again, to be ready for a new round without format change
            state.reset(*settings);
            // return the constructed buffer containing the gif trailer
            trailer_buffer
        });
        if let Some(trailer_buffer) = trailer_buffer {
            // manually push GIF trailer to the encoder's src pad
            let srcpad = element.get_static_pad("src").unwrap();
            srcpad.push(trailer_buffer)?;
        }

        Ok(gst::FlowSuccess::Ok)
    }
}

/// Helper method that takes a gstreamer video-frame and copies it into a
/// tightly packed rgb(a) buffer, ready for consumption by the gif encoder.
fn get_tightly_packed_framebuffer(frame: &gst_video::VideoFrameRef<&gst::BufferRef>) -> Vec<u8> {
    assert_eq!(frame.n_planes(), 1); // RGB and RGBA are tightly packed
    let line_size = (frame.info().width() * frame.n_components()) as usize;
    let line_stride = frame.info().stride()[0] as usize;
    let mut raw_frame: Vec<u8> = Vec::with_capacity(line_size * frame.info().height() as usize);

    // copy gstreamer frame to tightly packed rgb(a) frame.
    frame
        .plane_data(0)
        .unwrap()
        .chunks_exact(line_stride)
        .map(|padded_line| &padded_line[..line_size])
        .for_each(|line| raw_frame.extend_from_slice(line));

    raw_frame
}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "gifenc",
        gst::Rank::Primary,
        GifEnc::get_type(),
    )
}
