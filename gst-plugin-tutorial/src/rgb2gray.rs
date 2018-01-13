// Copyright (C) 2017 Sebastian Dröge <sebastian@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use glib;
use gst;
use gst::prelude::*;
use gst_video;

use gst_plugin::properties::*;
use gst_plugin::object::*;
use gst_plugin::element::*;
use gst_plugin::base_transform::*;

use std::i32;
use std::sync::Mutex;

// Default values of properties
const DEFAULT_INVERT: bool = false;
const DEFAULT_SHIFT: u32 = 0;

// Property value storage
#[derive(Debug, Clone, Copy)]
struct Settings {
    invert: bool,
    shift: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            invert: DEFAULT_INVERT,
            shift: DEFAULT_SHIFT,
        }
    }
}

// Metadata for the properties
static PROPERTIES: [Property; 2] = [
    Property::Boolean(
        "invert",
        "Invert",
        "Invert grayscale output",
        DEFAULT_INVERT,
        PropertyMutability::ReadWrite,
    ),
    Property::UInt(
        "shift",
        "Shift",
        "Shift grayscale output (wrapping around)",
        (0, 255),
        DEFAULT_SHIFT,
        PropertyMutability::ReadWrite,
    ),
];

// Stream-specific state, i.e. video format configuration
struct State {
    in_info: gst_video::VideoInfo,
    out_info: gst_video::VideoInfo,
}

// Struct containing all the element data
struct Rgb2Gray {
    cat: gst::DebugCategory,
    settings: Mutex<Settings>,
    state: Mutex<Option<State>>,
}

impl Rgb2Gray {
    // Called when a new instance is to be created
    fn new(_transform: &BaseTransform) -> Box<BaseTransformImpl<BaseTransform>> {
        Box::new(Self {
            cat: gst::DebugCategory::new(
                "rsrgb2gray",
                gst::DebugColorFlags::empty(),
                "Rust RGB-GRAY converter",
            ),
            settings: Mutex::new(Default::default()),
            state: Mutex::new(None),
        })
    }

    // Called exactly once when registering the type. Used for
    // setting up metadata for all instances, e.g. the name and
    // classification and the pad templates with their caps.
    //
    // Actual instances can create pads based on those pad templates
    // with a subset of the caps given here. In case of basetransform,
    // a "src" and "sink" pad template are required here and the base class
    // will automatically instantiate pads for them.
    //
    // Our element here can convert BGRx to BGRx or GRAY8, both being grayscale.
    fn class_init(klass: &mut BaseTransformClass) {
        klass.set_metadata(
            "RGB-GRAY Converter",
            "Filter/Effect/Converter/Video",
            "Converts RGB to GRAY or grayscale RGB",
            "Sebastian Dröge <sebastian@centricular.com>",
        );

        // On the src pad, we can produce BGRx and GRAY8 of any
        // width/height and with any framerate
        let caps = gst::Caps::new_simple(
            "video/x-raw",
            &[
                (
                    "format",
                    &gst::List::new(&[
                        &gst_video::VideoFormat::Bgrx.to_string(),
                        &gst_video::VideoFormat::Gray8.to_string(),
                    ]),
                ),
                ("width", &gst::IntRange::<i32>::new(0, i32::MAX)),
                ("height", &gst::IntRange::<i32>::new(0, i32::MAX)),
                (
                    "framerate",
                    &gst::FractionRange::new(
                        gst::Fraction::new(0, 1),
                        gst::Fraction::new(i32::MAX, 1),
                    ),
                ),
            ],
        );
        // The src pad template must be named "src" for basetransform
        // and specific a pad that is always there
        let src_pad_template = gst::PadTemplate::new(
            "src",
            gst::PadDirection::Src,
            gst::PadPresence::Always,
            &caps,
        );
        klass.add_pad_template(src_pad_template);

        // On the sink pad, we can accept BGRx of any
        // width/height and with any framerate
        let caps = gst::Caps::new_simple(
            "video/x-raw",
            &[
                ("format", &gst_video::VideoFormat::Bgrx.to_string()),
                ("width", &gst::IntRange::<i32>::new(0, i32::MAX)),
                ("height", &gst::IntRange::<i32>::new(0, i32::MAX)),
                (
                    "framerate",
                    &gst::FractionRange::new(
                        gst::Fraction::new(0, 1),
                        gst::Fraction::new(i32::MAX, 1),
                    ),
                ),
            ],
        );
        // The sink pad template must be named "sink" for basetransform
        // and specific a pad that is always there
        let sink_pad_template = gst::PadTemplate::new(
            "sink",
            gst::PadDirection::Sink,
            gst::PadPresence::Always,
            &caps,
        );
        klass.add_pad_template(sink_pad_template);

        // Install all our properties
        klass.install_properties(&PROPERTIES);

        // Configure basetransform so that we are never running in-place,
        // don't passthrough on same caps and also never call transform_ip
        // in passthrough mode (which does not matter for us here).
        //
        // We could work in-place for BGRx->BGRx but don't do here for simplicity
        // for now.
        klass.configure(BaseTransformMode::NeverInPlace, false, false);
    }

    // Converts one pixel of BGRx to a grayscale value, shifting and/or
    // inverting it as configured
    #[inline]
    fn bgrx_to_gray(in_p: &[u8], shift: u8, invert: bool) -> u8 {
        // See https://en.wikipedia.org/wiki/YUV#SDTV_with_BT.601
        const R_Y: u32 = 19595; // 0.299 * 65536
        const G_Y: u32 = 38470; // 0.587 * 65536
        const B_Y: u32 = 7471; // 0.114 * 65536

        assert_eq!(in_p.len(), 4);

        let b = u32::from(in_p[0]);
        let g = u32::from(in_p[1]);
        let r = u32::from(in_p[2]);

        let gray = ((r * R_Y) + (g * G_Y) + (b * B_Y)) / 65536;
        let gray = (gray as u8).wrapping_add(shift);

        if invert {
            255 - gray
        } else {
            gray
        }
    }
}

// Virtual methods of GObject itself
impl ObjectImpl<BaseTransform> for Rgb2Gray {
    // Called whenever a value of a property is changed. It can be called
    // at any time from any thread.
    fn set_property(&self, obj: &glib::Object, id: u32, value: &glib::Value) {
        let prop = &PROPERTIES[id as usize];
        let element = obj.clone().downcast::<BaseTransform>().unwrap();

        match *prop {
            Property::Boolean("invert", ..) => {
                let mut settings = self.settings.lock().unwrap();
                let invert = value.get().unwrap();
                gst_info!(
                    self.cat,
                    obj: &element,
                    "Changing invert from {} to {}",
                    settings.invert,
                    invert
                );
                settings.invert = invert;
            }
            Property::UInt("shift", ..) => {
                let mut settings = self.settings.lock().unwrap();
                let shift = value.get().unwrap();
                gst_info!(
                    self.cat,
                    obj: &element,
                    "Changing shift from {} to {}",
                    settings.shift,
                    shift
                );
                settings.shift = shift;
            }
            _ => unimplemented!(),
        }
    }

    // Called whenever a value of a property is read. It can be called
    // at any time from any thread.
    fn get_property(&self, _obj: &glib::Object, id: u32) -> Result<glib::Value, ()> {
        let prop = &PROPERTIES[id as usize];

        match *prop {
            Property::Boolean("invert", ..) => {
                let settings = self.settings.lock().unwrap();
                Ok(settings.invert.to_value())
            }
            Property::UInt("shift", ..) => {
                let settings = self.settings.lock().unwrap();
                Ok(settings.shift.to_value())
            }
            _ => unimplemented!(),
        }
    }
}

// Virtual methods of gst::Element. We override none
impl ElementImpl<BaseTransform> for Rgb2Gray {}

// Virtual methods of gst_base::BaseTransform
impl BaseTransformImpl<BaseTransform> for Rgb2Gray {
    // Called for converting caps from one pad to another to account for any
    // changes in the media format this element is performing.
    //
    // In our case that means that:
    fn transform_caps(
        &self,
        element: &BaseTransform,
        direction: gst::PadDirection,
        caps: gst::Caps,
        filter: Option<&gst::Caps>,
    ) -> gst::Caps {
        let other_caps = if direction == gst::PadDirection::Src {
            // For src to sink, no matter if we get asked for BGRx or GRAY8 caps, we can only
            // accept corresponding BGRx caps on the sinkpad. We will only ever get BGRx and GRAY8
            // caps here as input.
            let mut caps = caps.clone();

            for s in caps.make_mut().iter_mut() {
                s.set("format", &gst_video::VideoFormat::Bgrx.to_string());
            }

            caps
        } else {
            // For the sink to src case, we will only get BGRx caps and for each of them we could
            // output the same caps or the same caps as GRAY8. We prefer GRAY8 (put it first), and
            // at a later point the caps negotiation mechanism of GStreamer will decide on which
            // one to actually produce.
            let mut gray_caps = gst::Caps::new_empty();

            {
                let gray_caps = gray_caps.get_mut().unwrap();

                for s in caps.iter() {
                    let mut s_gray = s.to_owned();
                    s_gray.set("format", &gst_video::VideoFormat::Gray8.to_string());
                    gray_caps.append_structure(s_gray);
                }
                gray_caps.append(caps.clone());
            }

            gray_caps
        };

        gst_debug!(
            self.cat,
            obj: element,
            "Transformed caps from {} to {} in direction {:?}",
            caps,
            other_caps,
            direction
        );

        // In the end we need to filter the caps through an optional filter caps to get rid of any
        // unwanted caps.
        if let Some(filter) = filter {
            filter.intersect_with_mode(&other_caps, gst::CapsIntersectMode::First)
        } else {
            other_caps
        }
    }

    // Returns the size of one processing unit (i.e. a frame in our case) corresponding
    // to the given caps. This is used for allocating a big enough output buffer and
    // sanity checking the input buffer size, among other things.
    fn get_unit_size(&self, _element: &BaseTransform, caps: &gst::Caps) -> Option<usize> {
        gst_video::VideoInfo::from_caps(caps).map(|info| info.size())
    }

    // Called whenever the input/output caps are changing, i.e. in the very beginning before data
    // flow happens and whenever the situation in the pipeline is changing. All buffers after this
    // call have the caps given here.
    //
    // We simply remember the resulting VideoInfo from the caps to be able to use this for knowing
    // the width, stride, etc when transforming buffers
    fn set_caps(&self, element: &BaseTransform, incaps: &gst::Caps, outcaps: &gst::Caps) -> bool {
        let in_info = match gst_video::VideoInfo::from_caps(incaps) {
            None => return false,
            Some(info) => info,
        };
        let out_info = match gst_video::VideoInfo::from_caps(outcaps) {
            None => return false,
            Some(info) => info,
        };

        gst_debug!(
            self.cat,
            obj: element,
            "Configured for caps {} to {}",
            incaps,
            outcaps
        );

        *self.state.lock().unwrap() = Some(State {
            in_info: in_info,
            out_info: out_info,
        });

        true
    }

    // Called when shutting down the element so we can release all stream-related state
    // There's also start(), which is called whenever starting the element again
    fn stop(&self, element: &BaseTransform) -> bool {
        // Drop state
        let _ = self.state.lock().unwrap().take();

        gst_info!(self.cat, obj: element, "Stopped");

        true
    }

    // Does the actual transformation of the input buffer to the output buffer
    fn transform(
        &self,
        element: &BaseTransform,
        inbuf: &gst::Buffer,
        outbuf: &mut gst::BufferRef,
    ) -> gst::FlowReturn {
        // Keep a local copy of the values of all our properties at this very moment. This
        // ensures that the mutex is never locked for long and the application wouldn't
        // have to block until this function returns when getting/setting property values
        let settings = *self.settings.lock().unwrap();

        // Get a locked reference to our state, i.e. the input and output VideoInfo
        let mut state_guard = self.state.lock().unwrap();
        let state = match *state_guard {
            None => {
                gst_element_error!(element, gst::CoreError::Negotiation, ["Have no state yet"]);
                return gst::FlowReturn::NotNegotiated;
            }
            Some(ref mut state) => state,
        };

        // Map the input buffer as a VideoFrameRef. This is similar to directly mapping
        // the buffer with inbuf.map_readable() but in addition extracts various video
        // specific metadata and sets up a convenient data structure that directly gives
        // pointers to the different planes and has all the information about the raw
        // video frame, like width, height, stride, video format, etc.
        //
        // This fails if the buffer can't be read or is invalid in relation to the video
        // info that is passed here
        let in_frame = match gst_video::VideoFrameRef::from_buffer_ref_readable(
            inbuf.as_ref(),
            &state.in_info,
        ) {
            None => {
                gst_element_error!(
                    element,
                    gst::CoreError::Failed,
                    ["Failed to map input buffer readable"]
                );
                return gst::FlowReturn::Error;
            }
            Some(in_frame) => in_frame,
        };

        // And now map the output buffer writable, so we can fill it.
        let mut out_frame =
            match gst_video::VideoFrameRef::from_buffer_ref_writable(outbuf, &state.out_info) {
                None => {
                    gst_element_error!(
                        element,
                        gst::CoreError::Failed,
                        ["Failed to map output buffer writable"]
                    );
                    return gst::FlowReturn::Error;
                }
                Some(out_frame) => out_frame,
            };

        // Keep the various metadata we need for working with the video frames in
        // local variables. This saves some typing below.
        let width = in_frame.width() as usize;
        let in_stride = in_frame.plane_stride()[0] as usize;
        let in_data = in_frame.plane_data(0).unwrap();
        let out_stride = out_frame.plane_stride()[0] as usize;
        let out_format = out_frame.format();
        let out_data = out_frame.plane_data_mut(0).unwrap();

        // First check the output format. Our input format is always BGRx but the output might
        // be BGRx or GRAY8. Based on what it is we need to do processing slightly differently.
        if out_format == gst_video::VideoFormat::Bgrx {
            // Some assertions about our assumptions how the data looks like. This is only there
            // to give some further information to the compiler, in case these can be used for
            // better optimizations of the resulting code.
            //
            // If any of the assertions were not true, the code below would fail cleanly.
            assert_eq!(in_data.len() % 4, 0);
            assert_eq!(out_data.len() % 4, 0);
            assert_eq!(out_data.len() / out_stride, in_data.len() / in_stride);

            let in_line_bytes = width * 4;
            let out_line_bytes = width * 4;

            assert!(in_line_bytes <= in_stride);
            assert!(out_line_bytes <= out_stride);

            // Iterate over each line of the input and output frame, mutable for the output frame.
            // Each input line has in_stride bytes, each output line out_stride. We use the
            // chunks/chunks_mut iterators here for getting a chunks of that many bytes per
            // iteration and zip them together to have access to both at the same time.
            for (in_line, out_line) in in_data
                .chunks(in_stride)
                .zip(out_data.chunks_mut(out_stride))
            {
                // Next iterate the same way over each actual pixel in each line. Every pixel is 4
                // bytes in the input and output, so we again use the chunks/chunks_mut iterators
                // to give us each pixel individually and zip them together.
                //
                // Note that we take a sub-slice of the whole lines: each line can contain an
                // arbitrary amount of padding at the end (e.g. for alignment purposes) and we
                // don't want to process that padding.
                for (in_p, out_p) in in_line[..in_line_bytes]
                    .chunks(4)
                    .zip(out_line[..out_line_bytes].chunks_mut(4))
                {
                    assert_eq!(out_p.len(), 4);

                    // Use our above-defined function to convert a BGRx pixel with the settings to
                    // a grayscale value. Then store the same value in the red/green/blue component
                    // of the pixel.
                    let gray = Rgb2Gray::bgrx_to_gray(in_p, settings.shift as u8, settings.invert);
                    out_p[0] = gray;
                    out_p[1] = gray;
                    out_p[2] = gray;
                }
            }
        } else if out_format == gst_video::VideoFormat::Gray8 {
            assert_eq!(in_data.len() % 4, 0);
            assert_eq!(out_data.len() / out_stride, in_data.len() / in_stride);

            let in_line_bytes = width * 4;
            let out_line_bytes = width;

            assert!(in_line_bytes <= in_stride);
            assert!(out_line_bytes <= out_stride);

            // Iterate over each line of the input and output frame, mutable for the output frame.
            // Each input line has in_stride bytes, each output line out_stride. We use the
            // chunks/chunks_mut iterators here for getting a chunks of that many bytes per
            // iteration and zip them together to have access to both at the same time.
            for (in_line, out_line) in in_data
                .chunks(in_stride)
                .zip(out_data.chunks_mut(out_stride))
            {
                // Next iterate the same way over each actual pixel in each line. Every pixel is 4
                // bytes in the input and 1 byte in the output, so we again use the
                // chunks/chunks_mut iterators to give us each pixel individually and zip them
                // together.
                //
                // Note that we take a sub-slice of the whole lines: each line can contain an
                // arbitrary amount of padding at the end (e.g. for alignment purposes) and we
                // don't want to process that padding.
                for (in_p, out_p) in in_line[..in_line_bytes]
                    .chunks(4)
                    .zip(out_line[..out_line_bytes].iter_mut())
                {
                    // Use our above-defined function to convert a BGRx pixel with the settings to
                    // a grayscale value. Then store the value in the grayscale output directly.
                    let gray = Rgb2Gray::bgrx_to_gray(in_p, settings.shift as u8, settings.invert);
                    *out_p = gray;
                }
            }
        } else {
            unimplemented!();
        }

        gst::FlowReturn::Ok
    }
}

// This zero-sized struct is containing the static metadata of our element. It is only necessary to
// be able to implement traits on it, but e.g. a plugin that registers multiple elements with the
// same code would use this struct to store information about the concrete element. An example of
// this would be a plugin that wraps around a library that has multiple decoders with the same API,
// but wants (as it should) a separate element registered for each decoder.
struct Rgb2GrayStatic;

// The basic trait for registering the type: This returns a name for the type and registers the
// instance and class initializations functions with the type system, thus hooking everything
// together.
impl ImplTypeStatic<BaseTransform> for Rgb2GrayStatic {
    fn get_name(&self) -> &str {
        "Rgb2Gray"
    }

    fn new(&self, element: &BaseTransform) -> Box<BaseTransformImpl<BaseTransform>> {
        Rgb2Gray::new(element)
    }

    fn class_init(&self, klass: &mut BaseTransformClass) {
        Rgb2Gray::class_init(klass);
    }
}

// Registers the type for our element, and then registers in GStreamer under
// the name "rsrgb2gray" for being able to instantiate it via e.g.
// gst::ElementFactory::make().
pub fn register(plugin: &gst::Plugin) {
    let type_ = register_type(Rgb2GrayStatic);
    gst::Element::register(plugin, "rsrgb2gray", 0, type_);
}
