// decrypter.rs
//
// Copyright 2019 Jordan Petridis <jordan@centricular.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//
// SPDX-License-Identifier: MIT

use glib::prelude::*;
use glib::subclass;
use glib::subclass::prelude::*;
use gst::prelude::*;
use gst::subclass::prelude::*;
use sodiumoxide::crypto::box_;

use std::sync::Mutex;

lazy_static! {
    static ref CAT: gst::DebugCategory = {
        gst::DebugCategory::new(
            "sodiumdecrypter",
            gst::DebugColorFlags::empty(),
            Some("Decrypter Element"),
        )
    };
}

static PROPERTIES: [subclass::Property; 2] = [
    subclass::Property("receiver-key", |name| {
        glib::ParamSpec::boxed(
            name,
            "Receiver Key",
            "The private key of the Reeiver",
            glib::Bytes::static_type(),
            glib::ParamFlags::READWRITE,
        )
    }),
    subclass::Property("sender-key", |name| {
        glib::ParamSpec::boxed(
            name,
            "Sender Key",
            "The public key of the Sender",
            glib::Bytes::static_type(),
            glib::ParamFlags::WRITABLE,
        )
    }),
];

#[derive(Debug, Clone, Default)]
struct Props {
    receiver_key: Option<glib::Bytes>,
    sender_key: Option<glib::Bytes>,
}

#[derive(Debug)]
struct State {
    adapter: gst_base::UniqueAdapter,
    initial_nonce: Option<box_::Nonce>,
    precomputed_key: box_::PrecomputedKey,
    block_size: Option<u32>,
}

impl State {
    fn from_props(props: &Props) -> Result<Self, gst::ErrorMessage> {
        let sender_key = props
            .sender_key
            .as_ref()
            .and_then(|k| box_::PublicKey::from_slice(&k))
            .ok_or_else(|| {
                gst_error_msg!(
                    gst::ResourceError::NotFound,
                    [format!(
                        "Failed to set Sender's Key from property: {:?}",
                        props.sender_key
                    )
                    .as_ref()]
                )
            })?;

        let receiver_key = props
            .receiver_key
            .as_ref()
            .and_then(|k| box_::SecretKey::from_slice(&k))
            .ok_or_else(|| {
                gst_error_msg!(
                    gst::ResourceError::NotFound,
                    [format!(
                        "Failed to set Receiver's Key from property: {:?}",
                        props.receiver_key
                    )
                    .as_ref()]
                )
            })?;

        let precomputed_key = box_::precompute(&sender_key, &receiver_key);

        Ok(Self {
            adapter: gst_base::UniqueAdapter::new(),
            precomputed_key,
            initial_nonce: None,
            block_size: None,
        })
    }

    // Split the buffer into N(`chunk_index`) chunks of `block_size`,
    // decrypt them, and push them to the internal adapter for further
    // retrieval
    fn decrypt_into_adapter(
        &mut self,
        element: &gst::Element,
        pad: &gst::Pad,
        buffer: &gst::Buffer,
        chunk_index: u64,
    ) -> Result<gst::FlowSuccess, gst::FlowError> {
        let map = buffer.map_readable().ok_or_else(|| {
            gst_element_error!(
                element,
                gst::StreamError::Format,
                ["Failed to map buffer readable"]
            );

            gst::FlowError::Error
        })?;

        gst_debug!(CAT, obj: pad, "Returned pull size: {}", map.len());

        let mut nonce = add_nonce(self.initial_nonce.unwrap(), chunk_index);
        let block_size = self.block_size.expect("Block size wasn't set") as usize + box_::MACBYTES;

        for subbuffer in map.chunks(block_size) {
            let plain = box_::open_precomputed(&subbuffer, &nonce, &self.precomputed_key).map_err(
                |_| {
                    gst_element_error!(
                        element,
                        gst::StreamError::Format,
                        ["Failed to decrypt buffer"]
                    );
                    gst::FlowError::Error
                },
            )?;
            // assumes little endian
            nonce.increment_le_inplace();
            self.adapter.push(gst::Buffer::from_mut_slice(plain));
        }

        Ok(gst::FlowSuccess::Ok)
    }

    // Retrieve the requested buffer out of the adapter.
    fn get_requested_buffer(
        &mut self,
        pad: &gst::Pad,
        requested_size: u32,
        adapter_offset: usize,
    ) -> Result<gst::Buffer, gst::FlowError> {
        let avail = self.adapter.available();
        gst_debug!(CAT, obj: pad, "Avail: {}", avail);
        gst_debug!(CAT, obj: pad, "Adapter offset: {}", adapter_offset);

        // if this underflows, the available buffer in the adapter is smaller than the
        // requested offset, which means we have reached EOS
        let available_buffer = avail
            .checked_sub(adapter_offset)
            .ok_or(gst::FlowError::Eos)?;

        // if the available buffer size is smaller than the requested, its a short
        // read and return that. Else return the requested size
        let available_size = if available_buffer <= requested_size as usize {
            available_buffer
        } else {
            requested_size as usize
        };

        if available_size == 0 {
            self.adapter.clear();

            // if the requested buffer was 0 sized, retunr an
            // empty buffer
            if requested_size == 0 {
                return Ok(gst::Buffer::new());
            }

            return Err(gst::FlowError::Eos);
        }

        // discard what we don't need
        assert!(self.adapter.available() >= adapter_offset);
        self.adapter.flush(adapter_offset);

        assert!(self.adapter.available() >= available_size);
        let buffer = self
            .adapter
            .take_buffer(available_size)
            .expect("Failed to get buffer from adapter");

        // Cleanup the adapter
        self.adapter.clear();

        Ok(buffer)
    }
}

/// Calculate the nonce of a block based on the initial nonce
/// and the block index in the stream.
///
/// This is a faster way of doing `(0..chunk_index).for_each(|_| nonce.increment_le_inplace());`
fn add_nonce(initial_nonce: box_::Nonce, chunk_index: u64) -> box_::Nonce {
    let mut nonce = initial_nonce.0;
    // convert our index to a bytes array
    // add padding so our 8byte array of the chunk_index will have an
    // equal length with the nonce, padding at the end cause little endian
    let idx = chunk_index.to_le_bytes();
    let idx = &[
        idx[0], idx[1], idx[2], idx[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(idx.len(), box_::NONCEBYTES);

    // add the chunk index to the nonce
    sodiumoxide::utils::add_le(&mut nonce, idx).expect("Failed to calculate the nonce");

    // construct back a nonce from our custom array
    box_::Nonce::from_slice(&nonce).expect("Failed to convert slice back to Nonce")
}

struct Decrypter {
    srcpad: gst::Pad,
    sinkpad: gst::Pad,
    props: Mutex<Props>,
    state: Mutex<Option<State>>,
}

impl Decrypter {
    fn set_pad_functions(_sinkpad: &gst::Pad, srcpad: &gst::Pad) {
        srcpad.set_getrange_function(|pad, parent, offset, size| {
            Decrypter::catch_panic_pad_function(
                parent,
                || Err(gst::FlowError::Error),
                |decrypter, element| decrypter.get_range(pad, element, offset, size),
            )
        });

        srcpad.set_activatemode_function(|pad, parent, mode, active| {
            Decrypter::catch_panic_pad_function(
                parent,
                || {
                    Err(gst_loggable_error!(
                        CAT,
                        "Panic activating srcpad with mode"
                    ))
                },
                |decrypter, element| {
                    decrypter.src_activatemode_function(pad, element, mode, active)
                },
            )
        });

        srcpad.set_query_function(|pad, parent, query| {
            Decrypter::catch_panic_pad_function(
                parent,
                || false,
                |decrypter, element| decrypter.src_query(pad, element, query),
            )
        });
    }

    fn src_activatemode_function(
        &self,
        _pad: &gst::Pad,
        element: &gst::Element,
        mode: gst::PadMode,
        active: bool,
    ) -> Result<(), gst::LoggableError> {
        match mode {
            gst::PadMode::Pull => {
                self.sinkpad
                    .activate_mode(mode, active)
                    .map_err(gst::LoggableError::from)?;

                // Set the nonce and block size from the headers
                // right after we activate the pad
                self.check_headers(element)
            }
            gst::PadMode::Push => Err(gst_loggable_error!(CAT, "Push mode not supported")),
            _ => Err(gst_loggable_error!(
                CAT,
                "Failed to activate the pad in Unknown mode, {:?}",
                mode
            )),
        }
    }

    fn src_query(&self, pad: &gst::Pad, element: &gst::Element, query: &mut gst::QueryRef) -> bool {
        use gst::QueryView;

        gst_log!(CAT, obj: pad, "Handling query {:?}", query);

        match query.view_mut() {
            QueryView::Scheduling(mut q) => {
                let mut peer_query = gst::Query::new_scheduling();
                let res = self.sinkpad.peer_query(&mut peer_query);
                if !res {
                    return res;
                }

                gst_log!(CAT, obj: pad, "Upstream returned {:?}", peer_query);

                let (flags, min, max, align) = peer_query.get_result();
                q.set(flags, min, max, align);
                q.add_scheduling_modes(&[gst::PadMode::Pull]);
                gst_log!(CAT, obj: pad, "Returning {:?}", q.get_mut_query());
                true
            }
            QueryView::Duration(ref mut q) => {
                use std::convert::TryInto;

                if q.get_format() != gst::Format::Bytes {
                    return pad.query_default(Some(element), query);
                }

                /* First let's query the bytes duration upstream */
                let mut peer_query = gst::query::Query::new_duration(gst::Format::Bytes);

                if !self.sinkpad.peer_query(&mut peer_query) {
                    gst_error!(CAT, "Failed to query upstream duration");
                    return false;
                }

                let size = match peer_query.get_result().try_into().unwrap() {
                    gst::format::Bytes(Some(size)) => size,
                    gst::format::Bytes(None) => {
                        gst_error!(CAT, "Failed to query upstream duration");

                        return false;
                    }
                };

                let state = self.state.lock().unwrap();
                let state = match state.as_ref() {
                    // If state isn't set, it means that the
                    // element hasn't been activated yet.
                    None => return false,
                    Some(s) => s,
                };

                // subtract static offsets
                let size = size - super::HEADERS_SIZE as u64;

                // calculate the number of chunks that exist in the stream
                let total_chunks =
                    (size - 1) / state.block_size.expect("Block size wasn't set") as u64;
                // subtrack the MAC of each block
                let size = size - total_chunks * box_::MACBYTES as u64;

                gst_debug!(CAT, obj: pad, "Setting duration bytes: {}", size);
                q.set(gst::format::Bytes::from(size));

                true
            }
            _ => pad.query_default(Some(element), query),
        }
    }

    fn check_headers(&self, element: &gst::Element) -> Result<(), gst::LoggableError> {
        let is_none = {
            let mutex_state = self.state.lock().unwrap();
            let state = mutex_state.as_ref().unwrap();
            state.initial_nonce.is_none()
        };

        if !is_none {
            return Ok(());
        }

        let buffer = self
            .sinkpad
            .pull_range(0, crate::HEADERS_SIZE as u32)
            .map_err(|err| {
                let err = gst_loggable_error!(
                    CAT,
                    "Failed to pull nonce from the stream, reason: {:?}",
                    err
                );
                err.log_with_object(element);
                err
            })?;

        if buffer.get_size() != crate::HEADERS_SIZE {
            let err = gst_loggable_error!(CAT, "Headers buffer has wrong size");
            err.log_with_object(element);
            return Err(err);
        }

        let map = buffer.map_readable().ok_or_else(|| {
            let err = gst_loggable_error!(CAT, "Failed to map buffer readable");
            err.log_with_object(element);
            err
        })?;

        let sodium_header_slice = &map[..crate::TYPEFIND_HEADER_SIZE];
        if sodium_header_slice != crate::TYPEFIND_HEADER {
            let err = gst_loggable_error!(CAT, "Buffer has wrong typefind header");
            err.log_with_object(element);
            return Err(err);
        }

        let nonce_slice =
            &map[crate::TYPEFIND_HEADER_SIZE..crate::TYPEFIND_HEADER_SIZE + box_::NONCEBYTES];
        assert_eq!(nonce_slice.len(), box_::NONCEBYTES);
        let nonce = box_::Nonce::from_slice(nonce_slice).ok_or_else(|| {
            let err = gst_loggable_error!(CAT, "Failed to create nonce from buffer");
            err.log_with_object(&self.srcpad);
            err
        })?;

        let slice = &map[crate::TYPEFIND_HEADER_SIZE + box_::NONCEBYTES..crate::HEADERS_SIZE];
        assert_eq!(
            crate::HEADERS_SIZE - crate::TYPEFIND_HEADER_SIZE - box_::NONCEBYTES,
            4
        );
        let block_size = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);

        // reacquire the lock again to change the state
        let mut state = self.state.lock().unwrap();
        let state = state.as_mut().unwrap();

        state.initial_nonce = Some(nonce);
        gst_debug!(CAT, obj: element, "Setting nonce to: {:?}", nonce.0);
        state.block_size = Some(block_size);
        gst_debug!(CAT, obj: element, "Setting block size to: {}", block_size);

        Ok(())
    }

    fn pull_requested_buffer(
        &self,
        pad: &gst::Pad,
        element: &gst::Element,
        requested_size: u32,
        block_size: u32,
        chunk_index: u64,
    ) -> Result<gst::Buffer, gst::FlowError> {
        let pull_offset = super::HEADERS_SIZE as u64
            + (chunk_index * block_size as u64)
            + (chunk_index * box_::MACBYTES as u64);

        gst_debug!(CAT, obj: pad, "Pull offset: {}", pull_offset);
        gst_debug!(CAT, obj: pad, "block size: {}", block_size);

        // calculate how many chunks are needed, if we need something like 3.2
        // round the number to 4 and cut the buffer afterwards.
        let checked = requested_size.checked_add(block_size).ok_or_else(|| {
            gst_element_error!(
                element,
                gst::LibraryError::Failed,
                [
                    "Addition overflow when adding requested pull size and block size: {} + {}",
                    requested_size,
                    block_size,
                ]
            );
            gst::FlowError::Error
        })?;

        // Read at least one chunk in case 0 bytes were requested
        let total_chunks = u32::max((checked - 1) / block_size, 1);
        gst_debug!(CAT, obj: pad, "Blocks to be pulled: {}", total_chunks);

        // Pull a buffer of all the chunks we will need
        let checked_size = total_chunks.checked_mul(block_size).ok_or_else(|| {
            gst_element_error!(
                element,
                gst::LibraryError::Failed,
                [
                    "Overflowed trying to calculate the buffer size to pull: {} * {}",
                    total_chunks,
                    block_size,
                ]
            );
            gst::FlowError::Error
        })?;

        let total_size = checked_size + (total_chunks * box_::MACBYTES as u32);
        gst_debug!(CAT, obj: pad, "Requested pull size: {}", total_size);

        self.sinkpad.pull_range(pull_offset, total_size).map_err(|err| {
            match err {
                gst::FlowError::Flushing => {
                    gst_debug!(CAT, obj: &self.sinkpad, "Pausing after pulling buffer, reason: flushing");
                }
                gst::FlowError::Eos => {
                    gst_debug!(CAT, obj: &self.sinkpad, "Eos");
                }
                flow => {
                    gst_error!(CAT, obj: &self.sinkpad, "Failed to pull, reason: {:?}", flow);
                }
            };

            err
        })
    }

    fn get_range(
        &self,
        pad: &gst::Pad,
        element: &gst::Element,
        offset: u64,
        requested_size: u32,
    ) -> Result<gst::Buffer, gst::FlowError> {
        let block_size = {
            let mut mutex_state = self.state.lock().unwrap();
            // This will only be run after READY state,
            // and will be guaranted to be initialized
            let state = mutex_state.as_mut().unwrap();
            // Cleanup the adapter
            state.adapter.clear();
            state.block_size.expect("Block size wasn't set")
        };

        gst_debug!(CAT, obj: pad, "Requested offset: {}", offset);
        gst_debug!(CAT, obj: pad, "Requested size: {}", requested_size);

        let chunk_index = offset as u64 / block_size as u64;
        gst_debug!(CAT, obj: pad, "Stream Block index: {}", chunk_index);

        let pull_offset = offset - (chunk_index * block_size as u64);
        assert!(pull_offset <= std::u32::MAX as u64);
        let pull_offset = pull_offset as u32;

        let buffer = self.pull_requested_buffer(
            pad,
            element,
            requested_size + pull_offset,
            block_size,
            chunk_index,
        )?;

        let mut state = self.state.lock().unwrap();
        // This will only be run after READY state,
        // and will be guaranted to be initialized
        let state = state.as_mut().unwrap();

        state.decrypt_into_adapter(element, &self.srcpad, &buffer, chunk_index)?;

        let adapter_offset = pull_offset as usize;
        state.get_requested_buffer(&self.srcpad, requested_size, adapter_offset)
    }
}

impl ObjectSubclass for Decrypter {
    const NAME: &'static str = "RsSodiumDecryptor";
    type ParentType = gst::Element;
    type Instance = gst::subclass::ElementInstanceStruct<Self>;
    type Class = subclass::simple::ClassStruct<Self>;

    glib_object_subclass!();

    fn new_with_class(klass: &subclass::simple::ClassStruct<Self>) -> Self {
        let templ = klass.get_pad_template("sink").unwrap();
        let sinkpad = gst::Pad::new_from_template(&templ, Some("sink"));
        let templ = klass.get_pad_template("src").unwrap();
        let srcpad = gst::Pad::new_from_template(&templ, Some("src"));

        Decrypter::set_pad_functions(&sinkpad, &srcpad);
        let props = Mutex::new(Props::default());
        let state = Mutex::new(None);

        Self {
            srcpad,
            sinkpad,
            props,
            state,
        }
    }

    fn class_init(klass: &mut subclass::simple::ClassStruct<Self>) {
        klass.set_metadata(
            "Decrypter",
            "Generic",
            "libsodium-based file decrypter",
            "Jordan Petridis <jordan@centricular.com>",
        );

        let src_pad_template = gst::PadTemplate::new(
            "src",
            gst::PadDirection::Src,
            gst::PadPresence::Always,
            &gst::Caps::new_any(),
        )
        .unwrap();
        klass.add_pad_template(src_pad_template);

        let sink_caps = gst::Caps::builder("application/x-sodium-encrypted").build();
        let sink_pad_template = gst::PadTemplate::new(
            "sink",
            gst::PadDirection::Sink,
            gst::PadPresence::Always,
            &sink_caps,
        )
        .unwrap();
        klass.add_pad_template(sink_pad_template);
        klass.install_properties(&PROPERTIES);
    }
}

impl ObjectImpl for Decrypter {
    glib_object_impl!();

    fn constructed(&self, obj: &glib::Object) {
        self.parent_constructed(obj);

        let element = obj.downcast_ref::<gst::Element>().unwrap();
        element.add_pad(&self.sinkpad).unwrap();
        element.add_pad(&self.srcpad).unwrap();
    }

    fn set_property(&self, _obj: &glib::Object, id: usize, value: &glib::Value) {
        let prop = &PROPERTIES[id];

        match *prop {
            subclass::Property("sender-key", ..) => {
                let mut props = self.props.lock().unwrap();
                props.sender_key = value.get();
            }

            subclass::Property("receiver-key", ..) => {
                let mut props = self.props.lock().unwrap();
                props.receiver_key = value.get();
            }

            _ => unimplemented!(),
        }
    }

    fn get_property(&self, _obj: &glib::Object, id: usize) -> Result<glib::Value, ()> {
        let prop = &PROPERTIES[id];

        match *prop {
            subclass::Property("receiver-key", ..) => {
                let props = self.props.lock().unwrap();
                Ok(props.receiver_key.to_value())
            }

            _ => unimplemented!(),
        }
    }
}

impl ElementImpl for Decrypter {
    fn change_state(
        &self,
        element: &gst::Element,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        gst_debug!(CAT, obj: element, "Changing state {:?}", transition);

        match transition {
            gst::StateChange::NullToReady => {
                let props = self.props.lock().unwrap().clone();

                // Create an internal state struct from the provided properties or
                // refuse to change state
                let state_ = State::from_props(&props).map_err(|err| {
                    element.post_error_message(&err);
                    gst::StateChangeError
                })?;

                let mut state = self.state.lock().unwrap();
                *state = Some(state_);
            }
            gst::StateChange::ReadyToNull => {
                let _ = self.state.lock().unwrap().take();
            }
            _ => (),
        }

        let success = self.parent_change_state(element, transition)?;

        if transition == gst::StateChange::ReadyToNull {
            let _ = self.state.lock().unwrap().take();
        }

        Ok(success)
    }
}

pub fn register(plugin: &gst::Plugin) -> Result<(), glib::BoolError> {
    gst::Element::register(
        Some(plugin),
        "sodiumdecrypter",
        gst::Rank::None,
        Decrypter::get_type(),
    )
}
