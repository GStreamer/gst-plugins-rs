# NOTE: The canonical repository for gst-plugin-rs has moved to [freedesktop.org GitLab](https://gitlab.freedesktop.org/gstreamer/gst-plugin-rs)!

# gst-plugin-rs [![crates.io](https://img.shields.io/crates/v/gst-plugin.svg)](https://crates.io/crates/gst-plugin) [![pipeline status](https://gitlab.freedesktop.org/gstreamer/gst-plugin-rs/badges/master/pipeline.svg)](https://gitlab.freedesktop.org/gstreamer/gst-plugin-rs/commits/master)

Infrastructure for writing [GStreamer](https://gstreamer.freedesktop.org/)
plugins and elements in the [Rust programming
language](https://www.rust-lang.org/), and a collection of various GStreamer
plugins.

Documentation for the crate containing the infrastructure for writing
GStreamer plugins in Rust, [`gst-plugin`](gst-plugin), can be found
[here](https://sdroege.github.io/rustdoc/gst-plugin/gst_plugin/). The whole
API builds upon the [application-side GStreamer bindings](https://gitlab.freedesktop.org/gstreamer/gstreamer-rs).
Check the README.md of that repository also for details about how to set-up
your development environment.

Various example plugins can be found in the [GIT repository](https://gitlab.freedesktop.org/gstreamer/gst-plugin-rs/). A blog post series about writing GStreamer plugins/elements can be found [here](https://coaxion.net/blog/2018/01/how-to-write-gstreamer-elements-in-rust-part-1-a-video-filter-for-converting-rgb-to-grayscale/)[2](https://coaxion.net/blog/2018/02/how-to-write-gstreamer-elements-in-rust-part-2-a-raw-audio-sine-wave-source/).

For background and motivation, see the [announcement
blogpost](https://coaxion.net/blog/2016/05/writing-gstreamer-plugins-and-elements-in-rust/)
and the follow-up blogposts
[1](https://coaxion.net/blog/2016/09/writing-gstreamer-elements-in-rust-part-2-dont-panic-we-have-better-assertions-now-and-other-updates/),
[2](https://coaxion.net/blog/2016/11/writing-gstreamer-elements-in-rust-part-3-parsing-data-from-untrusted-sources-like-its-2016/),
[3](https://coaxion.net/blog/2017/03/writing-gstreamer-elements-in-rust-part-4-logging-cows-and-plugins/).
Note that the overall implementation has changed completely since those
blogposts were written.

## LICENSE

gst-plugin-rs and all crates contained in here that are not listed below are
licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

gst-plugin-togglerecord is licensed under the Lesser General Public License
([LICENSE-LGPLv2](LICENSE-LGPLv2)) version 2.1 or (at your option) any later
version.

GStreamer itself is licensed under the Lesser General Public License version
2.1 or (at your option) any later version:
https://www.gnu.org/licenses/lgpl-2.1.html

## Contribution

Any kinds of contributions are welcome as a pull request.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in gst-plugin-rs by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
