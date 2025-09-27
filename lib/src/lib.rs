#![doc = include_str!("../../README.md")]
#![cfg_attr(not(any(feature = "mx", test)), no_std)]
#![cfg_attr(not(any(feature = "mx", feature = "ndd")), forbid(unsafe_code))]
#![cfg_attr(any(feature = "mx", feature = "ndd"), feature(mutex_data_ptr))] // https://github.com/rust-lang/rust/issues/140368
#![cfg_attr(feature = "hpe", feature(hasher_prefixfree_extras))] //  https://github.com/rust-lang/rust/issues/96762
#![cfg_attr(feature = "flags", feature(adt_const_params))]
// https://github.com/rust-lang/rust/issues/95174
//#![cfg_attr(feature = "chk-details", feature(format_args))]
#![cfg_attr(feature = "chk-details", allow(internal_features))]
#![cfg_attr(
    feature = "chk-details",
    // No tracking issues (as of mid 2025). Only
    // https://doc.rust-lang.org/nightly/unstable-book/library-features/const-format-args.html
    // https://doc.rust-lang.org/nightly/unstable-book/library-features/fmt-internals.html
    // https://doc.rust-lang.org/nightly/unstable-book/library-features/panic-internals.html
    feature(const_format_args, fmt_internals, panic_internals)
)]
// - const_index https://github.com/rust-lang/rust/issues/143775
// - const_trait_impl https://github.com/rust-lang/rust/issues/143874
//
// @TODO const_index:
//
//#![cfg_attr(feature = "chk-details", feature(const_index, const_trait_impl))]
#![cfg_attr(feature = "chk-details", feature(const_trait_impl))]
#![forbid(unused_must_use)]

#[cfg(all(feature = "mx", feature = "ndd"))]
compile_error!("Do not use both 'mx' and 'ndd' cargo feature.");

pub use flags::{ProtocolFlags, new};
pub use hasher::{SignalledInjectionBuildHasher, SignalledInjectionHasher};
pub use signal::inject;

mod flags;
mod hasher;
mod signal;
mod state;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
