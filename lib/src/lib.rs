#![doc = include_str!("../../README.md")]
#![cfg_attr(not(feature = "mx"), no_std)]
#![cfg_attr(not(feature = "mx"), forbid(unsafe_code))]
#![cfg_attr(feature = "mx", feature(mutex_data_ptr))] // https://github.com/rust-lang/rust/issues/140368
#![cfg_attr(feature = "hpe", feature(hasher_prefixfree_extras))] //  https://github.com/rust-lang/rust/issues/96762
#![cfg_attr(feature = "flags", feature(adt_const_params))]
//#![cfg_attr(feature = "chk-details", feature(format_args))]
#![cfg_attr(feature = "chk-details", allow(internal_features))]
#![cfg_attr(
    feature = "chk-details",
    feature(const_format_args, fmt_internals, panic_internals)
)]
#![forbid(unused_must_use)]

pub use flags::{
    //_ProtocolFlagsSignalledViaLen, _ProtocolFlagsSignalledViaStr, _ProtocolFlagsSubset,
    ProtocolFlags,
    new,
};
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
