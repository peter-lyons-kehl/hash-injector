#![doc = include_str!("../../README.md")]
#![cfg_attr(not(any(feature = "lz", feature = "mx", feature = "mx-ptr")), no_std)]
#![cfg_attr(not(feature = "mx-ptr"), forbid(unsafe_code))]
// @TODO comment out:
//#![cfg_attr(feature = "mx-ptr", feature(const_index))] // https://github.com/rust-lang/rust/issues/143775
// @TODO comment out:
//#![cfg_attr(feature = "mx-ptr", feature(const_trait_impl))] // https://github.com/rust-lang/rust/issues/143874
#![cfg_attr(feature = "mx-ptr", feature(mutex_data_ptr))] // https://github.com/rust-lang/rust/issues/140368
#![feature(hasher_prefixfree_extras)]
#![cfg_attr(feature = "flags", feature(adt_const_params))]

#[cfg(feature = "string")]
extern crate alloc;

pub use flags::{
    _ProtocolFlagsSignalledViaLen, _ProtocolFlagsSignalledViaStr, _ProtocolFlagsSubset,
    ProtocolFlags, new,
};
use signal::{
    LEN_SIGNAL_CHECK_METHOD_IS_SIGNAL_FIRST, LEN_SIGNAL_CHECK_METHOD_IS_SUBMIT_FIRST,
    LEN_SIGNAL_HASH,
};
use state::SignalState;

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
