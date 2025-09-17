use core::hash::Hasher;
use core::hint;
use core::str;
#[cfg(feature = "mx")]
use std::sync::Mutex;

use crate::flags;
use crate::flags::signal_via;
pub use flags::{
    _ProtocolFlagsSignalledViaLen, _ProtocolFlagsSignalledViaStr, _ProtocolFlagsSubset, Flow,
    ProtocolFlags, SignalVia,
};

/// A fictitious slice length, which represents a signal that we either just handed an injected
/// hash, or we are about to hand it - depending on whether we signal first, or submit first.
pub const LEN_SIGNAL_HASH: usize = usize::MAX;

#[cfg(feature = "chk-flow")]
/// A fictitious slice length, indicating that a [`core::hash::Hash`] implementation submits a hash
/// first (before signalling).
pub const LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST: usize = usize::MAX - 1;
#[cfg(feature = "chk-flow")]
/// A fictitious slice length, indicating that a [`core::hash::Hash`] implementation signals first (before submitting a hash).
pub const LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST: usize = usize::MAX - 2;

#[cfg(feature = "mx")]
type U8_ARR = [u8; 3];
#[cfg(feature = "mx")]
static MX: Mutex<U8_ARR> = hint::black_box(Mutex::new([b'A', b'B', b'C']));
fn str_full() -> &'static str {
    let bytes = unsafe { &*MX.data_ptr() as &U8_ARR };
    let bytes_slice = &bytes[..];
    // @TODO earlier: str::from_utf8(bytes_slice) // CHECKED
    unsafe { str::from_utf8_unchecked(bytes_slice) }
}
pub fn str_signal_hash() -> &'static str {
    unsafe { str_full().get_unchecked(0..1) }
}
pub fn str_signal_check_flow_is_submit_first() -> &'static str {
    unsafe { str_full().get_unchecked(1..2) }
}
pub fn str_signal_check_flow_is_signal_first() -> &'static str {
    unsafe { str_full().get_unchecked(2..3) }
}

#[inline(always)]
fn signal<H: Hasher>(PF: ProtocolFlags, hasher: &mut H) {
    match flags::signal_via(PF) {
        SignalVia::Len => hasher.write_length_prefix(LEN_SIGNAL_HASH),
        SignalVia::Str => hasher.write_str(str_signal_hash()),
    };
}

/// For use with [crate::hasher::SignalledInjectionHasher] `created by
/// [crate::hasher::SignalledInjectionBuildHasher].
///
/// Be careful when using this function with standard/third party [Hasher] (and
/// [core::hash::BuildHasher]) implementations.
/// - You CAN use this when comparing the intended hash to instances of the SAME type, or any type
///   that signals the same intended hash. BUT
/// - The actual hash (retrieved by a [Hasher] created by an entropy-based
///   [core::hash::BuildHasher]) will NOT be the intended (signalled) hash. AND
/// - Consequently, you CANNOT use this when comparing the intended hash to instances of a vanilla
///   type, even if the intended hash comes from that vanilla type (by a [Hasher] created by the
///   same [core::hash::BuildHasher]).
///   
/// - [core::borrow::Borrow]) where that other type does NOT use [inject] (and, for example,
///   the intended hash comes from that other type's [`core::hash::Hash::hash`] on a [Hasher]
///   created by the same [core::hash::BuildHasher].)
///
/// Extra validation of signalling in the user's [core::hash::Hash] implementation is done ONLY in
/// when built with relevant cargo features (`chk-flow`, `chk-hash`, `chk`).
pub fn inject<H: Hasher, const PF: ProtocolFlags>(hasher: &mut H, hash: u64)
where
    _ProtocolFlagsSubset<PF>: _ProtocolFlagsSignalledViaLen,
{
    match flags::flow(PF) {
        Flow::SubmitFirst => {
            hasher.write_u64(hash);
            signal(PF, hasher);
        }
        Flow::SignalFirst => {
            signal(PF, hasher);
            hasher.write_u64(hash);
        }
    }
    // Check that finish() does return the signalled hash. We do this BEFORE
    // chk-flow-based checks (if any).
    #[cfg(feature = "chk-hash")]
    assert_eq!(hasher.finish(), hash);

    #[cfg(feature = "chk-flow")]
    match flags::flow(PF) {
        Flow::SubmitFirst => {
            match flags::signal_via(PF) {
                SignalVia::Len => hasher.write_length_prefix(LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST),
                SignalVia::Str => hasher.write_str(str_signal_check_flow_is_submit_first()),
            };
        }
        Flow::SignalFirst => {
            match flags::signal_via(PF) {
                SignalVia::Len => hasher.write_length_prefix(LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST),
                SignalVia::Str => hasher.write_str(str_signal_check_flow_is_signal_first()),
            };
        }
    }
}
