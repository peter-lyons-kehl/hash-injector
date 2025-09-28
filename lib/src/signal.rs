use core::hash::Hasher;
//use core::slice;

#[cfg(feature = "mx")]
use core::hint;
#[cfg(any(feature = "mx", feature = "ndd"))]
use core::{ptr, str};
#[cfg(feature = "ndd")]
use ndd::NonDeDuplicated;
#[cfg(feature = "mx")]
use std::sync::Mutex;

use crate::flags;
use flags::{Flow, HashVia, ProtocolFlags, SignalVia};

#[cfg(feature = "hpe")]
/// A fictitious slice length, which represents a signal that we either just handed an injected
/// hash, or we are about to hand it - depending on whether we signal first, or submit first.
pub const LEN_SIGNAL_HASH: usize = usize::MAX;

#[cfg(all(feature = "hpe", feature = "chk-flow"))]
/// A fictitious slice length, indicating that a [`core::hash::Hash`] implementation submits a hash
/// first (before signalling).
pub const LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST: usize = usize::MAX - 1;
#[cfg(all(feature = "hpe", feature = "chk-flow"))]
/// A fictitious slice length, indicating that a [`core::hash::Hash`] implementation signals first
/// (before submitting a hash).
pub const LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST: usize = usize::MAX - 2;

#[cfg(any(feature = "mx", feature = "ndd"))]
type U8Array = [u8; 3];
#[cfg(feature = "mx")]
static SIG_MX: Mutex<U8Array> = hint::black_box(Mutex::new([b'A', b'B', b'C']));
#[cfg(feature = "ndd")]
static SIG_NDD: NonDeDuplicated<U8Array> = NonDeDuplicated::new([b'A', b'B', b'C']);

#[cfg(any(feature = "mx", feature = "ndd"))]
#[inline(always)]
fn str_full() -> &'static str {
    // TODO check whether the following is the same, or whether it creates a temporary local array!
    //
    //let bytes = &*NDD;
    #[cfg(feature = "ndd")]
    let bytes = SIG_NDD.get();
    #[cfg(feature = "mx")]
    let bytes = unsafe { &*SIG_MX.data_ptr() as &U8Array };
    let bytes_slice = bytes.as_slice();
    #[cfg(feature = "ndd")]
    return str::from_utf8(bytes_slice).unwrap();
    #[cfg(feature = "mx")]
    return unsafe { str::from_utf8_unchecked(bytes_slice) };
}
#[cfg(any(feature = "mx", feature = "ndd"))]
#[inline(always)]
pub fn str_signal_hash() -> &'static str {
    #[cfg(feature = "ndd")]
    return str_full().get(0..1).unwrap();
    #[cfg(feature = "mx")]
    return unsafe { str_full().get_unchecked(0..1) };
}
#[cfg(all(any(feature = "mx", feature = "ndd"), feature = "chk-flow"))]
#[inline(always)]
pub fn str_signal_check_flow_is_submit_first() -> &'static str {
    #[cfg(feature = "ndd")]
    return str_full().get(1..2).unwrap();
    #[cfg(feature = "mx")]
    return unsafe { str_full().get_unchecked(1..2) };
}
#[cfg(all(any(feature = "mx", feature = "ndd"), feature = "chk-flow"))]
#[inline(always)]
pub fn str_signal_check_flow_is_signal_first() -> &'static str {
    #[cfg(feature = "ndd")]
    return str_full().get(2..3).unwrap();
    #[cfg(feature = "mx")]
    return unsafe { str_full().get_unchecked(2..3) };
}

#[cfg(any(feature = "mx", feature = "ndd"))]
#[inline(always)]
pub fn u8s_signal_hash() -> &'static [u8] {
    str_signal_hash().as_bytes()
}
#[cfg(all(any(feature = "mx", feature = "ndd"), feature = "chk-flow"))]
#[inline(always)]
pub fn u8s_signal_check_flow_is_submit_first() -> &'static [u8] {
    str_signal_check_flow_is_submit_first().as_bytes()
}
#[cfg(all(any(feature = "mx", feature = "ndd"), feature = "chk-flow"))]
#[inline(always)]
pub fn u8s_signal_check_flow_is_signal_first() -> &'static [u8] {
    str_signal_check_flow_is_signal_first().as_bytes()
}

#[cfg(any(feature = "mx", feature = "ndd"))]
#[inline(always)]
fn ptr_signal_hash() -> *const u8 {
    #[cfg(feature = "ndd")]
    panic!("TODO");
    #[cfg(feature = "mx")]
    return SIG_MX.data_ptr() as *const u8;
}
#[cfg(any(feature = "mx", feature = "ndd"))]
#[inline(always)]
pub fn is_ptr_signal_hash(other: *const u8) -> bool {
    ptr::eq(ptr_signal_hash(), other)
}
#[cfg(all(any(feature = "mx", feature = "ndd"), feature = "chk-flow"))]
#[inline(always)]
pub fn is_ptr_signal_check_flow_is_submit_first(other: *const u8) -> bool {
    #[cfg(feature = "ndd")]
    return ptr::eq(ptr_signal_hash().wrapping_add(1), other);
    #[cfg(feature = "mx")]
    return ptr::eq(unsafe { ptr_signal_hash().add(1) }, other);
}
#[cfg(all(any(feature = "mx", feature = "ndd"), feature = "chk-flow"))]
#[inline(always)]
pub fn is_ptr_signal_check_flow_is_signal_first(other: *const u8) -> bool {
    #[cfg(feature = "ndd")]
    return ptr::eq(ptr_signal_hash().wrapping_add(2), other);
    #[cfg(feature = "mx")]
    return ptr::eq(unsafe { ptr_signal_hash().add(2) }, other);
}

#[inline(always)]
fn signal<H: Hasher>(#[allow(non_snake_case)] PF: ProtocolFlags, _hasher: &mut H) {
    match flags::signal_via(PF) {
        SignalVia::U8s => {
            #[cfg(any(feature = "mx", feature = "ndd"))]
            _hasher.write(u8s_signal_hash());
            #[cfg(not(any(feature = "mx", feature = "ndd")))]
            unreachable!()
        }
        SignalVia::Len => {
            #[cfg(feature = "hpe")]
            _hasher.write_length_prefix(LEN_SIGNAL_HASH);
            #[cfg(not(feature = "hpe"))]
            unreachable!()
        }
        SignalVia::Str => {
            #[cfg(all(any(feature = "mx", feature = "ndd"), feature = "hpe"))]
            _hasher.write_str(str_signal_hash());
            #[cfg(not(all(any(feature = "mx", feature = "ndd"), feature = "hpe")))]
            unreachable!()
        }
    };
}

#[inline(always)]
fn submit_hash<H: Hasher, const PF: ProtocolFlags>(hasher: &mut H, hash: u64) {
    match flags::hash_via(PF) {
        HashVia::U64 => {
            hasher.write_u64(hash);
        }
        HashVia::I64 => {
            hasher.write_i64(hash as i64);
        }
        HashVia::U128 => {
            hasher.write_u128(hash as u128);
        }
        HashVia::I128 => {
            hasher.write_i128(hash as i128);
        }
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
pub fn inject<H: Hasher, const PF: ProtocolFlags>(hasher: &mut H, hash: u64) {
    match flags::flow(PF) {
        Flow::SubmitFirst => {
            submit_hash::<_, PF>(hasher, hash);
            signal(PF, hasher);
        }
        Flow::SignalFirst => {
            signal(PF, hasher);
            submit_hash::<_, PF>(hasher, hash);
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
                SignalVia::U8s => {
                    #[cfg(any(feature = "mx", feature = "ndd"))]
                    hasher.write(u8s_signal_check_flow_is_submit_first());
                    #[cfg(not(any(feature = "mx", feature = "ndd")))]
                    unreachable!()
                }

                SignalVia::Len => {
                    #[cfg(feature = "hpe")]
                    hasher.write_length_prefix(LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST);
                    #[cfg(not(feature = "hpe"))]
                    unreachable!()
                }
                SignalVia::Str => {
                    #[cfg(all(any(feature = "mx", feature = "ndd"), feature = "hpe"))]
                    hasher.write_str(str_signal_check_flow_is_submit_first());
                    #[cfg(not(all(any(feature = "mx", feature = "ndd"), feature = "hpe")))]
                    unreachable!()
                }
            };
        }
        Flow::SignalFirst => {
            match flags::signal_via(PF) {
                SignalVia::U8s => {
                    #[cfg(any(feature = "mx", feature = "ndd"))]
                    hasher.write(u8s_signal_check_flow_is_signal_first());
                    #[cfg(not(any(feature = "mx", feature = "ndd")))]
                    unreachable!()
                }
                SignalVia::Len => {
                    #[cfg(feature = "hpe")]
                    hasher.write_length_prefix(LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST);
                    #[cfg(not(feature = "hpe"))]
                    unreachable!()
                }
                SignalVia::Str => {
                    #[cfg(all(any(feature = "mx", feature = "ndd"), feature = "hpe"))]
                    hasher.write_str(str_signal_check_flow_is_signal_first());
                    #[cfg(not(all(any(feature = "mx", feature = "ndd"), feature = "hpe")))]
                    unreachable!()
                }
            };
        }
    }
}
