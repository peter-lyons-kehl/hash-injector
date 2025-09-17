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

struct SealedTraitParam;

pub trait LikeStr {
    #[allow(private_interfaces)]
    fn sealed_trait(_: &SealedTraitParam);
    fn slice(&'static self) -> &'static str;
}
impl LikeStr for str {
    #[allow(private_interfaces)]
    fn sealed_trait(_: &SealedTraitParam) {}
    fn slice(&'static self) -> &'static str {
        self
    }
}

const fn c_str<S: LikeStr + ?Sized>(s: &'static S) {}
const C: () = c_str("a");

pub trait SignalStrTr {
    #[allow(private_interfaces)]
    fn sealed_trait(_: &SealedTraitParam);
    fn slice(&'static self) -> &'static str;
}
// Its field is intentionally not public, so that the struct can't be constructed publicly, so that
// users don't accidentally pass static string slices that share addresses with other data.
pub struct WrapStr(&'static str);
impl SignalStrTr for str {
    #[allow(private_interfaces)]
    fn sealed_trait(_: &SealedTraitParam) {}
    fn slice(&'static self) -> &'static str {
        self
    }
}
impl SignalStrTr for WrapStr {
    #[allow(private_interfaces)]
    fn sealed_trait(_: &SealedTraitParam) {}
    fn slice(&'static self) -> &'static str {
        self.0
    }
}

const fn c_sstr<S: SignalStrTr + ?Sized>(s: &'static S) {}
const CS: () = c_sstr("a");
const CW: () = c_sstr(&WrapStr("a"));

impl From<String> for WrapStr {
    /// Parameter `s` needs to have length at least 2
    fn from(s: String) -> Self {
        assert!(s.len() >= 2);
        Self(s.leak())
    }
}
// This would require:
// - #![feature(const_index)] - https://github.com/rust-lang/rust/issues/143775
// - #![feature(const_trait_impl)] - https://github.com/rust-lang/rust/issues/143874
//
//const USB_STR: &'static str = &"abc"[0..1];

fn u_str() -> &'static str {
    &"abc"[0..1]
}

/// Used when we signal to signal hwen
pub trait SignalStrs {
    /// Respective to [FICTITIOUS_LEN_SIGNALLING].
    fn signalling(&self) -> &'static str;
    #[cfg(feature = "chk-flow")]
    /// Respective to [FICTITIOUS_LEN_EXPECTING_SUBMIT_FIRST_METHOD].
    fn expecting_submit_first_method(&self) -> &'static str;
    #[cfg(feature = "chk-flow")]
    /// Respective to [FICTITIOUS_LEN_EXPECTING_SIGNAL_FIRST_METHOD].
    fn expecting_signal_first_method(&self) -> &'static str;
    #[allow(private_interfaces)]
    fn sealed_trait(_: &SealedTraitParam);
}

pub trait ValidationPtrs {
    #[allow(private_interfaces)]
    fn sealed_trait(_: &SealedTraitParam);
}
/// Indicates static `str` slices to pass to [Hasher::write_length_prefix] for
/// - signalling (that a hash is about to be submitted, or that a hash has been just submitted), and
/// - signalling to the [Hasher] so it check that both the hashable type and [Hasher] use same
///   protocol flow (submit first, or signal first) - if enabled with cargo feature `chk-flow`.
///
/// Its fields are intentionally not public, so that the struct can't be constructed publicly.
/// Otherwise users could accidentally pass static string slices that share addresses with other
/// data.
pub struct SignalStrsSlices {
    /// Respective to [FICTITIOUS_LEN_SIGNALLING].
    signalling: &'static str,
    #[cfg(feature = "chk-flow")]
    /// Respective to [FICTITIOUS_LEN_EXPECTING_SUBMIT_FIRST_METHOD].
    expecting_submit_first_method: &'static str,
    #[cfg(feature = "chk-flow")]
    /// Respective to [FICTITIOUS_LEN_EXPECTING_SIGNAL_FIRST_METHOD].
    expecting_signal_first_method: &'static str,
}

impl From<String> for SignalStrsSlices {
    /// Parameter `s` needs to have length at least 3 characters. This
    /// may create appropriate non-empty sub-slices, each with a different start (to short-circuit
    /// comparison). (Sub-slices are created only if needed, depending on `chk-flow` cargo
    /// feature. However, for consistency, we require that minimum length regardless of the cargo
    /// feature.)
    fn from(s: String) -> Self {
        assert!(s.len() >= 3);
        let s = s.leak();
        Self {
            signalling: &s[0..1],
            expecting_submit_first_method: &s[1..2],
            expecting_signal_first_method: &s[2..3],
        }
    }
}

impl SignalStrs for SignalStrsSlices {
    fn signalling(&self) -> &'static str {
        self.signalling
    }
    fn expecting_submit_first_method(&self) -> &'static str {
        self.expecting_submit_first_method
    }
    fn expecting_signal_first_method(&self) -> &'static str {
        self.expecting_signal_first_method
    }
    fn sealed_trait(_: &SealedTraitParam) {}
}

static ABC: &'static str = "ABC";
//static A: *const u8 = ABC.as_ptr();
//static A: Mutex<&'static u8> = *const u8 = ABC.as_ptr();

static A: &'static u8 = ABC.as_bytes().first().unwrap();

static XY: [u8; 2] = [b'X', b'Y'];
static X: &'static u8 = XY.first().unwrap();
