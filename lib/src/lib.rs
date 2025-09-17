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
#[cfg(feature = "string")]
use alloc::string::String;

use core::hash::{BuildHasher, Hasher};
use core::hint;
use core::str;
#[cfg(feature = "lz")]
use std::sync::LazyLock;
#[cfg(feature = "mx-ptr")]
use std::sync::Mutex;

pub use flags::{
    _ProtocolFlagsSignalledViaLen, _ProtocolFlagsSignalledViaStr, _ProtocolFlagsSubset,
    ProtocolFlags, new,
};
use state::SignalState;

mod flags;
mod state;

/// A fictitious slice length, which represents a signal that we either just handed an injected
/// hash, or we are about to hand it - depending on whether we signal first, or submit first.
const LEN_SIGNAL_HASH: usize = usize::MAX;

#[cfg(feature = "chk-flow")]
/// A fictitious slice length, indicating that a [`core::hash::Hash`] implementation submits a hash
/// first (before signalling).
const LEN_SIGNAL_CHECK_METHOD_IS_SUBMIT_FIRST: usize = usize::MAX - 1;
#[cfg(feature = "chk-flow")]
/// A fictitious slice length, indicating that a [`core::hash::Hash`] implementation signals first (before submitting a hash).
const LEN_SIGNAL_CHECK_METHOD_IS_SIGNAL_FIRST: usize = usize::MAX - 2;

#[cfg(feature = "mx-ptr")]
const STR_SIGNAL_BYTE_HASH: u8 = b'A';
#[cfg(all(feature = "mx-ptr", feature = "chk-flow"))]
const LEN_SIGNAL_BYTE_CHECK_METHOD_IS_SUBMIT_FIRST: u8 = b'B';
#[cfg(all(feature = "mx-ptr", feature = "chk-flow"))]
const LEN_SIGNAL_BYTE_CHECK_METHOD_IS_SIGNAL_FIRST: u8 = b'C';

#[cfg(feature = "mx-ptr")]
/// This has to be mutable, so that the compiler or LLVM doesn't optimize it away and de-duplicate.
static STR_SIGNAL_BYTES: [u8; 3] = [
    STR_SIGNAL_BYTE_HASH,
    LEN_SIGNAL_BYTE_CHECK_METHOD_IS_SUBMIT_FIRST,
    LEN_SIGNAL_BYTE_CHECK_METHOD_IS_SIGNAL_FIRST,
];

/*#[cfg(feature = "mut-static")]
static SIGNAL_STRS: SignalStrs = {
    if let Ok(slice) = str::from_utf8(unsafe {
        // We pass the pointer to black_box(...) as a mut pointer, so that Rust or LLVM doesn't
        // optimize it away and doesn't de-duplicate.
        let ptr = hint::black_box(&raw mut SIGNAL_ARR) as *const [u8; 2];
        &*ptr
    }) {
        assert!(slice.len() >= 2);
        SignalStrs {
            signalling: slice,
            expecting_submit_first_method: &slice[1..],
            expecting_signal_first_method: &slice[2..],
        }
    } else {
        panic!();
    }
};*/

#[cfg(feature = "string")] // TODO feature: std
type ARR = [u8; 3];
static ARR_MX: Mutex<ARR> = hint::black_box(Mutex::new([b'A', b'B', b'C']));
static SIGNAL_STRS_MX: () = {
    //ARR_MX.data_ptr();
};
static STRI: String = String::new();
fn utf8_str() {
    let bytes = unsafe { &*ARR_MX.data_ptr() as &ARR };
    let bytes_slice = &bytes[..];
    // @TODO earlier: str::from_utf8(bytes_slice) // CHECKED
    let utf8 = unsafe { str::from_utf8_unchecked(bytes_slice) };
}

/// For use with [SignalledInjectionHasher] `created by [SignalledInjectionBuildHasher].
///
/// Be careful when using this function with standard/third party [Hasher] (and [BuildHasher])
/// implementations.
/// - You CAN use this when comparing the intended hash to instances of the SAME type, or any type
///   that signals the same intended hash. BUT
/// - The actual hash (retrieved by a [Hasher] created by an entropy-based [BuildHasher]) will NOT
///   be the intended (signalled) hash. AND
/// - Consequently, you CANNOT use this when comparing the intended hash to instances of a vanilla
///   type, even if the intended hash comes from that vanilla type (by a [Hasher] created by the
///   same [BuildHasher]).
///
///   [core::borrow::Borrow]) where that other type does NOT use [inject_via_len] (and, for
///   example, the intended hash comes from that other type's `Hash::hash` on a [Hasher] created by
///   the same [BuildHasher].)
///
/// Extra validation of signalling in the user's [core::hash::Hash] implementation is done ONLY in
/// when built with `chk` feature.
pub fn inject_via_len<H: Hasher, const PF: ProtocolFlags>(hasher: &mut H, hash: u64)
where
    _ProtocolFlagsSubset<PF>: _ProtocolFlagsSignalledViaLen,
{
    // extra check, in addition to the check with _ProtocolFlagsSignalledViaLen
    debug_assert!(flags::is_signal_via_len(PF));
    // The order of operations is intentionally different for SIGNAL_FIRST. This (hopefully) helps
    // us notice any logical errors or opportunities for improvement in this module earlier.
    if flags::is_signal_first(PF) {
        hasher.write_length_prefix(LEN_SIGNAL_HASH);
        hasher.write_u64(hash);
    } else {
        hasher.write_u64(hash);
        hasher.write_length_prefix(LEN_SIGNAL_HASH);
    }
    // Check that finish() does return the signalled hash. We do this BEFORE
    // chk-flow-based checks (if any).
    #[cfg(feature = "chk-hash")]
    assert_eq!(hasher.finish(), hash);

    #[cfg(feature = "chk-flow")]
    hasher.write_length_prefix(if flags::is_signal_first(PF) {
        LEN_SIGNAL_CHECK_METHOD_IS_SIGNAL_FIRST
    } else {
        LEN_SIGNAL_CHECK_METHOD_IS_SUBMIT_FIRST
    });
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

#[cfg(feature = "string")]
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

#[cfg(feature = "string")]
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

/// We pass `signal_str` by value (rather than by reference), because if `chk-flow` cargo
/// feature is disabled then [SignalStrs] is small.
pub fn inject_via_str<H: Hasher, S: SignalStrs, const PF: ProtocolFlags>(
    hasher: &mut H,
    hash: u64,
    signal: S,
) where
    _ProtocolFlagsSubset<PF>: _ProtocolFlagsSignalledViaStr,
{
    // extra check, in addition to the check with _ProtocolFlagsSignalledViaStr
    debug_assert!(flags::is_signal_via_str(PF));
    todo!();
}

pub struct SignalledInjectionHasher<H: Hasher, const PF: ProtocolFlags> {
    hasher: H,
    state: SignalState,
}
impl<H: Hasher, const PF: ProtocolFlags> SignalledInjectionHasher<H, PF> {
    #[inline]
    const fn new(hasher: H) -> Self {
        Self {
            hasher,
            state: SignalState::new_nothing_written(),
        }
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn written_ordinary_hash(&mut self) {
        self.state.set_written_ordinary_hash();
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written(&self) {
        #[cfg(feature = "chk")]
        assert!(self.state.is_nothing_written());
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written_or_ordinary_hash(&self) {
        #[cfg(feature = "chk")]
        assert!(
            self.state.is_nothing_written_or_ordinary_hash(),
            "Expecting the state to be NothingWritten or WrittenOrdinaryHash, but the state was: {:?}",
            self.state
        );
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    /// Assert that
    /// - no hash has been signalled (if we do signal first - before submitting), and
    /// - no hash has been received (regardless of whether we signal first, or submit first).
    #[inline(always)]
    fn assert_nothing_written_or_ordinary_hash_or_possibly_submitted(&self) {
        #[cfg(feature = "chk")]
        {
            assert!(
                self.state
                    .is_nothing_written_or_ordinary_hash_or_possibly_submitted(PF),
                "Expecting the state to be NothingWritten or WrittenOrdinaryHash, or HashPossiblySubmitted (if applicable), but the state was: {:?}",
                self.state
            );
        }
    }
}
impl<H: Hasher, const PF: ProtocolFlags> Hasher for SignalledInjectionHasher<H, PF> {
    #[inline]
    fn finish(&self) -> u64 {
        if self.state.is_hash_received() {
            self.state.hash
        } else {
            self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
            self.hasher.finish()
        }
    }
    /// This does NOT signal, even if you handed it the same bytes as [`inject_via_len`] passes
    /// through `write_length_prefix` and `write_u64` when signalling.
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write(bytes);
        self.written_ordinary_hash();
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_u8(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_u16(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_u32(i);
        self.written_ordinary_hash();
    }
    fn write_u64(&mut self, i: u64) {
        // the outer if check can get optimized away (const)
        if flags::is_signal_via_len(PF) {
            // @TODO
        }
        if flags::is_signal_first(PF) {
            if self.state.is_signalled_proposal_coming(PF) {
                self.state = SignalState::new_hash_received(i);
            } else {
                self.assert_nothing_written_or_ordinary_hash();
                self.hasher.write_u64(i);
                self.written_ordinary_hash();
            }
        } else {
            self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
            // If we are indeed signalling, then after the following write_u64(...) the value
            // written to the underlying Hasher will NOT be used, because finish(&self) then returns
            // the injected hash - instead of calling the underlying Hasher's finish(). So, the
            // compiler MAY optimize the following call away (thanks to Hasher objects being passed
            // by generic reference - instead of a &dyn trait reference):
            self.hasher.write_u64(i);
            if self.state.is_nothing_written() {
                self.state = SignalState::new_hash_possibly_submitted(i, PF);
            } else {
                // In case the hash was "possibly_submitted", submitting any more data (u64 or
                // otherwise) invalidates it.
                self.state.set_written_ordinary_hash();
            }
        }
    }
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_u128(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_usize(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i8(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i16(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i32(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i64(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i128(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_isize(i);
        self.written_ordinary_hash();
    }
    fn write_length_prefix(&mut self, len: usize) {
        // the outer if check can get optimized away (const)
        if flags::is_signal_first(PF) {
            if len == LEN_SIGNAL_HASH {
                self.assert_nothing_written();
                self.state.set_signalled_proposal_coming(PF);
            } else {
                #[cfg(feature = "chk-flow")]
                {
                    if len == LEN_SIGNAL_CHECK_METHOD_IS_SIGNAL_FIRST {
                        return; // just being checked (no data to write)
                    }
                    assert_ne!(len, LEN_SIGNAL_CHECK_METHOD_IS_SUBMIT_FIRST);
                }

                self.assert_nothing_written_or_ordinary_hash();
                self.hasher.write_length_prefix(len);
                self.written_ordinary_hash();
            }
        } else {
            if len == LEN_SIGNAL_HASH {
                if self.state.is_hash_possibly_submitted(PF) {
                    self.state.set_hash_received();
                } else {
                    #[cfg(feature = "chk")]
                    assert!(
                        false,
                        "Expected state HashPossiblySubmitted, but it was {:?}.",
                        self.state
                    );

                    self.hasher.write_length_prefix(len);
                    self.written_ordinary_hash();
                }
            } else {
                #[cfg(feature = "chk-flow")]
                {
                    if len == LEN_SIGNAL_CHECK_METHOD_IS_SUBMIT_FIRST {
                        return; // just being checked (no data to write)
                    }
                    assert_ne!(len, LEN_SIGNAL_CHECK_METHOD_IS_SIGNAL_FIRST);
                }

                self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
                self.hasher.write_length_prefix(len);
                self.written_ordinary_hash();
            }
        }
    }

    #[inline]
    fn write_str(&mut self, s: &str) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_str(s);
        self.written_ordinary_hash();
    }
}

pub struct SignalledInjectionBuildHasher<
    H: Hasher,
    B: BuildHasher<Hasher = H>,
    const PF: ProtocolFlags,
> {
    build: B,
}
impl<H: Hasher, B: BuildHasher<Hasher = H>, const PF: ProtocolFlags>
    SignalledInjectionBuildHasher<H, B, PF>
{
    pub fn new(build: B) -> Self {
        Self { build }
    }
}
impl<H: Hasher, B: BuildHasher<Hasher = H>, const PF: ProtocolFlags> BuildHasher
    for SignalledInjectionBuildHasher<H, B, PF>
{
    type Hasher = SignalledInjectionHasher<H, PF>;

    // Required method
    fn build_hasher(&self) -> Self::Hasher {
        SignalledInjectionHasher::new(self.build.build_hasher())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
