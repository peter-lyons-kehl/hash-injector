#![forbid(unsafe_code)]

use core::hash::{BuildHasher, Hasher};
#[cfg(feature = "adt-const-params")]
use core::marker::ConstParamTy;

mod state;
use state::SignalState;

#[cfg(all(
    feature = "injector-checks-same-protocol",
    not(feature = "injector-checks-finish")
))]
const _SAME_FLOW_CHECK_REQUIRES_FINISH_CHECK: () = {
    panic!(
        "Feature injector-checks-same-protocol is enabled, but it requires feature injector-checks-finish, too."
    );
};

/// A fictitious slice length, which represents a signal that we either just handed an injected
/// hash, or we are about to hand it - depending on whether we signal first, or submit first.
const SIGNALLING: usize = usize::MAX;

/// A fictitious slice length, indicating that a [`core::hash::Hash`] implementation submits a hash first (before signalling).
#[cfg(feature = "injector-checks-same-protocol")]
const EXPECTING_SUBMIT_FIRST_METHOD: usize = usize::MAX - 2;
#[cfg(feature = "injector-checks-same-protocol")]
/// A fictitious slice length, indicating that a [`core::hash::Hash`] implementation signals first (before submitting a hash).
const EXPECTING_SIGNAL_FIRST_METHOD: usize = usize::MAX - 1;

/// An enum-like Type for const generic parameter `IF`. Use `new_flags_xxx` functions to create the
/// values.
///
/// Do not compare with/store as/pass as values of other types - the actual implementation of the
/// type is subject to change.
pub type InjectionFlags = InjectionFlagsImpl;

// If we ever have more than one flag, then change this into e.g. u8.
#[cfg(not(feature = "adt-const-params"))]
type InjectionFlagsImpl = bool;

#[cfg(feature = "adt-const-params")]
/// Type for const generic parameter `F`.
#[derive(ConstParamTy, Clone, Copy, PartialEq, Eq)]
pub struct InjectionFlagsImpl {
    signal_first: bool,
}
pub const fn new_flags_signal_first() -> InjectionFlags {
    #[cfg(not(feature = "adt-const-params"))]
    {
        true
    }
    #[cfg(feature = "adt-const-params")]
    InjectionFlags { signal_first: true }
}
pub const fn new_flags_submit_first() -> InjectionFlags {
    #[cfg(not(feature = "adt-const-params"))]
    {
        false
    }
    #[cfg(feature = "adt-const-params")]
    InjectionFlags {
        signal_first: false,
    }
}
const fn signal_first(flags: InjectionFlags) -> bool {
    #[cfg(not(feature = "adt-const-params"))]
    {
        flags
    }
    #[cfg(feature = "adt-const-params")]
    {
        flags.signal_first
    }
}
const fn submit_first(flags: InjectionFlags) -> bool {
    #[cfg(not(feature = "adt-const-params"))]
    {
        !flags
    }
    #[cfg(feature = "adt-const-params")]
    {
        !flags.signal_first
    }
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
///   [core::borrow::Borrow]) where that other type does NOT use [signal_inject_hash] (and, for
///   example, the intended hash comes from that other type's `Hash::hash` on a [Hasher] created by
///   the same [BuildHasher].)
///
/// Extra validation of signalling in the user's [core::hash::Hash] implementation is done ONLY in
/// when built with `asserts` feature.
pub fn signal_inject_hash<H: Hasher, const IF: InjectionFlags>(hasher: &mut H, hash: u64) {
    // The order of operations is intentionally different for SIGNAL_FIRST. This (hopefully) helps us
    // notice any logical errors or opportunities for improvement in this module earlier.
    if signal_first(IF) {
        hasher.write_length_prefix(SIGNALLING);
        hasher.write_u64(hash);
    } else {
        hasher.write_u64(hash);
        hasher.write_length_prefix(SIGNALLING);
    }
    // Check that finish() does return the signalled hash. We do this BEFORE
    // injector-checks-same-protocol-based checks (if any).
    #[cfg(feature = "injector-checks-finish")]
    assert_eq!(hasher.finish(), hash);

    #[cfg(feature = "injector-checks-same-protocol")]
    hasher.write_length_prefix(if signal_first(IF) {
        EXPECTING_SIGNAL_FIRST_METHOD
    } else {
        EXPECTING_SUBMIT_FIRST_METHOD
    });
}

pub struct SignalledInjectionHasher<H: Hasher, const IF: InjectionFlags> {
    hasher: H,
    state: SignalState,
}
impl<H: Hasher, const IF: InjectionFlags> SignalledInjectionHasher<H, IF> {
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
        #[cfg(feature = "asserts")]
        assert!(self.state.is_nothing_written());
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written_or_ordinary_hash(&self) {
        #[cfg(feature = "asserts")]
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
        #[cfg(feature = "asserts")]
        {
            assert!(
                self.state
                    .is_nothing_written_or_ordinary_hash_or_possibly_submitted(IF),
                "Expecting the state to be NothingWritten or WrittenOrdinaryHash, or HashPossiblySubmitted (if applicable), but the state was: {:?}",
                self.state
            );
        }
    }
}
impl<H: Hasher, const IF: InjectionFlags> Hasher for SignalledInjectionHasher<H, IF> {
    #[inline]
    fn finish(&self) -> u64 {
        if self.state.is_hash_received() {
            self.state.hash
        } else {
            self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
            self.hasher.finish()
        }
    }
    /// This does NOT signal, even if you handed it the same bytes as [`signal_inject_hash`] passes
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
        if signal_first(IF) {
            if self.state.is_signalled_proposal_coming(IF) {
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
            // compiler can optimize the following call away (thanks to Hasher objects being passed
            // by generic reference - instead of a &dyn trait reference):
            self.hasher.write_u64(i);
            self.state = SignalState::new_hash_possibly_submitted(i, IF);
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
        if signal_first(IF) {
            if len == SIGNALLING {
                self.assert_nothing_written();
                self.state.set_signalled_proposal_coming(IF);
            } else {
                #[cfg(feature = "injector-checks-same-protocol")]
                {
                    if len == EXPECTING_SIGNAL_FIRST_METHOD {
                        return;
                    }
                    assert_ne!(len, EXPECTING_SUBMIT_FIRST_METHOD);
                }

                self.assert_nothing_written_or_ordinary_hash();
                self.hasher.write_length_prefix(len);
                self.written_ordinary_hash();
            }
        } else {
            if len == SIGNALLING {
                if self.state.is_hash_possibly_submitted(IF) {
                    self.state.set_hash_received();
                } else {
                    #[cfg(feature = "asserts")]
                    assert!(
                        false,
                        "Expected state HashPossiblySubmitted, but it was {:?}.",
                        self.state
                    );

                    self.hasher.write_length_prefix(len);
                    self.written_ordinary_hash();
                }
            } else {
                #[cfg(feature = "injector-checks-same-protocol")]
                {
                    if len == EXPECTING_SUBMIT_FIRST_METHOD {
                        return;
                    }
                    assert_ne!(len, EXPECTING_SIGNAL_FIRST_METHOD);
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
    const IF: InjectionFlags,
> {
    build: B,
}
impl<H: Hasher, B: BuildHasher<Hasher = H>, const IF: InjectionFlags>
    SignalledInjectionBuildHasher<H, B, IF>
{
    pub fn new(build: B) -> Self {
        Self { build }
    }
}
impl<H: Hasher, B: BuildHasher<Hasher = H>, const IF: InjectionFlags> BuildHasher
    for SignalledInjectionBuildHasher<H, B, IF>
{
    type Hasher = SignalledInjectionHasher<H, IF>;

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
