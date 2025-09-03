#![no_std]
#![feature(hasher_prefixfree_extras)]

use core::hash::{BuildHasher, Hasher};

const SIGNALLED_LENGTH_PREFIX: usize = usize::MAX;

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
pub fn signal_inject_hash<H: Hasher>(hasher: &mut H, hash: u64) {
    // The order of operations is intentionally different for debug and release. This (hopefully)
    // helps us notice any logical errors or opportunities for improvement in this module earlier.
    #[cfg(feature = "extra_flow")]
    {
        hasher.write_length_prefix(SIGNALLED_LENGTH_PREFIX);
        hasher.write_u64(hash);
    }
    #[cfg(not(feature = "extra_flow"))]
    {
        hasher.write_u64(hash);
        hasher.write_length_prefix(SIGNALLED_LENGTH_PREFIX);
    }
}

/// A state machine for a [Hash] implementation to pass a specified hash to [Hasher] - rather than
/// [Hasher] hashing the bytes supplied from [Hash].
///
/// Variants (but NOT their integer values) are listed in order of progression.
#[derive(PartialEq, Eq, Debug)]
enum SignalStateKind {
    NothingWritten = 1,
    WrittenOrdinaryHash = 2,

    // Set to zero, so as to speed up write_u64(,,,) when under #[cfg(feature = "extra_flow")]
    #[cfg(feature = "extra_flow")]
    SignalledProposalComing = 0,

    #[cfg(not(feature = "extra_flow"))]
    HashPossiblyProposed = 3,

    HashReceived = 4,
}

/// This used to be a data-carrying enum on its own, separate from SignalStateKind, NOT containing
/// SignalStateKind, and carrying the possibly proposed/received hash in its variants. But, then we
/// couldn't specify its variant integer values without fixing the representation, which would be
/// limiting.
#[derive(PartialEq, Eq, Debug)]
struct SignalState {
    kind: SignalStateKind,
    /// Only valid if kind is appropriate.
    hash: u64,
}
impl SignalState {
    /// `hash` is stored, but irrelevant if `kind` is not appropriate
    pub fn new(kind: SignalStateKind, hash: u64) -> Self {
        Self { kind, hash }
    }
}

pub struct SignalledInjectionHasher<H: Hasher> {
    hasher: H,
    state: SignalState,
}
impl<H: Hasher> SignalledInjectionHasher<H> {
    #[inline]
    fn new(hasher: H) -> Self {
        Self {
            hasher,
            state: SignalState::new(SignalStateKind::NothingWritten, 0),
        }
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_state_kind(&self, expected_state_kind: SignalStateKind) {
        #[cfg(feature = "asserts")]
        assert_eq!(self.state.kind, expected_state_kind);
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn written_ordinary_hash(&mut self) {
        self.state = SignalState::new(SignalStateKind::WrittenOrdinaryHash, 0);
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written(&self) {
        self.assert_state_kind(SignalStateKind::NothingWritten);
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written_or_ordinary_hash(&self) {
        #[cfg(feature = "asserts")]
        assert!(
            matches!(
                self.state.kind,
                SignalStateKind::NothingWritten | SignalStateKind::WrittenOrdinaryHash
            ),
            "Expecting the state to be NothingWritten or WrittenOrdinaryHash, but the state was: {:?}",
            self.state
        );
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written_or_ordinary_hash_or_proposed(&self) {
        #[cfg(feature = "asserts")]
        {
            #[cfg(feature = "extra_flow")]
            assert!(
                matches!(
                    self.state.kind,
                    SignalStateKind::NothingWritten | SignalStateKind::WrittenOrdinaryHash
                ),
                "Expecting the state to be NothingWritten or WrittenOrdinaryHash (or HashPossiblyProposed, which is not applicable), but the state was: {:?}",
                self.state
            );

            #[cfg(not(feature = "extra_flow"))]
            assert!(
                matches!(
                    self.state.kind,
                    SignalStateKind::NothingWritten
                        | SignalStateKind::WrittenOrdinaryHash
                        | SignalStateKind::HashPossiblyProposed
                ),
                "Expecting the state to be NothingWritten or WrittenOrdinaryHash or HashPossiblyProposed, but the state was: {:?}",
                self.state
            );
        }
    }
}
impl<H: Hasher> Hasher for SignalledInjectionHasher<H> {
    #[inline]
    fn finish(&self) -> u64 {
        if self.state.kind == SignalStateKind::HashReceived {
            self.state.hash
        } else {
            self.assert_nothing_written_or_ordinary_hash_or_proposed();
            self.hasher.finish()
        }
    }
    /// This does NOT signal, even if it sends the same bytes as `write_length_prefix` and
    /// `write_u64` would when signalling.
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write(bytes);
        self.written_ordinary_hash();
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_u8(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_u16(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_u32(i);
        self.written_ordinary_hash();
    }
    fn write_u64(&mut self, i: u64) {
        #[cfg(feature = "extra_flow")]
        if self.state.kind == SignalStateKind::SignalledProposalComing {
            self.state = SignalState::new(SignalStateKind::HashReceived, i);
        } else {
            self.assert_nothing_written_or_ordinary_hash();
            self.hasher.write_u64(i);
            self.written_ordinary_hash();
        }
        #[cfg(not(feature = "extra_flow"))]
        {
            self.assert_nothing_written_or_ordinary_hash_or_proposed();
            self.state = SignalState::new(SignalStateKind::HashPossiblyProposed, i);
            self.hasher.write_u64(i);
        }
    }
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_u128(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_usize(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_i8(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_i16(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_i32(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_i64(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_i128(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_isize(i);
        self.written_ordinary_hash();
    }
    fn write_length_prefix(&mut self, len: usize) {
        #[cfg(feature = "extra_flow")]
        {
            if len == SIGNALLED_LENGTH_PREFIX {
                self.assert_nothing_written();
                self.state.kind = SignalStateKind::SignalledProposalComing;
            } else {
                self.assert_nothing_written_or_ordinary_hash();
                self.hasher.write_length_prefix(len);
                self.written_ordinary_hash();
            }
        }
        #[cfg(not(feature = "extra_flow"))]
        if len == SIGNALLED_LENGTH_PREFIX {
            if self.state.kind == SignalStateKind::HashPossiblyProposed {
                self.state.kind = SignalStateKind::HashReceived;
            } else {
                #[cfg(feature = "asserts")]
                assert!(
                    false,
                    "Expected state HashPossiblyProposed, but it was {:?}.",
                    self.state
                );

                self.hasher.write_length_prefix(len);
                self.written_ordinary_hash();
            }
        } else {
            self.assert_nothing_written_or_ordinary_hash_or_proposed();
            self.hasher.write_length_prefix(len);
            self.written_ordinary_hash();
        }
    }
    #[inline]
    fn write_str(&mut self, s: &str) {
        self.assert_nothing_written_or_ordinary_hash_or_proposed();
        self.hasher.write_str(s);
        self.written_ordinary_hash();
    }
}

pub struct SignalledInjectionBuildHasher<H: Hasher, B: BuildHasher<Hasher = H>> {
    build: B,
}
impl<H: Hasher, B: BuildHasher<Hasher = H>> SignalledInjectionBuildHasher<H, B> {
    pub fn new(build: B) -> Self {
        Self { build }
    }
}
impl<H: Hasher, B: BuildHasher<Hasher = H>> BuildHasher for SignalledInjectionBuildHasher<H, B> {
    type Hasher = SignalledInjectionHasher<H>;

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
