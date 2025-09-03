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
/// Variants are in order of progression.
#[derive(PartialEq, Eq, Debug)]
enum SignalState {
    NothingWritten,
    WrittenOrdinaryHash,

    #[cfg(feature = "extra_flow")]
    SignalledProposalComing,

    #[cfg(not(feature = "extra_flow"))]
    HashProposed(u64),
    
    HashReceived(u64),
}
impl SignalState {
    pub fn kind(&self) -> SignalStateKind {
        match self {
            Self::NothingWritten => SignalStateKind::NothingWritten,
            Self::WrittenOrdinaryHash => SignalStateKind::WrittenOrdinaryHash,
            #[cfg(feature = "extra_flow")]
            Self::SignalledProposalComing => SignalStateKind::SignalledProposalComing,
            #[cfg(not(feature = "extra_flow"))]
            Self::HashProposed(_) => SignalStateKind::HashProposed,
            Self::HashReceived(_) => SignalStateKind::HashReceived,
        }
    }
}
#[derive(PartialEq, Eq, Debug)]
enum SignalStateKind {
    NothingWritten,
    WrittenOrdinaryHash,

    #[cfg(feature = "extra_flow")]
    SignalledProposalComing,
    
    #[cfg(not(feature = "extra_flow"))]
    HashProposed,
    
    HashReceived,
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
            state: SignalState::NothingWritten,
        }
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written(&self) {
        self.assert_state(SignalStateKind::NothingWritten);
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_state(&self, expected_state: SignalStateKind) {
        #[cfg(feature = "asserts")]
        assert_eq!(self.state.kind(), expected_state);
    }
}
impl<H: Hasher> Hasher for SignalledInjectionHasher<H> {
    #[inline]
    fn finish(&self) -> u64 {
        if let SignalState::HashReceived(hash) = self.state {
            hash
        } else {
            self.assert_nothing_written();
            self.hasher.finish()
        }
    }
    /// This does NOT signal, even if it sends the same bytes as `write_length_prefix` and
    /// `write_u64` would when signalling.
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.assert_nothing_written();
        self.hasher.write(bytes);
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.assert_nothing_written();
        self.hasher.write_u8(i);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.assert_nothing_written();
        self.hasher.write_u16(i);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.assert_nothing_written();
        self.hasher.write_u32(i);
    }
    fn write_u64(&mut self, i: u64) {
        #[cfg(feature = "extra_flow")]
        if self.state == SignalState::SignalledProposalComing {
            self.state = SignalState::HashReceived(i);
        } else {
            self.assert_nothing_written();
        }
        #[cfg(not(feature = "extra_flow"))]
        {
            self.assert_nothing_written();
            self.state = SignalState::HashProposed(i);
        }
        // @TODO skip the folllwing, if signalled
        self.hasher.write_u64(i);
    }
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.assert_nothing_written();
        self.hasher.write_u128(i);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.assert_nothing_written();
        self.hasher.write_usize(i);
    }
    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.assert_nothing_written();
        self.hasher.write_i8(i);
    }
    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.assert_nothing_written();
        self.hasher.write_i16(i);
    }
    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.assert_nothing_written();
        self.hasher.write_i32(i);
    }
    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.assert_nothing_written();
        self.hasher.write_i64(i);
    }
    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.assert_nothing_written();
        self.hasher.write_i128(i);
    }
    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.assert_nothing_written();
        self.hasher.write_isize(i);
    }
    fn write_length_prefix(&mut self, len: usize) {
        #[cfg(feature = "extra_flow")]
        {
            self.assert_nothing_written();
            if len == SIGNALLED_LENGTH_PREFIX {
                self.state = SignalState::SignalledProposalComing;
            } else {
                self.hasher.write_length_prefix(len);
            }
        }
        #[cfg(not(feature = "extra_flow"))]
        if len == SIGNALLED_LENGTH_PREFIX {
            if let SignalState::HashProposed(i) = self.state {
                self.state = SignalState::HashReceived(i);
            } else {
                // Fail if "asserts" feature is enabled:
                self.assert_state(SignalStateKind::HashProposed);
                self.hasher.write_length_prefix(len);
            }
        } else {
            self.assert_nothing_written();
            self.hasher.write_length_prefix(len);
        }
    }
    #[inline]
    fn write_str(&mut self, s: &str) {
        self.assert_nothing_written();
        self.hasher.write_str(s);
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
