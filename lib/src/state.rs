use crate::ProtocolFlags;
use crate::flags;

#[allow(private_interfaces)]
pub type SignalStateKind = SignalStateKindImpl;

/// A state machine for a [Hash] implementation to pass a specified hash to [Hasher] - rather than
/// [Hasher] hashing the bytes supplied from [Hash].
///
/// Variants (but NOT their integer values) are listed in order of progression.
///
/// The enum is private, to prevent accidental misuse of variants incompatible with the signalling
/// first/submit first behavior ([`crate::ProtocolFlags``]).
#[derive(PartialEq, Eq, Debug)]
#[allow(private_interfaces)]
enum SignalStateKindImpl {
    NothingWritten = 1,
    /// Ordinary hash (or its part) has been written
    WrittenOrdinaryHash = 2,

    #[cfg_attr(not(any(feature="mx", feature="hpe")), allow(dead_code))]
    /// Set to zero, so as to speed up write_u64(,,,) when signal_first(PF)==true. Use ONLY when
    /// signal_first(PF)==true.
    SignalledProposalComing = 0,

    // Used ONLY when submit_first(PF)==true.
    HashPossiblySubmitted = 3,

    HashReceived = 4,
}

/// This used to be a data-carrying enum on its own, separate from SignalStateKind, NOT containing
/// SignalStateKind, and carrying the possibly submitted/received hash in its variants. But, then we
/// couldn't specify its variant integer values without fixing the representation, which would be
/// limiting.
#[derive(PartialEq, Eq, Debug)]
pub struct SignalState {
    #[allow(private_interfaces)]
    pub kind: SignalStateKind,
    /// Only valid if kind is appropriate.
    pub hash: u64,
}
impl SignalState {
    // Constructors and mutators. (Again, in order of SignalStateKind's usual lifecycle.)
    #[inline(always)]
    pub const fn new_nothing_written() -> Self {
        Self {
            kind: SignalStateKind::NothingWritten,
            hash: 0,
        }
    }
    #[inline(always)]
    pub const fn set_written_ordinary_hash(&mut self) {
        #[cfg(feature = "chk")]
        if matches!(self.kind, SignalStateKind::HashReceived) {
            panic!();
        }
        self.kind = SignalStateKind::WrittenOrdinaryHash;
    }

    #[cfg_attr(not(any(feature="mx", feature="hpe")), allow(dead_code))]
    /// Set the state that it was signalled that a hash proposal is coming.
    ///
    /// Requires `signal_first(PF)==true` - otherwise it panics in debug mode (regardless of, and
    /// ignoring, `chk` feature).
    #[inline(always)]
    pub const fn set_signalled_proposal_coming(
        &mut self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) {
        #[cfg(debug_assertions)]
        if flags::is_submit_first(PF) {
            panic!();
        }
        self.kind = SignalStateKind::SignalledProposalComing;
    }
    /// Set the state to contain the given `u64` as a possible hash.
    ///
    /// Requires `submit_first(PF)==true` - otherwise it panics in debug mode (regardless of, and
    /// ignoring, `chk` feature).
    #[inline(always)]
    pub const fn new_hash_possibly_submitted(
        hash: u64,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> Self {
        #[cfg(debug_assertions)]
        if flags::is_signal_first(PF) {
            panic!();
        }
        Self {
            kind: SignalStateKind::HashPossiblySubmitted,
            hash,
        }
    }

    #[cfg_attr(not(any(feature="mx", feature="hpe")), allow(dead_code))]
    #[inline(always)]
    pub const fn set_hash_received(&mut self) {
        self.kind = SignalStateKind::HashReceived;
    }
    #[inline(always)]
    pub const fn new_hash_received(hash: u64) -> Self {
        Self {
            kind: SignalStateKind::HashReceived,
            hash,
        }
    }

    // Queries (some used by chk only). In order of SignalStateKind's usual lifecycle.
    #[inline(always)]
    pub const fn is_nothing_written(&self) -> bool {
        //@TODO replace with matches!(..)
        matches!(self.kind, SignalStateKind::NothingWritten)
    }

    #[cfg(feature = "chk")]
    #[inline(always)]
    const fn is_nothing_written_or_ordinary_hash(&self) -> bool {
        matches!(
            self.kind,
            SignalStateKind::NothingWritten | SignalStateKind::WrittenOrdinaryHash
        )
    }

    #[cfg(feature = "chk")]
    /// Checks whether the state is
    /// - nothing written, or
    /// - ordinary hash data written, or
    /// - hash was possibly submitted - but that is checked only if `submit_first(PF)==true` ( otherwise this state is not applicable).
    #[inline(always)]
    const fn is_nothing_written_or_ordinary_hash_or_possibly_submitted(
        &self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> bool {
        if flags::is_signal_first(PF) {
            matches!(
                self.kind,
                // HashPossiblySubmitted is not applicable because we signal first
                SignalStateKind::NothingWritten | SignalStateKind::WrittenOrdinaryHash
            )
        } else {
            debug_assert!(
                matches!(
                    self.kind,
                    SignalStateKind::NothingWritten
                        | SignalStateKind::WrittenOrdinaryHash
                        | SignalStateKind::HashPossiblySubmitted
                ) == !matches!(self.kind, SignalStateKind::HashReceived)
            );
            !matches!(self.kind, SignalStateKind::HashReceived)
        }
    }

    /// Check the state whether it was signalled that a hash proposal is coming.
    ///
    /// Requires `signal_first(PF)==true` - otherwise it panics in debug mode (regardless of, and
    /// ignoring, `chk` feature).
    #[inline(always)]
    pub const fn is_signalled_proposal_coming(
        &self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> bool {
        #[cfg(debug_assertions)]
        if flags::is_submit_first(PF) {
            panic!();
        }
        matches!(self.kind, SignalStateKindImpl::SignalledProposalComing)
    }

    #[cfg_attr(not(any(feature="mx", feature="hpe")), allow(dead_code))]
    #[inline(always)]
    pub const fn is_hash_possibly_submitted(
        &self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> bool {
        #[cfg(debug_assertions)]
        if flags::is_signal_first(PF) {
            panic!();
        }
        matches!(self.kind, SignalStateKind::HashPossiblySubmitted)
    }
    pub const fn is_hash_received(&self) -> bool {
        matches!(self.kind, SignalStateKindImpl::HashReceived)
    }

    #[cfg_attr(not(any(feature="mx", feature="hpe")), allow(dead_code))]
    #[inline(always)]
    pub const fn assert_nothing_written(&self) {
        #[cfg(feature = "chk")]
        assert!(self.is_nothing_written());
    }
    #[inline(always)]
    pub fn assert_nothing_written_or_ordinary_hash(&self) {
        #[cfg(feature = "chk")]
        assert!(
            self.is_nothing_written_or_ordinary_hash(),
            "Expecting the state to be NothingWritten or WrittenOrdinaryHash, but the state was: {:?}",
            self
        );
    }
    /// Assert that
    /// - no hash has been signalled (if we do signal first - before submitting), and
    /// - no hash has been received (regardless of whether we signal first, or submit first).
    #[inline(always)]
    pub fn assert_nothing_written_or_ordinary_hash_or_possibly_submitted(
        &self,
        #[allow(non_snake_case)] _PF: ProtocolFlags,
    ) {
        #[cfg(feature = "chk")]
        {
            assert!(
                self.is_nothing_written_or_ordinary_hash_or_possibly_submitted(_PF),
                "Expecting the state to be NothingWritten or WrittenOrdinaryHash, or HashPossiblySubmitted (if applicable), but the state was: {:?}",
                self
            );
        }
    }
}

const _CHECKS: () = {
    assert!(matches!(
        SignalState::new_nothing_written().kind,
        SignalStateKind::NothingWritten
    ));
    assert!(SignalState::new_nothing_written().is_nothing_written());
    #[cfg(feature = "chk")]
    assert!(SignalState::new_nothing_written().is_nothing_written_or_ordinary_hash());
    SignalState::new_nothing_written().assert_nothing_written();

    {
        let mut ordinary_zero_hash = SignalState::new_nothing_written();
        ordinary_zero_hash.set_written_ordinary_hash();
        assert!(matches!(
            ordinary_zero_hash.kind,
            SignalStateKind::WrittenOrdinaryHash
        ));
    }

    const SXXXXX_FIRST_FLAGS_LEN: usize = if cfg!(feature = "hpe") {
        4 // hpe and regardless of mx: len signalling
        + if cfg!(feature = "mx") {
            8 // hpe and mx: u8s and str signalling
        } else {
            0
        }
    } else if cfg!(feature = "mx") {
        4 // no hpe, mx only: u8s signal;ling
    } else {
        0
    };
    const SIGNAL_FIRST_FLAGS: [ProtocolFlags; SXXXXX_FIRST_FLAGS_LEN] = [
        #[cfg(feature = "mx")]
        flags::new::u8s::signal_first::u64(),
        #[cfg(feature = "mx")]
        flags::new::u8s::signal_first::i64(),
        #[cfg(feature = "mx")]
        flags::new::u8s::signal_first::u128(),
        #[cfg(feature = "mx")]
        flags::new::u8s::signal_first::i128(),
        #[cfg(feature = "hpe")]
        flags::new::len::signal_first::u64(),
        #[cfg(feature = "hpe")]
        flags::new::len::signal_first::i64(),
        #[cfg(feature = "hpe")]
        flags::new::len::signal_first::u128(),
        #[cfg(feature = "hpe")]
        flags::new::len::signal_first::i128(),
        #[cfg(all(feature = "mx", feature = "hpe"))]
        flags::new::str::signal_first::u64(),
        #[cfg(all(feature = "mx", feature = "hpe"))]
        flags::new::str::signal_first::i64(),
        #[cfg(all(feature = "mx", feature = "hpe"))]
        flags::new::str::signal_first::u128(),
        #[cfg(all(feature = "mx", feature = "hpe"))]
        flags::new::str::signal_first::i128(),
    ];
    {
        //for pf in [flags::new::len::signal_first::i128()] {
        let mut i = 0usize;
        while i < SXXXXX_FIRST_FLAGS_LEN {
            let pf = SIGNAL_FIRST_FLAGS[i];
            assert!(flags::is_signal_first(pf));

            let mut state = SignalState::new_nothing_written();
            state.set_signalled_proposal_coming(pf);

            #[cfg(feature = "chk")]
            assert!(
                SignalState::new_nothing_written()
                    .is_nothing_written_or_ordinary_hash_or_possibly_submitted(pf)
            );

            i += 1;
        }
    }

    const SUBMIT_FIRST_FLAGS: [ProtocolFlags; SXXXXX_FIRST_FLAGS_LEN] = [
        #[cfg(feature = "mx")]
        flags::new::u8s::submit_first::u64(),
        #[cfg(feature = "mx")]
        flags::new::u8s::submit_first::i64(),
        #[cfg(feature = "mx")]
        flags::new::u8s::submit_first::u128(),
        #[cfg(feature = "mx")]
        flags::new::u8s::submit_first::i128(),
        #[cfg(feature = "hpe")]
        flags::new::len::submit_first::u64(),
        #[cfg(feature = "hpe")]
        flags::new::len::submit_first::i64(),
        #[cfg(feature = "hpe")]
        flags::new::len::submit_first::u128(),
        #[cfg(feature = "hpe")]
        flags::new::len::submit_first::i128(),
        #[cfg(all(feature = "mx", feature = "hpe"))]
        flags::new::str::submit_first::u64(),
        #[cfg(all(feature = "mx", feature = "hpe"))]
        flags::new::str::submit_first::i64(),
        #[cfg(all(feature = "mx", feature = "hpe"))]
        flags::new::str::submit_first::u128(),
        #[cfg(all(feature = "mx", feature = "hpe"))]
        flags::new::str::submit_first::i128(),
    ];
    {
        //for pf in [flags::new::len::signal_first::i128()] {
        let mut i = 0usize;
        while i < SXXXXX_FIRST_FLAGS_LEN {
            let pf = SUBMIT_FIRST_FLAGS[i];

            assert!(flags::is_submit_first(pf));
            SignalState::new_hash_possibly_submitted(0, pf);

            #[cfg(feature = "chk")]
            assert!(
                SignalState::new_nothing_written()
                    .is_nothing_written_or_ordinary_hash_or_possibly_submitted(pf)
            );

            i += 1;
        }
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        SignalState::new_nothing_written().assert_nothing_written_or_ordinary_hash();
    }
}
