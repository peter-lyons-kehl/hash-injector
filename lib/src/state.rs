use crate::ProtocolFlags;
use crate::flags;
#[cfg(feature = "chk-details")]
use core::fmt::Arguments;

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

    #[cfg_attr(not(any(feature = "mx", feature = "hpe")), allow(dead_code))]
    /// Set to zero, so as to speed up write_u64(,,,) when signal_first(PF)==true. Use ONLY when
    /// signal_first(PF)==true.
    SignalledProposalComing = 0,

    // Used ONLY when submit_first(PF)==true.
    HashPossiblySubmitted = 3,

    HashReceived = 4,
}
impl SignalStateKindImpl {
    #[allow(dead_code)]
    const fn equals(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::NothingWritten, Self::NothingWritten)
                | (Self::WrittenOrdinaryHash, Self::WrittenOrdinaryHash)
                | (Self::SignalledProposalComing, Self::SignalledProposalComing)
                | (Self::HashPossiblySubmitted, Self::HashPossiblySubmitted)
                | (Self::HashReceived, Self::HashReceived)
        )
    }
}
#[cfg(feature = "chk-details")]
impl SignalStateKindImpl {
    /// For use in [Arguments]/
    const fn type_and_variant(&self) -> &'static str {
        match self {
            Self::NothingWritten => "SignalStateKindImpl::NothingWritten",
            Self::WrittenOrdinaryHash => "SignalStateKindImpl::WrittenOrdinaryHash",
            Self::SignalledProposalComing => "SignalStateKindImpl::SignalledProposalComing",
            Self::HashPossiblySubmitted => "SignalStateKindImpl::HashPossiblySubmitted",
            Self::HashReceived => "SignalStateKindImpl::HashReceived",
        }
    }
}
/// This used to be a data-carrying enum on its own, separate from SignalStateKind, NOT containing
/// SignalStateKind, and carrying the possibly submitted/received hash in its variants. But, then we
/// couldn't specify its variant integer values without fixing the representation, which would be
/// limiting.
///
/// Another advantage of separation is that [SignalStateKindImpl] has
/// [SignalStateKindImpl::type_and_variant], helps with making
/// [SignalState::assert_nothing_written_or_ordinary_hash] and
/// [SignalState::assert_nothing_written_or_ordinary_hash_or_possibly_submitted] `const fn`. That
/// allows us to validate them in [_CHECKS].
#[derive(PartialEq, Eq, Debug)]
pub struct SignalState {
    #[allow(private_interfaces)]
    pub kind: SignalStateKind,
    /// Only valid if [SignalState::kind] is appropriate.
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

    #[cfg_attr(not(any(feature = "mx", feature = "hpe")), allow(dead_code))]
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
            panic!("Supported only for ProtocolFlags that signal first.");
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
            panic!("Supported only for ProtocolFlags that submit first.");
        }
        Self {
            kind: SignalStateKind::HashPossiblySubmitted,
            hash,
        }
    }

    #[cfg_attr(not(any(feature = "mx", feature = "hpe")), allow(dead_code))]
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
    // ------

    // Queries (some used by chk only). In order of SignalStateKind's usual lifecycle.
    #[inline(always)]
    pub const fn is_nothing_written(&self) -> bool {
        //@TODO replace with matches!(..)
        matches!(self.kind, SignalStateKind::NothingWritten)
    }

    #[cfg_attr(not(feature = "chk"), allow(dead_code))]
    #[inline(always)]
    const fn is_nothing_written_or_ordinary_hash(&self) -> bool {
        matches!(
            self.kind,
            SignalStateKind::NothingWritten | SignalStateKind::WrittenOrdinaryHash
        )
    }

    #[cfg_attr(not(feature = "chk"), allow(dead_code))]
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
            panic!("Supported only for ProtocolFlags that signal first.");
        }
        matches!(self.kind, SignalStateKindImpl::SignalledProposalComing)
    }

    #[cfg_attr(not(any(feature = "mx", feature = "hpe")), allow(dead_code))]
    #[inline(always)]
    pub const fn is_hash_possibly_submitted(
        &self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> bool {
        #[cfg(debug_assertions)]
        if flags::is_signal_first(PF) {
            panic!("Supported only for ProtocolFlags that submit first.")
        }
        matches!(self.kind, SignalStateKind::HashPossiblySubmitted)
    }
    pub const fn is_hash_received(&self) -> bool {
        matches!(self.kind, SignalStateKindImpl::HashReceived)
    }
    // ------

    #[cfg_attr(not(any(feature = "mx", feature = "hpe")), allow(dead_code))]
    #[inline(always)]
    pub const fn assert_nothing_written(&self) {
        #[cfg(feature = "chk")]
        if !self.is_nothing_written() {
            #[cfg(not(feature = "chk-details"))]
            {
                panic!("Expecting the state to be SignalStateKindImpl::NothingWritten.");
            }
            #[cfg(feature = "chk-details")]
            {
                let args_parts: [&'static str; 2] = [
                    "Expecting the state to be SignalStateKindImpl::NothingWritten, but the state was: {}.",
                    self.kind.type_and_variant(),
                ];
                let args: Arguments = Arguments::new_const(&args_parts);
                core::panicking::panic_fmt(args)
            }
        }
    }
    #[inline(always)]
    pub const fn assert_nothing_written_or_ordinary_hash(&self) {
        #[cfg(feature = "chk")]
        if !self.is_nothing_written_or_ordinary_hash() {
            #[cfg(not(feature = "chk-details"))]
            {
                panic!(
                    "Expecting the state to be SignalStateKindImpl::NothingWritten or SignalStateKindImpl::WrittenOrdinaryHash."
                );
            }
            #[cfg(feature = "chk-details")]
            {
                let args_parts: [&'static str; 2] = [
                    "Expecting the state to be SignalStateKindImpl::NothingWritten or SignalStateKindImpl::WrittenOrdinaryHash, but the state was: {}.",
                    self.kind.type_and_variant(),
                ];
                let args: Arguments = Arguments::new_const(&args_parts);
                core::panicking::panic_fmt(args)
            }
        }
    }
    /// Assert that
    /// - no hash has been signalled (if we do signal first - before submitting), and
    /// - no hash has been received (regardless of whether we signal first, or submit first).
    #[inline(always)]
    pub const fn assert_nothing_written_or_ordinary_hash_or_possibly_submitted(
        &self,
        #[allow(non_snake_case)] _PF: ProtocolFlags,
    ) {
        #[cfg(feature = "chk")]
        {
            if !self.is_nothing_written_or_ordinary_hash_or_possibly_submitted(_PF) {
                #[cfg(not(feature = "chk-details"))]
                {
                    panic!(
                        "Expecting the state to be SignalStateKindImpl::NothingWritten, or SignalStateKindImpl::WrittenOrdinaryHash, or SignalStateKindImpl::HashPossiblySubmitted (if applicable)."
                    );
                }
                #[cfg(feature = "chk-details")]
                {
                    let args_parts: [&'static str; 2] = [
                        "Expecting the state to be SignalStateKindImpl::NothingWritten, or SignalStateKindImpl::WrittenOrdinaryHash, or SignalStateKindImpl::HashPossiblySubmitted (if applicable), but the state was: {}.",
                        self.kind.type_and_variant(),
                    ];
                    let args: Arguments = Arguments::new_const(&args_parts);
                    core::panicking::panic_fmt(args);
                }
            }
        }
    }
}

const _CHECKS: () = {
    let nothing_written = SignalState::new_nothing_written();
    {
        nothing_written.assert_nothing_written();
        assert!(nothing_written.is_nothing_written());

        nothing_written.assert_nothing_written_or_ordinary_hash();
        #[cfg(feature = "chk")]
        assert!(nothing_written.is_nothing_written_or_ordinary_hash());

        assert!(!nothing_written.is_hash_received());

        assert!(matches!(
            nothing_written.kind,
            SignalStateKind::NothingWritten
        ));
    }
    let written_ordinary_hash_zero = {
        let mut written_ordinary_hash_zero = SignalState::new_nothing_written();
        written_ordinary_hash_zero.set_written_ordinary_hash();
        written_ordinary_hash_zero
    };
    {
        written_ordinary_hash_zero.assert_nothing_written_or_ordinary_hash();
        #[cfg(feature = "chk")]
        assert!(written_ordinary_hash_zero.is_nothing_written_or_ordinary_hash());

        assert!(!nothing_written.is_hash_received());

        assert!(matches!(
            written_ordinary_hash_zero.kind,
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
            #[allow(non_snake_case)]
            let PF = SIGNAL_FIRST_FLAGS[i];
            assert!(flags::is_signal_first(PF));

            nothing_written.assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
            #[cfg(feature = "chk")]
            assert!(nothing_written.is_nothing_written_or_ordinary_hash_or_possibly_submitted(PF));

            assert!(!nothing_written.is_signalled_proposal_coming(PF));
            // ----
            let signalled_proposal_coming = {
                let mut signalled_proposal_coming = SignalState::new_nothing_written();
                signalled_proposal_coming.set_signalled_proposal_coming(PF);
                signalled_proposal_coming
            };
            assert!(!signalled_proposal_coming.is_nothing_written());
            assert!(!signalled_proposal_coming.is_nothing_written_or_ordinary_hash());
            assert!(
                !signalled_proposal_coming
                    .is_nothing_written_or_ordinary_hash_or_possibly_submitted(PF)
            );

            assert!(signalled_proposal_coming.is_signalled_proposal_coming(PF));

            assert!(!signalled_proposal_coming.is_hash_received());

            assert!(matches!(
                signalled_proposal_coming.kind,
                SignalStateKind::SignalledProposalComing
            ));

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
        let mut i = 0usize;
        while i < SXXXXX_FIRST_FLAGS_LEN {
            #[allow(non_snake_case)]
            let PF = SUBMIT_FIRST_FLAGS[i];
            assert!(flags::is_submit_first(PF));

            nothing_written.assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
            #[cfg(feature = "chk")]
            assert!(nothing_written.is_nothing_written_or_ordinary_hash_or_possibly_submitted(PF));

            assert!(!nothing_written.is_hash_possibly_submitted(PF));
            // ----
            let hash_possibly_submitted = SignalState::new_hash_possibly_submitted(0, PF);

            assert!(!hash_possibly_submitted.is_nothing_written());
            assert!(!hash_possibly_submitted.is_nothing_written_or_ordinary_hash());

            assert!(
                hash_possibly_submitted
                    .is_nothing_written_or_ordinary_hash_or_possibly_submitted(PF)
            );
            hash_possibly_submitted
                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);

            assert!(!hash_possibly_submitted.is_hash_received());

            assert!(matches!(
                hash_possibly_submitted.kind,
                SignalStateKind::HashPossiblySubmitted
            ));

            i += 1;
        }
    }

    let set_hash_received = {
        let mut set_hash_received = SignalState::new_nothing_written();
        set_hash_received.set_hash_received();
        set_hash_received
    };
    let new_hash_received = SignalState::new_hash_received(0);
    // @TODO Use derived(?) or own `impl` ofr PartialEq/const PartailEq, once const PartialEq is
    // stable: https://github.com/rust-lang/rust/issues/143800
    assert!(set_hash_received.kind.equals(&new_hash_received.kind));
    assert!(set_hash_received.hash == new_hash_received.hash);

    assert!(!set_hash_received.is_nothing_written());
    assert!(!set_hash_received.is_nothing_written_or_ordinary_hash());
    {
        //for pf in [flags::new::len::signal_first::i128()] {
        let mut i = 0usize;
        while i < SXXXXX_FIRST_FLAGS_LEN {
            assert!(
                !set_hash_received.is_nothing_written_or_ordinary_hash_or_possibly_submitted(
                    SUBMIT_FIRST_FLAGS[i]
                )
            );

            assert!(!set_hash_received.is_signalled_proposal_coming(SIGNAL_FIRST_FLAGS[i]));

            assert!(!set_hash_received.is_hash_possibly_submitted(SUBMIT_FIRST_FLAGS[i]));

            i += 1;
        }
    }
    assert!(set_hash_received.is_hash_received());

    assert!(matches!(
        set_hash_received.kind,
        SignalStateKind::HashReceived
    ));
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        SignalState::new_nothing_written().assert_nothing_written_or_ordinary_hash();
    }
}
