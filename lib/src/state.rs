use crate::ProtocolFlags;

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

    // Set to zero, so as to speed up write_u64(,,,) when signal_first(PF)==true. Used ONLY when
    // signal_first(PF)==true.
    SignalledProposalComing = 0,

    // Used ONLY when submit_first(PF)==true.
    HashPossiblySubmitted = 3,

    // @TODO if submit_first(PF)==true and the client writes u64 twice, then switch to WrittenOrdinaryHash
    //
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
    pub const fn new_nothing_written() -> Self {
        Self {
            kind: SignalStateKind::NothingWritten,
            hash: 0,
        }
    }
    pub const fn set_written_ordinary_hash(&mut self) {
        #[cfg(feature = "asserts")]
        if matches!(self.kind, SignalStateKind::HashReceived) {
            panic!();
        }
        self.kind = SignalStateKind::WrittenOrdinaryHash;
    }

    /// Set the state that it was signalled that a hash proposal is coming.
    ///
    /// Requires `signal_first(PF)==true` - otherwise it panics in debug mode (regardless of, and
    /// ignoring, `asserts` feature).
    pub const fn set_signalled_proposal_coming(
        &mut self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) {
        #[cfg(debug_assertions)]
        if crate::submit_first(PF) {
            panic!();
        }
        self.kind = SignalStateKind::SignalledProposalComing;
    }
    /// Set the state to contain the given `u64` as a possible hash.
    ///
    /// Requires `submit_first(PF)==true` - otherwise it panics in debug mode (regardless of, and
    /// ignoring, `asserts` feature).
    pub const fn new_hash_possibly_submitted(
        hash: u64,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> Self {
        #[cfg(debug_assertions)]
        if crate::signal_first(PF) {
            panic!();
        }
        Self {
            kind: SignalStateKind::HashPossiblySubmitted,
            hash,
        }
    }

    pub const fn set_hash_received(&mut self) {
        self.kind = SignalStateKind::HashReceived;
    }
    pub const fn new_hash_received(hash: u64) -> Self {
        Self {
            kind: SignalStateKind::HashReceived,
            hash,
        }
    }

    // Queries (some used by asserts only). In order of SignalStateKind's usual lifecycle.
    #[cfg(feature = "asserts")]
    pub const fn is_nothing_written(&self) -> bool {
        //@TODO replace with matches!(..)
        matches!(self.kind, SignalStateKind::NothingWritten)
    }
    #[cfg(feature = "asserts")]
    pub const fn is_nothing_written_or_ordinary_hash(&self) -> bool {
        matches!(
            self.kind,
            SignalStateKind::NothingWritten | SignalStateKind::WrittenOrdinaryHash
        )
    }
    #[cfg(feature = "asserts")]
    /// Checks whether the state is
    /// - nothing written, or
    /// - ordinary hash data written, or
    /// - hash was possibly submitted - but that is checked only if `submit_first(PF)==true` ( otherwise this state is not applicable).
    pub const fn is_nothing_written_or_ordinary_hash_or_possibly_submitted(
        &self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> bool {
        if crate::signal_first(PF) {
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
    /// ignoring, `asserts` feature).
    pub const fn is_signalled_proposal_coming(
        &self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> bool {
        #[cfg(debug_assertions)]
        if crate::submit_first(PF) {
            panic!();
        }
        matches!(self.kind, SignalStateKindImpl::SignalledProposalComing)
    }

    pub const fn is_hash_possibly_submitted(
        &self,
        #[allow(non_snake_case)] PF: ProtocolFlags,
    ) -> bool {
        #[cfg(debug_assertions)]
        if crate::signal_first(PF) {
            panic!();
        }
        matches!(self.kind, SignalStateKind::HashPossiblySubmitted)
    }
    pub const fn is_hash_received(&self) -> bool {
        matches!(self.kind, SignalStateKindImpl::HashReceived)
    }
}

const _VERIFY: () = {
    if !matches!(
        SignalState::new_nothing_written().kind,
        SignalStateKind::NothingWritten
    ) {
        panic!();
    }
    {
        let mut ordinary_zero_hash = SignalState::new_nothing_written();
        ordinary_zero_hash.set_written_ordinary_hash();
        if !matches!(
            ordinary_zero_hash.kind,
            SignalStateKind::WrittenOrdinaryHash
        ) {
            panic!();
        }
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
