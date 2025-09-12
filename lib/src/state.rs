use crate::ProtocolFlags;

#[allow(private_interfaces)]
pub type SignalStateKind = SignalStateKindImpl;

/// A state machine for a [Hash] implementation to pass a specified hash to [Hasher] - rather than
/// [Hasher] hashing the bytes supplied from [Hash].
///
/// Variants (but NOT their integer values) are listed in order of progression.
///
/// The enum is private, to prevent accidental misuse of variants incompatible with the signal
/// first/submit first behavior (InjectionFlags).
#[derive(PartialEq, Eq, Debug)]
#[allow(private_interfaces)]
enum SignalStateKindImpl {
    NothingWritten = 1,
    /// Ordinary hash (or its part) has been written
    WrittenOrdinaryHash = 2,

    // Set to zero, so as to speed up write_u64(,,,) when signal_first(IF)==true. Used ONLY when
    // signal_first(IF)==true.
    SignalledProposalComing = 0,

    // Used ONLY when signal_first(IF)==false.
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
    // constructors and mutators
    pub const fn new_nothing_written() -> Self {
        Self {
            kind: SignalStateKind::NothingWritten,
            hash: 0,
        }
    }
    pub const fn set_written_ordinary_hash(&mut self) {
        self.kind = SignalStateKind::WrittenOrdinaryHash;
    }
    pub const fn new_hash_received(hash: u64) -> Self {
        Self {
            kind: SignalStateKind::HashReceived,
            hash,
        }
    }
    pub const fn new_hash_possibly_submitted(
        hash: u64,
        #[allow(non_snake_case)] IF: ProtocolFlags,
    ) -> Self {
        #[cfg(debug_assertions)]
        if crate::signal_first(IF) {
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
    pub const fn set_signalled_proposal_coming(
        &mut self,
        #[allow(non_snake_case)] IF: ProtocolFlags,
    ) {
        #[cfg(debug_assertions)]
        if crate::submit_first(IF) {
            panic!();
        }
        self.kind = SignalStateKind::SignalledProposalComing;
    }

    // -----

    pub const fn is_nothing_written(&self) -> bool {
        //@TODO replace with matches!(..)
        matches!(self.kind, SignalStateKind::NothingWritten)
    }
    pub const fn is_nothing_written_or_ordinary_hash(&self) -> bool {
        matches!(
            self.kind,
            SignalStateKind::NothingWritten | SignalStateKind::WrittenOrdinaryHash
        )
    }
    pub const fn is_nothing_written_or_ordinary_hash_or_possibly_submitted(
        &self,
        #[allow(non_snake_case)] IF: ProtocolFlags,
    ) -> bool {
        if crate::signal_first(IF) {
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
    pub const fn is_hash_received(&self) -> bool {
        matches!(self.kind, SignalStateKindImpl::HashReceived)
    }
    pub const fn is_signalled_proposal_coming(
        &self,
        #[allow(non_snake_case)] IF: ProtocolFlags,
    ) -> bool {
        #[cfg(debug_assertions)]
        if crate::submit_first(IF) {
            panic!();
        }
        matches!(self.kind, SignalStateKindImpl::SignalledProposalComing)
    }
    pub const fn is_hash_possibly_submitted(
        &self,
        #[allow(non_snake_case)] IF: ProtocolFlags,
    ) -> bool {
        #[cfg(debug_assertions)]
        if crate::signal_first(IF) {
            panic!();
        }
        matches!(self.kind, SignalStateKind::HashPossiblySubmitted)
    }
}

const _VERIFY: () = {
    if !matches!(
        SignalState::new_nothing_written().kind,
        SignalStateKind::NothingWritten
    ) {
        panic!();
    }
    // @TODO this and more
    /*if !SignalState::set_written_ordinary_hash().kind.const_eq(&SignalStateKind::WrittenOrdinaryHash) {
        panic!();
    }*/
    if !SignalState::new_nothing_written().is_nothing_written() {
        panic!();
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
