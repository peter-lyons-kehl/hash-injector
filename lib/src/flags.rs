#[cfg(feature = "flags")]
use core::marker::ConstParamTy;

/// An enum-like Type for const generic parameter `PF`. Use `new_flags_xxx` functions to create the
/// values.
///
/// Do not compare with/store as/pass as values of other types - the actual implementation of the
/// type is subject to change.
pub type ProtocolFlags = ProtocolFlagsImpl;

// If we ever have more than one flag, then change this into e.g. u8.
#[cfg(not(feature = "flags"))]
type ProtocolFlagsImpl = u8;

#[cfg(feature = "flags")]
#[derive(ConstParamTy, Clone, Copy, PartialEq, Eq)]
enum HashViaInternal {
    U64,
    I64,
    U128,
    I128,
}

#[cfg(feature = "flags")]
/// Type for const generic parameter `PF`.
#[derive(ConstParamTy, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolFlagsImpl {
    signal_via_str: bool,
    signal_first: bool,
    hash_via: HashViaInternal,
}

#[cfg(not(feature = "flags"))]
const FLAGS_BIT_VIA_STR: ProtocolFlags = 0b1;
#[cfg(not(feature = "flags"))]
const FLAGS_BIT_SIGNAL_FIRST: ProtocolFlags = 0b10;

#[cfg(not(feature = "flags"))]
const FLAGS_MASK_HASH_U64: ProtocolFlags = 0b0000;
#[cfg(not(feature = "flags"))]
const FLAGS_MASK_HASH_I64: ProtocolFlags = 0b0100;
#[cfg(not(feature = "flags"))]
const FLAGS_MASK_HASH_U128: ProtocolFlags = 0b1000;
#[cfg(not(feature = "flags"))]
const FLAGS_MASK_HASH_I128: ProtocolFlags = 0b1100;

#[cfg(not(feature = "flags"))]
const FLAGS_BITS_HASH: ProtocolFlags = 0b1100;

#[cfg(not(feature = "flags"))]
const FLAGS_MAX: ProtocolFlags = 0b1111;

/// Whether this protocol signals with a fictitious length, that is, via
/// [`Hasher::write_length_prefix`]. Otherwise it signals with a special static string slice `&str`,
/// that is, via [`Hasher::write_str`].
pub const fn is_signal_via_len(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        debug_assert!(flags <= FLAGS_MAX);
        flags & FLAGS_BIT_VIA_STR == 0
    }
    #[cfg(feature = "flags")]
    {
        !flags.signal_via_str
    }
}
/// Whether this protocol signals with a special static string slice `&str, that is, via
///  [`Hasher::write_str`]. Otherwise it signals with a fictitious length, that is, via
/// [`Hasher::write_length_prefix`].
pub const fn is_signal_via_str(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        debug_assert!(flags <= FLAGS_MAX);
        flags & FLAGS_BIT_VIA_STR != 0
    }
    #[cfg(feature = "flags")]
    {
        flags.signal_via_str
    }
}

/// Whether the protocol signals before it submits the hash.
pub const fn is_signal_first(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        debug_assert!(flags <= FLAGS_MAX);
        flags & FLAGS_BIT_SIGNAL_FIRST != 0
    }
    #[cfg(feature = "flags")]
    {
        flags.signal_first
    }
}
/// Whether the protocol submits the hash before it signals.
pub const fn is_submit_first(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        #[cfg(feature = "chk")]
        assert!(flags <= FLAGS_MAX);
        flags & FLAGS_BIT_SIGNAL_FIRST == 0
    }
    #[cfg(feature = "flags")]
    {
        !flags.signal_first
    }
}

pub const fn is_hash_via_u64(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        #[cfg(feature = "chk")]
        assert!(flags <= FLAGS_MAX);
        flags & FLAGS_MASK_HASH_U64 == FLAGS_MASK_HASH_U64
    }
    #[cfg(feature = "flags")]
    {
        matches!(flags.hash_via, HashViaInternal::U64)
    }
}
pub const fn is_hash_via_i64(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        #[cfg(feature = "chk")]
        assert!(flags <= FLAGS_MAX);
        flags & FLAGS_MASK_HASH_I64 == FLAGS_MASK_HASH_I64
    }
    #[cfg(feature = "flags")]
    {
        matches!(flags.hash_via, HashViaInternal::I64)
    }
}
pub const fn is_hash_via_u128(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        #[cfg(feature = "chk")]
        assert!(flags <= FLAGS_MAX);
        flags & FLAGS_MASK_HASH_U128 == FLAGS_MASK_HASH_U128
    }
    #[cfg(feature = "flags")]
    {
        matches!(flags.hash_via, HashViaInternal::U128)
    }
}
pub const fn is_hash_via_i128(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        #[cfg(feature = "chk")]
        assert!(flags <= FLAGS_MAX);
        flags & FLAGS_MASK_HASH_I128 == FLAGS_MASK_HASH_I128
    }
    #[cfg(feature = "flags")]
    {
        matches!(flags.hash_via, HashViaInternal::I128)
    }
}

/// A helper enum that allows us to use `match ... {...}`` statements, rather than
///
/// `if is_signal_via...(PF) {...} else {...}`.
///
/// Rust checks match statements to be exhaustive, so one less chance of a mistake.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignalVia {
    Len,
    Str,
}
pub const fn signal_via(flags: ProtocolFlags) -> SignalVia {
    if is_signal_via_len(flags) {
        SignalVia::Len
    } else {
        SignalVia::Str
    }
}

/// A helper enum that allows us to use `match ... {...}`` statements, rather than
///
/// `if is_submit_first(PF) {...} else {...}`.
///
/// Rust checks match statements to be exhaustive, so one less chance of a mistake.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    SubmitFirst,
    SignalFirst,
}
pub const fn flow(flags: ProtocolFlags) -> Flow {
    if is_submit_first(flags) {
        Flow::SubmitFirst
    } else {
        Flow::SignalFirst
    }
}

/// Constructors of [ProtocolFlags].
pub mod new {
    /// Constructors of [crate::ProtocolFlags] for protocols that that
    /// - signal with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
    /// - sends hash via [core::hash::Hasher::write_u64].
    pub mod len_u64 {
        use crate::flags::ProtocolFlags;

        #[cfg(feature = "flags")]
        use crate::flags::HashViaInternal;

        #[cfg(not(feature = "flags"))]
        use crate::flags::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_MASK_HASH_U64};

        /// Flag constructor for protocols that
        /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
        /// - sends hash via [core::hash::Hasher::write_u64]
        /// - signals before it submits the hash.
        pub const fn signal_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U64
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: false,
                hash_via: HashViaInternal::U64,
                signal_first: true,
            }
        }
        /// Flag constructor for protocols that
        /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
        /// - sends hash via [core::hash::Hasher::write_u64]
        /// - submits the hash before it signals.
        pub const fn submit_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                0 | FLAGS_MASK_HASH_U64
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: false,
                hash_via: HashViaInternal::U64,
                signal_first: false,
            }
        }
    }
    /// Constructors of [crate::ProtocolFlags] for protocols that that
    /// - signal with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
    /// - sends hash via [core::hash::Hasher::write_i64].
    pub mod len_i64 {
        use crate::flags::ProtocolFlags;

        #[cfg(feature = "flags")]
        use crate::flags::HashViaInternal;

        #[cfg(not(feature = "flags"))]
        use crate::flags::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_MASK_HASH_I64};

        /// Flag constructor for protocols that
        /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
        /// - sends hash via [core::hash::Hasher::write_i64]
        /// - signals before it submits the hash.
        pub const fn signal_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I64
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: false,
                hash_via: HashViaInternal::I64,
                signal_first: true,
            }
        }
        /// Flag constructor for protocols that
        /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
        /// - sends hash via [core::hash::Hasher::write_i64]
        /// - submits the hash before it signals.
        pub const fn submit_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                0 | FLAGS_MASK_HASH_I64
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: false,
                hash_via: HashViaInternal::I64,
                signal_first: false,
            }
        }
    }
    /// Constructors of [crate::ProtocolFlags] for protocols that that
    /// - signal with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
    /// - sends hash via [core::hash::Hasher::write_u128].
    pub mod len_u128 {
        use crate::flags::ProtocolFlags;

        #[cfg(feature = "flags")]
        use crate::flags::HashViaInternal;

        #[cfg(not(feature = "flags"))]
        use crate::flags::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_MASK_HASH_U128};

        /// Flag constructor for protocols that
        /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
        /// - sends hash via [core::hash::Hasher::write_u128]
        /// - signals before it submits the hash.
        pub const fn signal_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U128
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: false,
                hash_via: HashViaInternal::U128,
                signal_first: true,
            }
        }
        /// Flag constructor for protocols that
        /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
        /// - sends hash via [core::hash::Hasher::write_u129]
        /// - submits the hash before it signals.
        pub const fn submit_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                0 | FLAGS_MASK_HASH_U128
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: false,
                hash_via: HashViaInternal::U128,
                signal_first: false,
            }
        }
    }
    /// Constructors of [crate::ProtocolFlags] for protocols that that
    /// - signal with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
    /// - sends hash via [core::hash::Hasher::write_i128].
    pub mod len_i128 {
        use crate::flags::ProtocolFlags;

        #[cfg(feature = "flags")]
        use crate::flags::HashViaInternal;

        #[cfg(not(feature = "flags"))]
        use crate::flags::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_MASK_HASH_I128};

        /// Flag constructor for protocols that
        /// - signals with a fictitious length (via [`Hasher::write_length_prefix`]).
        /// - sends hash via [core::hash::Hasher::write_u128]
        /// - signals before it submits the hash.
        pub const fn signal_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I128
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: false,
                hash_via: HashViaInternal::I128,
                signal_first: true,
            }
        }
        /// Flag constructor for protocols that
        /// - signals with a fictitious length (via [`Hasher::write_length_prefix`]).
        /// - sends hash via [core::hash::Hasher::write_u129]
        /// - submits the hash before it signals.
        pub const fn submit_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                0 | FLAGS_MASK_HASH_I128
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: false,
                hash_via: HashViaInternal::I128,
                signal_first: false,
            }
        }
    }
    //------

    /// Constructors of [crate::ProtocolFlags] for protocols that that
    /// - signal with a dedicated string slice (via [`core::hash::Hasher::write_str`]), and
    /// - sends hash via [core::hash::Hasher::write_u64].
    pub mod str_u64 {
        use crate::flags::ProtocolFlags;

        #[cfg(feature = "flags")]
        use crate::flags::HashViaInternal;

        #[cfg(not(feature = "flags"))]
        use crate::flags::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_BIT_VIA_STR, FLAGS_MASK_HASH_U64};

        /// Flag constructor for protocols that
        /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - sends hash via [core::hash::Hasher::write_u64]
        /// - signals before it submits the hash.
        pub const fn signal_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_VIA_STR | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U64
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: true,
                hash_via: HashViaInternal::U64,
                signal_first: true,
            }
        }
        /// Flag constructor for protocols that
        /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - sends hash via [core::hash::Hasher::write_u64]
        /// - submits the hash before it signals.
        pub const fn submit_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_VIA_STR | 0 | FLAGS_MASK_HASH_U64
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: true,
                hash_via: HashViaInternal::U64,
                signal_first: false,
            }
        }
    }
    /// Constructors of [crate::ProtocolFlags] for protocols that that
    /// - signal with a dedicated string slice (via [`core::hash::Hasher::write_str`]), and
    /// - sends hash via [core::hash::Hasher::write_i64].
    pub mod str_i64 {
        use crate::flags::ProtocolFlags;

        #[cfg(feature = "flags")]
        use crate::flags::HashViaInternal;

        #[cfg(not(feature = "flags"))]
        use crate::flags::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_BIT_VIA_STR, FLAGS_MASK_HASH_I64};

        /// Flag constructor for protocols that
        /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - sends hash via [core::hash::Hasher::write_u64]
        /// - signals before it submits the hash.
        pub const fn signal_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_VIA_STR | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I64
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: true,
                hash_via: HashViaInternal::I64,
                signal_first: true,
            }
        }
        /// Flag constructor for protocols that
        /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - sends hash via [core::hash::Hasher::write_i64]
        /// - submits the hash before it signals.
        pub const fn submit_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_VIA_STR | 0 | FLAGS_MASK_HASH_I64
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: true,
                hash_via: HashViaInternal::I64,
                signal_first: false,
            }
        }
    }
    /// Constructors of [crate::ProtocolFlags] for protocols that that
    /// - signal with a dedicated string slice (via [`core::hash::Hasher::write_str`]), and
    /// - sends hash via [core::hash::Hasher::write_u128].
    pub mod str_u128 {
        use crate::flags::ProtocolFlags;

        #[cfg(feature = "flags")]
        use crate::flags::HashViaInternal;

        #[cfg(not(feature = "flags"))]
        use crate::flags::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_BIT_VIA_STR, FLAGS_MASK_HASH_U128};

        /// Flag constructor for protocols that
        /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - sends hash via [core::hash::Hasher::write_u128]
        /// - signals before it submits the hash.
        pub const fn signal_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_VIA_STR | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U128
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: true,
                hash_via: HashViaInternal::U128,
                signal_first: true,
            }
        }
        /// Flag constructor for protocols that
        /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - sends hash via [core::hash::Hasher::write_u128]
        /// - submits the hash before it signals.
        pub const fn submit_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_VIA_STR | 0 | FLAGS_MASK_HASH_U128
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: true,
                hash_via: HashViaInternal::U128,
                signal_first: false,
            }
        }
    }
    /// Constructors of [crate::ProtocolFlags] for protocols that that
    /// - signal with a dedicated string slice (via [`core::hash::Hasher::write_str`]), and
    /// - sends hash via [core::hash::Hasher::write_i128].
    pub mod str_i128 {
        use crate::flags::ProtocolFlags;

        #[cfg(feature = "flags")]
        use crate::flags::HashViaInternal;

        #[cfg(not(feature = "flags"))]
        use crate::flags::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_BIT_VIA_STR, FLAGS_MASK_HASH_I128};

        /// Flag constructor for protocols that
        /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - sends hash via [core::hash::Hasher::write_i128]
        /// - signals before it submits the hash.
        pub const fn signal_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_VIA_STR | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I128
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: true,
                hash_via: HashViaInternal::I128,
                signal_first: true,
            }
        }
        /// Flag constructor for protocols that
        /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - sends hash via [core::hash::Hasher::write_i128]
        /// - submits the hash before it signals.
        pub const fn submit_first() -> ProtocolFlags {
            #[cfg(not(feature = "flags"))]
            {
                FLAGS_BIT_VIA_STR | 0 | FLAGS_MASK_HASH_I128
            }
            #[cfg(feature = "flags")]
            ProtocolFlags {
                signal_via_str: true,
                hash_via: HashViaInternal::I128,
                signal_first: false,
            }
        }
    }
}

/// Marker trait, making separate [inject_via_len] implementations easier.
pub trait _ProtocolFlagsSignalledViaLen {}
pub struct _ProtocolFlagsSubset<const PF: ProtocolFlags>;
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::len_u64::signal_first() }> {}
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::len_u64::submit_first() }> {}
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::len_i64::signal_first() }> {}
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::len_i64::submit_first() }> {}

impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::len_u128::signal_first() }> {}
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::len_u128::submit_first() }> {}
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::len_i128::signal_first() }> {}
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::len_i128::submit_first() }> {}

pub trait _ProtocolFlagsSignalledViaStr {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::str_u64::signal_first() }> {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::str_u64::submit_first() }> {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::str_i64::signal_first() }> {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::str_i64::submit_first() }> {}

impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::str_u128::signal_first() }> {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::str_u128::submit_first() }> {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::str_i128::signal_first() }> {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::str_i128::submit_first() }> {}

const _CHECKS: () = {
    assert!(is_signal_via_len(new::len_u64::signal_first())==true);
    assert!(is_signal_via_len(new::len_u64::submit_first())==true);
    assert!(is_signal_via_len(new::len_i64::signal_first())==true);
    assert!(is_signal_via_len(new::len_i64::submit_first())==true);

    assert!(is_signal_via_len(new::len_u128::signal_first())==true);
    assert!(is_signal_via_len(new::len_u128::submit_first())==true);
    assert!(is_signal_via_len(new::len_i128::signal_first())==true);
    assert!(is_signal_via_len(new::len_i128::submit_first())==true);

    assert!(is_signal_via_str(new::str_u64::signal_first())==true);
    assert!(is_signal_via_str(new::str_u64::submit_first())==true);
    assert!(is_signal_via_str(new::str_i64::signal_first())==true);
    assert!(is_signal_via_str(new::str_i64::submit_first())==true);

    assert!(is_signal_via_str(new::str_u128::signal_first())==true);
    assert!(is_signal_via_str(new::str_u128::submit_first())==true);
    assert!(is_signal_via_str(new::str_i128::signal_first())==true);
    assert!(is_signal_via_str(new::str_i128::submit_first())==true);
    // ----

    assert!(is_signal_first(new::len_u64::signal_first())==true);
    assert!(is_submit_first(new::len_u64::submit_first())==true);
    assert!(is_signal_first(new::len_i64::signal_first())==true);
    assert!(is_submit_first(new::len_i64::submit_first())==true);

    assert!(is_signal_first(new::len_u128::signal_first())==true);
    assert!(is_submit_first(new::len_u128::submit_first())==true);
    assert!(is_signal_first(new::len_i128::signal_first())==true);
    assert!(is_submit_first(new::len_i128::submit_first())==true);

    assert!(is_signal_first(new::str_u64::signal_first())==true);
    assert!(is_submit_first(new::str_u64::submit_first())==true);
    assert!(is_signal_first(new::str_i64::signal_first())==true);
    assert!(is_submit_first(new::str_i64::submit_first())==true);

    assert!(is_signal_first(new::str_u128::signal_first())==true);
    assert!(is_submit_first(new::str_u128::submit_first())==true);
    assert!(is_signal_first(new::str_i128::signal_first())==true);
    assert!(is_submit_first(new::str_i128::submit_first())==true);
    // ----

    assert!(is_hash_via_u64(new::len_u64::signal_first())==true);
    assert!(is_hash_via_u64(new::len_u64::submit_first())==true);
    assert!(is_hash_via_i64(new::len_i64::signal_first())==true);
    assert!(is_hash_via_i64(new::len_i64::submit_first())==true);

    assert!(is_hash_via_u128(new::len_u128::signal_first())==true);
    assert!(is_hash_via_u128(new::len_u128::submit_first())==true);
    assert!(is_hash_via_i128(new::len_i128::signal_first())==true);
    assert!(is_hash_via_i128(new::len_i128::submit_first())==true);

    assert!(is_hash_via_u64(new::str_u64::signal_first())==true);
    assert!(is_hash_via_u64(new::str_u64::submit_first())==true);
    assert!(is_hash_via_i64(new::str_i64::signal_first())==true);
    assert!(is_hash_via_i64(new::str_i64::submit_first())==true);

    assert!(is_hash_via_u128(new::str_u128::signal_first())==true);
    assert!(is_hash_via_u128(new::str_u128::submit_first())==true);
    assert!(is_hash_via_i128(new::str_i128::signal_first())==true);
    assert!(is_hash_via_i128(new::str_i128::submit_first())==true);
};