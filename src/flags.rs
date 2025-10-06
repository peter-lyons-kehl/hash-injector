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

#[cfg_attr(feature = "flags", derive(ConstParamTy))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashVia {
    U64,
    I64,
    U128,
    I128,
}

#[cfg_attr(feature = "flags", derive(ConstParamTy))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalVia {
    U8s,
    Len,
    Str,
}

#[cfg(feature = "flags")]
/// Type for const generic parameter `PF`.
#[derive(ConstParamTy, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolFlagsImpl {
    signal_via: SignalVia,
    signal_first: bool,
    hash_via: HashVia,
}

#[cfg(not(feature = "flags"))]
const FLAGS_MASK_VIA_U8S: ProtocolFlags = 0b00;
#[cfg(not(feature = "flags"))]
const FLAGS_MASK_VIA_LEN: ProtocolFlags = 0b01;
#[cfg(not(feature = "flags"))]
const FLAGS_MASK_VIA_STR: ProtocolFlags = 0b10;
#[cfg(not(feature = "flags"))]
const FLAGS_BITS_VIA: ProtocolFlags = 0b11;

#[cfg(not(feature = "flags"))]
const FLAGS_BIT_SIGNAL_FIRST: ProtocolFlags = 0b100;

#[cfg(not(feature = "flags"))]
const FLAGS_MASK_HASH_U64: ProtocolFlags = 0b0000;
#[cfg(not(feature = "flags"))]
const FLAGS_MASK_HASH_I64: ProtocolFlags = 0b1000;
#[cfg(not(feature = "flags"))]
const FLAGS_MASK_HASH_U128: ProtocolFlags = 0b10000;
#[cfg(not(feature = "flags"))]
const FLAGS_MASK_HASH_I128: ProtocolFlags = 0b11000;

#[cfg(not(feature = "flags"))]
const FLAGS_MAX: ProtocolFlags = 0b11110;

/// Whether this protocol signals with a special static u8 slice `&[u8]`, that is, via
///  [`core::hash::Hasher::write`].
pub const fn is_signal_via_u8s(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        debug_assert!(flags <= FLAGS_MAX);
        flags & FLAGS_BITS_VIA == FLAGS_MASK_VIA_U8S
    }
    #[cfg(feature = "flags")]
    {
        matches!(flags.signal_via, SignalVia::U8s)
    }
}

/// Whether this protocol signals with a fictitious length, that is, via
/// [`core::hash::Hasher::write_length_prefix`].
pub const fn is_signal_via_len(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        debug_assert!(flags <= FLAGS_MAX);
        flags & FLAGS_BITS_VIA == FLAGS_MASK_VIA_LEN
    }
    #[cfg(feature = "flags")]
    {
        matches!(flags.signal_via, SignalVia::Len)
    }
}
/// Whether this protocol signals with a special static string slice `&str, that is, via
///  [`core::hash::Hasher::write_str`].
pub const fn is_signal_via_str(flags: ProtocolFlags) -> bool {
    #[cfg(not(feature = "flags"))]
    {
        debug_assert!(flags <= FLAGS_MAX);
        flags & FLAGS_BITS_VIA == FLAGS_MASK_VIA_STR
    }
    #[cfg(feature = "flags")]
    {
        matches!(flags.signal_via, SignalVia::Str)
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
        matches!(flags.hash_via, HashVia::U64)
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
        matches!(flags.hash_via, HashVia::I64)
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
        matches!(flags.hash_via, HashVia::U128)
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
        matches!(flags.hash_via, HashVia::I128)
    }
}

pub(crate) const fn signal_via(flags: ProtocolFlags) -> SignalVia {
    if is_signal_via_u8s(flags) {
        SignalVia::U8s
    } else if is_signal_via_len(flags) {
        SignalVia::Len
    } else if is_signal_via_str(flags) {
        SignalVia::Str
    } else {
        unreachable!()
    }
}

pub(crate) const fn hash_via(flags: ProtocolFlags) -> HashVia {
    if is_hash_via_u64(flags) {
        HashVia::U64
    } else if is_hash_via_i64(flags) {
        HashVia::I64
    } else if is_hash_via_u128(flags) {
        HashVia::U128
    } else if is_hash_via_i128(flags) {
        HashVia::I128
    } else {
        unreachable!()
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
    #[cfg(any(feature = "mx", feature = "ndd"))]
    /// Constructors of [crate::ProtocolFlags] for protocols that
    /// signal with a dedicated u8 slice (via [`core::hash::Hasher::write`]).
    pub mod u8s {
        /// Constructors of [crate::ProtocolFlags] for protocols that
        /// - signal with a dedicated u8 slice (via [`core::hash::Hasher::write`]).
        /// - signal before they submit the hash.
        pub mod signal_first {
            use crate::flags::ProtocolFlags;

            #[cfg(feature = "flags")]
            use crate::flags::{HashVia, SignalVia};

            #[cfg(not(feature = "flags"))]
            use crate::flags::{
                FLAGS_BIT_SIGNAL_FIRST, FLAGS_MASK_HASH_I64, FLAGS_MASK_HASH_I128,
                FLAGS_MASK_HASH_U64, FLAGS_MASK_HASH_U128, FLAGS_MASK_VIA_U8S,
            };

            /// Flag constructor for protocols that
            /// - signals with a dedicated u8 slice (via [`core::hash::Hasher::write`])
            /// - sends hash via [core::hash::Hasher::write_u64]
            /// - signals before it submits the hash.
            pub const fn u64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_U8S | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::U8s,
                    hash_via: HashVia::U64,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated u8 slice (via [`core::hash::Hasher::write`])
            /// - sends hash via [core::hash::Hasher::write_i64]
            /// - signals before it submits the hash.
            pub const fn i64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_U8S | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::U8s,
                    hash_via: HashVia::I64,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated u8 slice (via [`core::hash::Hasher::write`])
            /// - sends hash via [core::hash::Hasher::write_u128]
            /// - signals before it submits the hash.
            pub const fn u128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_U8S | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::U8s,
                    hash_via: HashVia::U128,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated u8 slice (via [`core::hash::Hasher::write`])
            /// - sends hash via [core::hash::Hasher::write_u128]
            /// - signals before it submits the hash.
            pub const fn i128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_U8S | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::U8s,
                    hash_via: HashVia::I128,
                    signal_first: true,
                }
            }
        }

        /// Constructors of [crate::ProtocolFlags] for protocols that
        /// - signal with a dedicated u8 slice (via [`core::hash::Hasher::write`])
        /// - submit the hash before they signal.
        pub mod submit_first {
            use crate::flags::ProtocolFlags;

            #[cfg(feature = "flags")]
            use crate::flags::{HashVia, SignalVia};

            #[cfg(not(feature = "flags"))]
            use crate::flags::{
                FLAGS_MASK_HASH_I64, FLAGS_MASK_HASH_I128, FLAGS_MASK_HASH_U64,
                FLAGS_MASK_HASH_U128, FLAGS_MASK_VIA_U8S,
            };

            /// Flag constructor for protocols that
            /// - signals with a dedicated u8 slice (via [`core::hash::Hasher::write`])
            /// - sends hash via [core::hash::Hasher::write_u64]
            /// - submits the hash before it signals.
            pub const fn u64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_U8S | 0 | FLAGS_MASK_HASH_U64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::U8s,
                    hash_via: HashVia::U64,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated u8 slice (via [`core::hash::Hasher::write`])
            /// - sends hash via [core::hash::Hasher::write_i64]
            /// - submits the hash before it signals.
            pub const fn i64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_U8S | 0 | FLAGS_MASK_HASH_I64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::U8s,
                    hash_via: HashVia::I64,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated u8 slice (via [`core::hash::Hasher::write`])
            /// - sends hash via [core::hash::Hasher::write_u129]
            /// - submits the hash before it signals.
            pub const fn u128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_U8S | 0 | FLAGS_MASK_HASH_U128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::U8s,
                    hash_via: HashVia::U128,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated u8 slice (via [`core::hash::Hasher::write`])
            /// - sends hash via [core::hash::Hasher::write_u129]
            /// - submits the hash before it signals.
            pub const fn i128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_U8S | 0 | FLAGS_MASK_HASH_I128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::U8s,
                    hash_via: HashVia::I128,
                    signal_first: false,
                }
            }
        }
    }

    #[cfg(feature = "hpe")]
    /// Constructors of [crate::ProtocolFlags] for protocols that that signal with a fictitious
    /// length (via [`core::hash::Hasher::write_length_prefix`]).
    pub mod len {
        /// Constructors of [crate::ProtocolFlags] for protocols that that
        /// - signal with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
        /// - signal before they submit the hash.
        pub mod signal_first {
            use crate::flags::ProtocolFlags;

            #[cfg(feature = "flags")]
            use crate::flags::{HashVia, SignalVia};

            #[cfg(not(feature = "flags"))]
            use crate::flags::{
                FLAGS_BIT_SIGNAL_FIRST, FLAGS_MASK_HASH_I64, FLAGS_MASK_HASH_I128,
                FLAGS_MASK_HASH_U64, FLAGS_MASK_HASH_U128, FLAGS_MASK_VIA_LEN,
            };

            /// Flag constructor for protocols that
            /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
            /// - sends hash via [core::hash::Hasher::write_u64]
            /// - signals before it submits the hash.
            pub const fn u64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_LEN | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Len,
                    hash_via: HashVia::U64,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a fictitious length (via
            ///   [`core::hash::Hasher::write_length_prefix`]).
            /// - sends hash via [core::hash::Hasher::write_i64]
            /// - signals before it submits the hash.
            pub const fn i64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_LEN | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Len,
                    hash_via: HashVia::I64,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
            /// - sends hash via [core::hash::Hasher::write_u128]
            /// - signals before it submits the hash.
            pub const fn u128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_LEN | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Len,
                    hash_via: HashVia::U128,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a fictitious length (via [`Hasher::write_length_prefix`]).
            /// - sends hash via [core::hash::Hasher::write_u128]
            /// - signals before it submits the hash.
            pub const fn i128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_LEN | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Len,
                    hash_via: HashVia::I128,
                    signal_first: true,
                }
            }
        }

        /// Constructors of [crate::ProtocolFlags] for protocols that that
        /// - signal with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
        /// - submit the hash before they signal.
        pub mod submit_first {
            use crate::flags::ProtocolFlags;

            #[cfg(feature = "flags")]
            use crate::flags::{HashVia, SignalVia};

            #[cfg(not(feature = "flags"))]
            use crate::flags::{
                FLAGS_MASK_HASH_I64, FLAGS_MASK_HASH_I128, FLAGS_MASK_HASH_U64,
                FLAGS_MASK_HASH_U128, FLAGS_MASK_VIA_LEN,
            };

            /// Flag constructor for protocols that
            /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
            /// - sends hash via [core::hash::Hasher::write_u64]
            /// - submits the hash before it signals.
            pub const fn u64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_LEN | 0 | FLAGS_MASK_HASH_U64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Len,
                    hash_via: HashVia::U64,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a fictitious length (via
            ///   [`core::hash::Hasher::write_length_prefix`]).
            /// - sends hash via [core::hash::Hasher::write_i64]
            /// - submits the hash before it signals.
            pub const fn i64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_LEN | 0 | FLAGS_MASK_HASH_I64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Len,
                    hash_via: HashVia::I64,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a fictitious length (via [`core::hash::Hasher::write_length_prefix`]).
            /// - sends hash via [core::hash::Hasher::write_u129]
            /// - submits the hash before it signals.
            pub const fn u128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_LEN | 0 | FLAGS_MASK_HASH_U128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Len,
                    hash_via: HashVia::U128,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a fictitious length (via [`Hasher::write_length_prefix`]).
            /// - sends hash via [core::hash::Hasher::write_u129]
            /// - submits the hash before it signals.
            pub const fn i128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_LEN | 0 | FLAGS_MASK_HASH_I128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Len,
                    hash_via: HashVia::I128,
                    signal_first: false,
                }
            }
        }
    }

    #[cfg(any(feature = "mx", feature = "ndd"))]
    /// Constructors of [crate::ProtocolFlags] for protocols that signal with a dedicated string
    /// slice (via [`core::hash::Hasher::write_str`]).
    pub mod str {
        /// Flag constructor for protocols that
        /// - signal with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - signal before they submit the hash.
        pub mod signal_first {
            use crate::flags::ProtocolFlags;

            #[cfg(feature = "flags")]
            use crate::flags::{HashVia, SignalVia};

            #[cfg(not(feature = "flags"))]
            use crate::flags::{
                FLAGS_BIT_SIGNAL_FIRST, FLAGS_MASK_HASH_I64, FLAGS_MASK_HASH_I128,
                FLAGS_MASK_HASH_U64, FLAGS_MASK_HASH_U128, FLAGS_MASK_VIA_STR,
            };

            /// Flag constructor for protocols that
            /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
            /// - sends hash via [core::hash::Hasher::write_u64]
            /// - signals before it submits the hash.
            pub const fn u64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_STR | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Str,
                    hash_via: HashVia::U64,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
            /// - sends hash via [core::hash::Hasher::write_u64]
            /// - signals before it submits the hash.
            pub const fn i64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_STR | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Str,
                    hash_via: HashVia::I64,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
            /// - sends hash via [core::hash::Hasher::write_u128]
            /// - signals before it submits the hash.
            pub const fn u128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_STR | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_U128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Str,
                    hash_via: HashVia::U128,
                    signal_first: true,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
            /// - sends hash via [core::hash::Hasher::write_i128]
            /// - signals before it submits the hash.
            pub const fn i128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_STR | FLAGS_BIT_SIGNAL_FIRST | FLAGS_MASK_HASH_I128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Str,
                    hash_via: HashVia::I128,
                    signal_first: true,
                }
            }
        }

        /// Flag constructor for protocols that
        /// - signal with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
        /// - submit the hash before they signal.
        pub mod submit_first {
            use crate::flags::ProtocolFlags;

            #[cfg(feature = "flags")]
            use crate::flags::{HashVia, SignalVia};

            #[cfg(not(feature = "flags"))]
            use crate::flags::{
                FLAGS_MASK_HASH_I64, FLAGS_MASK_HASH_I128, FLAGS_MASK_HASH_U64,
                FLAGS_MASK_HASH_U128, FLAGS_MASK_VIA_STR,
            };

            /// Flag constructor for protocols that
            /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
            /// - sends hash via [core::hash::Hasher::write_u64]
            /// - submits the hash before it signals.
            pub const fn u64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_STR | 0 | FLAGS_MASK_HASH_U64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Str,
                    hash_via: HashVia::U64,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
            /// - sends hash via [core::hash::Hasher::write_i64]
            /// - submits the hash before it signals.
            pub const fn i64() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_STR | 0 | FLAGS_MASK_HASH_I64
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Str,
                    hash_via: HashVia::I64,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
            /// - sends hash via [core::hash::Hasher::write_u128]
            /// - submits the hash before it signals.
            pub const fn u128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_STR | 0 | FLAGS_MASK_HASH_U128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Str,
                    hash_via: HashVia::U128,
                    signal_first: false,
                }
            }

            /// Flag constructor for protocols that
            /// - signals with a dedicated string slice (via [`core::hash::Hasher::write_str`]).
            /// - sends hash via [core::hash::Hasher::write_i128]
            /// - submits the hash before it signals.
            pub const fn i128() -> ProtocolFlags {
                #[cfg(not(feature = "flags"))]
                {
                    FLAGS_MASK_VIA_STR | 0 | FLAGS_MASK_HASH_I128
                }
                #[cfg(feature = "flags")]
                ProtocolFlags {
                    signal_via: SignalVia::Str,
                    hash_via: HashVia::I128,
                    signal_first: false,
                }
            }
        }
    }
}

const _CHECKS: () = {
    #[cfg(any(feature = "mx", feature = "ndd"))]
    {
        assert!(is_signal_via_u8s(new::u8s::signal_first::u64()) == true);
        assert!(is_signal_via_u8s(new::u8s::signal_first::i64()) == true);
        assert!(is_signal_via_u8s(new::u8s::signal_first::u128()) == true);
        assert!(is_signal_via_u8s(new::u8s::signal_first::i128()) == true);

        assert!(is_signal_via_u8s(new::u8s::submit_first::u64()) == true);
        assert!(is_signal_via_u8s(new::u8s::submit_first::i64()) == true);
        assert!(is_signal_via_u8s(new::u8s::submit_first::u128()) == true);
        assert!(is_signal_via_u8s(new::u8s::submit_first::i128()) == true);
    }
    #[cfg(feature = "hpe")]
    {
        assert!(is_signal_via_len(new::len::signal_first::u64()) == true);
        assert!(is_signal_via_len(new::len::signal_first::i64()) == true);
        assert!(is_signal_via_len(new::len::signal_first::u128()) == true);
        assert!(is_signal_via_len(new::len::signal_first::i128()) == true);

        assert!(is_signal_via_len(new::len::submit_first::u64()) == true);
        assert!(is_signal_via_len(new::len::submit_first::i64()) == true);
        assert!(is_signal_via_len(new::len::submit_first::u128()) == true);
        assert!(is_signal_via_len(new::len::submit_first::i128()) == true);
    }
    #[cfg(all(any(feature = "mx", feature = "ndd"), feature = "hpe"))]
    {
        assert!(is_signal_via_str(new::str::signal_first::u64()) == true);
        assert!(is_signal_via_str(new::str::signal_first::i64()) == true);
        assert!(is_signal_via_str(new::str::signal_first::u128()) == true);
        assert!(is_signal_via_str(new::str::signal_first::i128()) == true);

        assert!(is_signal_via_str(new::str::submit_first::u64()) == true);
        assert!(is_signal_via_str(new::str::submit_first::i64()) == true);
        assert!(is_signal_via_str(new::str::submit_first::u128()) == true);
        assert!(is_signal_via_str(new::str::submit_first::i128()) == true);
    }
    // ----

    #[cfg(any(feature = "mx", feature = "ndd"))]
    {
        assert!(is_signal_first(new::u8s::signal_first::u64()) == true);
        assert!(is_signal_first(new::u8s::signal_first::i64()) == true);
        assert!(is_signal_first(new::u8s::signal_first::u128()) == true);
        assert!(is_signal_first(new::u8s::signal_first::i128()) == true);

        assert!(is_submit_first(new::u8s::submit_first::u64()) == true);
        assert!(is_submit_first(new::u8s::submit_first::i64()) == true);
        assert!(is_submit_first(new::u8s::submit_first::u128()) == true);
        assert!(is_submit_first(new::u8s::submit_first::i128()) == true);
    }
    #[cfg(feature = "hpe")]
    {
        assert!(is_signal_first(new::len::signal_first::u64()) == true);
        assert!(is_signal_first(new::len::signal_first::i64()) == true);
        assert!(is_signal_first(new::len::signal_first::u128()) == true);
        assert!(is_signal_first(new::len::signal_first::i128()) == true);
        // ----

        assert!(is_submit_first(new::len::submit_first::u64()) == true);
        assert!(is_submit_first(new::len::submit_first::i64()) == true);
        assert!(is_submit_first(new::len::submit_first::u128()) == true);
        assert!(is_submit_first(new::len::submit_first::i128()) == true);
    }
    #[cfg(all(any(feature = "mx", feature = "ndd"), feature = "hpe"))]
    {
        assert!(is_signal_first(new::str::signal_first::u64()) == true);
        assert!(is_signal_first(new::str::signal_first::i64()) == true);
        assert!(is_signal_first(new::str::signal_first::u128()) == true);
        assert!(is_signal_first(new::str::signal_first::i128()) == true);
        // ----
        assert!(is_submit_first(new::str::submit_first::u64()) == true);
        assert!(is_submit_first(new::str::submit_first::i64()) == true);
        assert!(is_submit_first(new::str::submit_first::u128()) == true);
        assert!(is_submit_first(new::str::submit_first::i128()) == true);
    }
    // ----
    #[cfg(any(feature = "mx", feature = "ndd"))]
    {
        assert!(is_hash_via_u64(new::u8s::signal_first::u64()) == true);
        assert!(is_hash_via_i64(new::u8s::signal_first::i64()) == true);
        assert!(is_hash_via_u128(new::u8s::signal_first::u128()) == true);
        assert!(is_hash_via_i128(new::u8s::signal_first::i128()) == true);

        assert!(is_hash_via_u64(new::u8s::submit_first::u64()) == true);
        assert!(is_hash_via_i64(new::u8s::submit_first::i64()) == true);
        assert!(is_hash_via_u128(new::u8s::submit_first::u128()) == true);
        assert!(is_hash_via_i128(new::u8s::submit_first::i128()) == true);
    }
    #[cfg(feature = "hpe")]
    {
        assert!(is_hash_via_u64(new::len::signal_first::u64()) == true);
        assert!(is_hash_via_i64(new::len::signal_first::i64()) == true);
        assert!(is_hash_via_u128(new::len::signal_first::u128()) == true);
        assert!(is_hash_via_i128(new::len::signal_first::i128()) == true);

        assert!(is_hash_via_u64(new::len::submit_first::u64()) == true);
        assert!(is_hash_via_i64(new::len::submit_first::i64()) == true);
        assert!(is_hash_via_u128(new::len::submit_first::u128()) == true);
        assert!(is_hash_via_i128(new::len::submit_first::i128()) == true);
    }
    #[cfg(all(any(feature = "mx", feature = "ndd"), feature = "hpe"))]
    {
        assert!(is_hash_via_u64(new::str::signal_first::u64()) == true);
        assert!(is_hash_via_u128(new::str::signal_first::u128()) == true);
        assert!(is_hash_via_i64(new::str::signal_first::i64()) == true);
        assert!(is_hash_via_i128(new::str::signal_first::i128()) == true);

        assert!(is_hash_via_u64(new::str::submit_first::u64()) == true);
        assert!(is_hash_via_i64(new::str::submit_first::i64()) == true);
        assert!(is_hash_via_u128(new::str::submit_first::u128()) == true);
        assert!(is_hash_via_i128(new::str::submit_first::i128()) == true);
    }
};
