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
type ProtocolFlagsImpl = usize;

#[cfg(feature = "flags")]
/// Type for const generic parameter `PF`.
#[derive(ConstParamTy, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolFlagsImpl {
    signal_via_str: bool,
    signal_first: bool,
}

#[cfg(not(feature = "flags"))]
const FLAGS_BIT_VIA_STR: ProtocolFlags = 0b1;
#[cfg(not(feature = "flags"))]
const FLAGS_BIT_SIGNAL_FIRST: ProtocolFlags = 0b10;
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

pub mod new {
    use super::ProtocolFlags;
    #[cfg(not(feature = "flags"))]
    use super::{FLAGS_BIT_SIGNAL_FIRST, FLAGS_BIT_VIA_STR};

    /// Protocol that
    /// - signals with a fictitious length (via [`Hasher::write_length_prefix`]), and
    /// - signals before it submits the hash.
    pub const fn flags_len_signal_first() -> ProtocolFlags {
        #[cfg(not(feature = "flags"))]
        {
            FLAGS_BIT_SIGNAL_FIRST
        }
        #[cfg(feature = "flags")]
        ProtocolFlags {
            signal_via_str: false,
            signal_first: true,
        }
    }
    /// Protocol that
    /// - signals with a fictitious length (via [`Hasher::write_length_prefix`]), and
    /// - submits the hash before it signals.
    pub const fn flags_len_submit_first() -> ProtocolFlags {
        #[cfg(not(feature = "flags"))]
        {
            0
        }
        #[cfg(feature = "flags")]
        ProtocolFlags {
            signal_via_str: false,
            signal_first: false,
        }
    }
    /// Protocol that
    /// - signals with a  special string slice `&str` (via [`Hasher::write_str`]), and
    /// - signals before it submits the hash.
    pub const fn flags_str_signal_first() -> ProtocolFlags {
        #[cfg(not(feature = "flags"))]
        {
            FLAGS_BIT_VIA_STR & FLAGS_BIT_SIGNAL_FIRST
        }
        #[cfg(feature = "flags")]
        ProtocolFlags {
            signal_via_str: true,
            signal_first: true,
        }
    }
    /// Protocol that
    /// - signals with a  special string slice `&str` (via [`Hasher::write_str`]), and
    /// - submits the hash before it signals.
    pub const fn flags_str_submit_first() -> ProtocolFlags {
        #[cfg(not(feature = "flags"))]
        {
            FLAGS_BIT_VIA_STR
        }
        #[cfg(feature = "flags")]
        ProtocolFlags {
            signal_via_str: true,
            signal_first: false,
        }
    }
}

/// Marker trait, making separate [inject_via_len] implementations easier.
pub trait _ProtocolFlagsSignalledViaLen {}
pub struct _ProtocolFlagsSubset<const PF: ProtocolFlags>;
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::flags_len_signal_first() }> {}
impl _ProtocolFlagsSignalledViaLen for _ProtocolFlagsSubset<{ new::flags_len_submit_first() }> {}
pub trait _ProtocolFlagsSignalledViaStr {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::flags_str_signal_first() }> {}
impl _ProtocolFlagsSignalledViaStr for _ProtocolFlagsSubset<{ new::flags_str_submit_first() }> {}
