use crate::hash::InjectionFlags;
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::mem;
use core::ops::{Deref, DerefMut};

// duality triality quaternity

// tertiary quaternary
/// Implementation detail only: For now this is only `bool`, and it indicates whether
/// [core::cmp::PartialEq] implementation should compare `hash` field before comparing `p` field.
/// Use `true` if `P` is larger/more complex than `u64`.
pub type KeyFlags = KeyFlagsImpl;

// If we ever have more than one flag, then change this into e.g. u8.
#[cfg(not(feature = "adt-const-params"))]
type KeyFlagsImpl = bool;

#[cfg(feature = "adt-const-params")]
/// Type for const generic parameter `KF`.
#[derive(ConstParamTy, Clone, Copy, PartialEq, Eq)]
pub struct KeyFlagsImpl {
    compare_hash_first: bool,
}

#[derive(Eq, Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Primary<P, const IF: InjectionFlags/* , const KF: KeyFlags*/> {
    /// `hash` is listed before `p`, so that it can short-circuit the derived [PartialEq]
    /// implementation by comparing `hash` first.
    ///
    /// TODO Consider a flag in Flags to control whether PartialEq compares hash or not.
    pub hash: u64,
    pub p: P,
}
impl<P: Hash, const IF: InjectionFlags> Primary<P, IF> {
    pub fn new(p: P, hash: u64) -> Self {
        Self { p, hash }
    }
    /// We consume the hasher, so that it's not reused accidentally.
    pub fn new_from_hasher<H: Hasher>(key: P, mut h: H) -> Self {
        key.hash(&mut h);
        Self::new(key, h.finish())
    }
}
impl<P: PartialEq, const IF: InjectionFlags> PartialEq for Primary<P, IF> {
    fn eq(&self, other: &Self) -> bool {
        self.p == other.p
    }
    fn ne(&self, other: &Self) -> bool {
        self.p != other.p
    }
}
impl<P: Hash, const IF: InjectionFlags> Hash for Primary<P, IF> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, IF>(state, self.hash);
    }
}
impl<P, const IF: InjectionFlags> Deref for Primary<P, IF> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        &self.p
    }
}
impl<P, const IF: InjectionFlags> DerefMut for Primary<P, IF> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.p
    }
}

#[derive(Clone, Copy, Debug, Eq)]
#[non_exhaustive]
pub struct Secondary<S, const IF: InjectionFlags> {
    pub hash: u64,
    pub s: S,
}
impl<S, const IF: InjectionFlags> Secondary<S, IF> {
    pub fn new(s: S, hash: u64) -> Self {
        Self { s, hash }
    }
}
impl<S: PartialEq, const IF: InjectionFlags> PartialEq for Secondary<S, IF> {
    fn eq(&self, other: &Self) -> bool {
        self.s == other.s
    }
    fn ne(&self, other: &Self) -> bool {
        self.s != other.s
    }
}
impl<S: PartialOrd, const IF: InjectionFlags> PartialOrd for Secondary<S, IF> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.s.partial_cmp(&other.s)
    }
    fn ge(&self, other: &Self) -> bool {
        self.s.ge(&other.s)
    }
    fn gt(&self, other: &Self) -> bool {
        self.s.gt(&other.s)
    }
    fn le(&self, other: &Self) -> bool {
        self.s.le(&other.s)
    }
    fn lt(&self, other: &Self) -> bool {
        self.s.lt(&other.s)
    }
}
impl<S: Ord, const IF: InjectionFlags> Ord for Secondary<S, IF> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.s.cmp(&other.s)
    }
}
impl<S: Hash, const IF: InjectionFlags> Hash for Secondary<S, IF> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, IF>(state, self.hash);
    }
}
impl<S, const IF: InjectionFlags> Deref for Secondary<S, IF> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.s
    }
}
impl<S, const IF: InjectionFlags> DerefMut for Secondary<S, IF> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s
    }
}

/// A bi-modal wrapper. On its own it uses only `ck` part for [PartialEq] and [Hash]. However, see
/// trait for borrowing as comparable by `idx` part, too.
#[derive(Clone, Eq, Copy, Debug)]
pub struct Duality<P, S, const IF: InjectionFlags> {
    pub pk: Primary<P, IF>,
    pub sk: Secondary<S, IF>,
}
impl<P, S, const IF: InjectionFlags> Duality<P, S, IF> {
    pub fn new(pk: Primary<P, IF>, sk: Secondary<S, IF>) -> Self {
        Self { pk, sk }
    }
}

impl<P, S, const IF: InjectionFlags> Hash for Duality<P, S, IF> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, IF>(state, self.sk.hash);
    }
}
impl<P: PartialEq, S, const IF: InjectionFlags> PartialEq for Duality<P, S, IF> {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
    fn ne(&self, other: &Self) -> bool {
        self.pk != other.pk
    }
}

impl<P, S, const IF: InjectionFlags> Borrow<Primary<P, IF>> for Duality<P, S, IF> {
    fn borrow(&self) -> &Primary<P, IF> {
        &self.pk
    }
}
impl<P, S, const IF: InjectionFlags> Borrow<Secondary<S, IF>> for Duality<P, S, IF> {
    fn borrow(&self) -> &Secondary<S, IF> {
        &self.sk
    }
}

/// Needed, because we can't implement both `Borrow<Primary<P>>` and `Borrow<P>` for
/// `Duality<P, S, F>`, as they could conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PrimaryWrap<P> {
    pub p: P,
}

impl<'a, P, S, const IF: InjectionFlags> Borrow<PrimaryWrap<P>> for Duality<P, S, IF> {
    fn borrow(&self) -> &PrimaryWrap<P> {
        unsafe { mem::transmute(&self.pk.p) }
    }
}

/// Needed, because we can't implement both `Borrow<Secondary<S>>` and `Borrow<S>` for
/// `Duality<P, S, F>`, as they could conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct SecondaryWrap<S> {
    pub s: S,
}

impl<'a, P, S, const IF: InjectionFlags> Borrow<SecondaryWrap<P>> for Duality<P, S, IF> {
    fn borrow(&self) -> &SecondaryWrap<P> {
        unsafe { mem::transmute(&self.sk.s) }
    }
}
