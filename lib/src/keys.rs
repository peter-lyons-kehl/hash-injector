use crate::hash::Flags;
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::mem;
use core::ops::{Deref, DerefMut};

// duality triality quaternity

// tertiary quaternary
/// `CHF` = "Compare Hash First": whether [core::cmp::PartialEq] should compare `hash` field before
/// comparing `p` field. Use `true` if `P` is larger/more complex than `u64`.
#[derive(Eq, Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Primary<P, const F: Flags /* , const CHF: bool*/> {
    /// `hash` is listed before `p`, so that it can short-circuit the derived [PartialEq]
    /// implementation by comparing `hash` first.
    ///
    /// TODO Consider a flag in Flags to control whether PartialEq compares hash or not.
    pub hash: u64,
    pub p: P,
}
impl<P: Hash, const F: Flags> Primary<P, F> {
    pub fn new(p: P, hash: u64) -> Self {
        Self { p, hash }
    }
    /// We consume the hasher, so that it's not reused accidentally.
    pub fn new_from_hasher<H: Hasher>(key: P, mut h: H) -> Self {
        key.hash(&mut h);
        Self::new(key, h.finish())
    }
}
impl<P: PartialEq, const F: Flags> PartialEq for Primary<P, F> {
    fn eq(&self, other: &Self) -> bool {
        self.p == other.p
    }
    fn ne(&self, other: &Self) -> bool {
        self.p != other.p
    }
}
impl<P: Hash, const F: Flags> Hash for Primary<P, F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, F>(state, self.hash);
    }
}
impl<P, const F: Flags> Deref for Primary<P, F> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        &self.p
    }
}
impl<P, const F: Flags> DerefMut for Primary<P, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.p
    }
}

#[derive(Clone, Copy, Debug, Eq)]
#[non_exhaustive]
pub struct Secondary<S, const F: Flags> {
    pub hash: u64,
    pub s: S,
}
impl<S, const F: Flags> Secondary<S, F> {
    pub fn new(s: S, hash: u64) -> Self {
        Self { s, hash }
    }
}
impl<S: PartialEq, const F: Flags> PartialEq for Secondary<S, F> {
    fn eq(&self, other: &Self) -> bool {
        self.s == other.s
    }
    fn ne(&self, other: &Self) -> bool {
        self.s != other.s
    }
}
impl<S: PartialOrd, const F: Flags> PartialOrd for Secondary<S, F> {
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
impl<S: Ord, const F: Flags> Ord for Secondary<S, F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.s.cmp(&other.s)
    }
}
impl<S: Hash, const F: Flags> Hash for Secondary<S, F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, F>(state, self.hash);
    }
}
impl<S, const F: Flags> Deref for Secondary<S, F> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.s
    }
}
impl<S, const F: Flags> DerefMut for Secondary<S, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s
    }
}

/// A bi-modal wrapper. On its own it uses only `ck` part for [PartialEq] and [Hash]. However, see
/// trait for borrowing as comparable by `idx` part, too.
#[derive(Clone, Eq, Copy, Debug)]
pub struct Duality<P, S, const F: Flags> {
    pub pk: Primary<P, F>,
    pub sk: Secondary<S, F>,
}
impl<P, S, const F: Flags> Duality<P, S, F> {
    pub fn new(pk: Primary<P, F>, sk: Secondary<S, F>) -> Self {
        Self { pk, sk }
    }
}

impl<P, S, const F: Flags> Hash for Duality<P, S, F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, F>(state, self.sk.hash);
    }
}
impl<P: PartialEq, S, const F: Flags> PartialEq for Duality<P, S, F> {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
    fn ne(&self, other: &Self) -> bool {
        self.pk != other.pk
    }
}

impl<P, S, const F: Flags> Borrow<Primary<P, F>> for Duality<P, S, F> {
    fn borrow(&self) -> &Primary<P, F> {
        &self.pk
    }
}
impl<P, S, const F: Flags> Borrow<Secondary<S, F>> for Duality<P, S, F> {
    fn borrow(&self) -> &Secondary<S, F> {
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

impl<'a, P, S, const F: Flags> Borrow<PrimaryWrap<P>> for Duality<P, S, F> {
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

impl<'a, P, S, const F: Flags> Borrow<SecondaryWrap<P>> for Duality<P, S, F> {
    fn borrow(&self) -> &SecondaryWrap<P> {
        unsafe { mem::transmute(&self.sk.s) }
    }
}
