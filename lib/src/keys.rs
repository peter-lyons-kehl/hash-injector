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
/// That can shortcut unnecessary comparison.
///
/// Use `true` if `P` is larger/more complex than `u64`.
pub type KeyFlags = KeyFlagsImpl;

// If we ever have more than one flag, then change this into e.g. u8.
#[cfg(not(feature = "adt-const-params"))]
type KeyFlagsImpl = bool;

#[cfg(feature = "adt-const-params")]
/// Type for const generic parameter `KF`.
#[derive(ConstParamTy, Clone, Copy, PartialEq, Eq)]
pub struct KeyFlagsImpl {
    eq_involves_hash: bool,
}
pub const fn new_flags_eq_includes_hash() -> KeyFlags {
    #[cfg(not(feature = "adt-const-params"))]
    {
        true
    }
    #[cfg(feature = "adt-const-params")]
    KeyFlags {
        eq_involves_hash: true,
    }
}
pub const fn new_flags_eq_excludes_hash() -> KeyFlags {
    #[cfg(not(feature = "adt-const-params"))]
    {
        false
    }
    #[cfg(feature = "adt-const-params")]
    KeyFlags {
        eq_involves_hash: false,
    }
}

#[derive(Eq, Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Primary<P, const IF: InjectionFlags, const KF: KeyFlags> {
    /// `hash` is listed before `p`, so that it can short-circuit the derived [PartialEq]
    /// implementation by comparing `hash` first.
    ///
    /// TODO Consider a flag in Flags to control whether PartialEq compares hash or not.
    pub hash: u64,
    pub p: P,
}
impl<P: Hash, const IF: InjectionFlags, const KF: KeyFlags> Primary<P, IF, KF> {
    pub fn new(p: P, hash: u64) -> Self {
        Self { p, hash }
    }
    /// We consume the hasher, so that it's not reused accidentally.
    pub fn new_from_hasher<H: Hasher>(key: P, mut h: H) -> Self {
        key.hash(&mut h);
        Self::new(key, h.finish())
    }
}
impl<P: PartialEq, const IF: InjectionFlags, const KF: KeyFlags> PartialEq for Primary<P, IF, KF> {
    fn eq(&self, other: &Self) -> bool {
        self.p == other.p
    }
    fn ne(&self, other: &Self) -> bool {
        self.p != other.p
    }
}
impl<P: Hash, const IF: InjectionFlags, const KF: KeyFlags> Hash for Primary<P, IF, KF> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, IF>(state, self.hash);
    }
}
impl<P, const IF: InjectionFlags, const KF: KeyFlags> Deref for Primary<P, IF, KF> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        &self.p
    }
}
impl<P, const IF: InjectionFlags, const KF: KeyFlags> DerefMut for Primary<P, IF, KF> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.p
    }
}

#[derive(Clone, Copy, Debug, Eq)]
#[non_exhaustive]
pub struct Secondary<S, const IF: InjectionFlags, const KF: KeyFlags> {
    pub hash: u64,
    pub s: S,
}
impl<S, const IF: InjectionFlags, const KF: KeyFlags> Secondary<S, IF, KF> {
    pub fn new(s: S, hash: u64) -> Self {
        Self { s, hash }
    }
}
impl<S: PartialEq, const IF: InjectionFlags, const KF: KeyFlags> PartialEq
    for Secondary<S, IF, KF>
{
    fn eq(&self, other: &Self) -> bool {
        self.s == other.s
    }
    fn ne(&self, other: &Self) -> bool {
        self.s != other.s
    }
}
impl<S: PartialOrd, const IF: InjectionFlags, const KF: KeyFlags> PartialOrd
    for Secondary<S, IF, KF>
{
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
impl<S: Ord, const IF: InjectionFlags, const KF: KeyFlags> Ord for Secondary<S, IF, KF> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.s.cmp(&other.s)
    }
}
impl<S: Hash, const IF: InjectionFlags, const KF: KeyFlags> Hash for Secondary<S, IF, KF> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, IF>(state, self.hash);
    }
}
impl<S, const IF: InjectionFlags, const KF: KeyFlags> Deref for Secondary<S, IF, KF> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.s
    }
}
impl<S, const IF: InjectionFlags, const KF: KeyFlags> DerefMut for Secondary<S, IF, KF> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s
    }
}

/// A bi-modal wrapper. On its own it uses only `ck` part for [PartialEq] and [Hash]. However, see
/// trait for borrowing as comparable by `idx` part, too.
#[derive(Clone, Eq, Copy, Debug)]
pub struct Duality<P, S, const IF: InjectionFlags, const PKF: KeyFlags, const SKF: KeyFlags> {
    pub pk: Primary<P, IF, PKF>,
    pub sk: Secondary<S, IF, SKF>,
}
impl<P, S, const IF: InjectionFlags, const PKF: KeyFlags, const SKF: KeyFlags>
    Duality<P, S, IF, PKF, SKF>
{
    pub fn new(pk: Primary<P, IF, PKF>, sk: Secondary<S, IF, SKF>) -> Self {
        Self { pk, sk }
    }
}

impl<P, S, const IF: InjectionFlags, const PKF: KeyFlags, const SKF: KeyFlags> Hash
    for Duality<P, S, IF, PKF, SKF>
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::hash::signal_inject_hash::<H, IF>(state, self.sk.hash);
    }
}
impl<P: PartialEq, S, const IF: InjectionFlags, const PKF: KeyFlags, const SKF: KeyFlags> PartialEq
    for Duality<P, S, IF, PKF, SKF>
{
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
    fn ne(&self, other: &Self) -> bool {
        self.pk != other.pk
    }
}

impl<P, S, const IF: InjectionFlags, const PKF: KeyFlags, const SKF: KeyFlags>
    Borrow<Primary<P, IF, PKF>> for Duality<P, S, IF, PKF, SKF>
{
    fn borrow(&self) -> &Primary<P, IF, PKF> {
        &self.pk
    }
}
impl<P, S, const IF: InjectionFlags, const PKF: KeyFlags, const SKF: KeyFlags>
    Borrow<Secondary<S, IF, SKF>> for Duality<P, S, IF, PKF, SKF>
{
    fn borrow(&self) -> &Secondary<S, IF, SKF> {
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

impl<'a, P, S, const IF: InjectionFlags, const PKF: KeyFlags, const SKF: KeyFlags>
    Borrow<PrimaryWrap<P>> for Duality<P, S, IF, PKF, SKF>
{
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

impl<'a, P, S, const IF: InjectionFlags, const PKF: KeyFlags, const SKF: KeyFlags>
    Borrow<SecondaryWrap<P>> for Duality<P, S, IF, PKF, SKF>
{
    fn borrow(&self) -> &SecondaryWrap<P> {
        unsafe { mem::transmute(&self.sk.s) }
    }
}
