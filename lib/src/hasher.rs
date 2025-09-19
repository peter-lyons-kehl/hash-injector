use core::hash::{BuildHasher, Hasher};

use crate::flags::{self, Flow, ProtocolFlags, SignalVia};
#[cfg(feature = "mx")]
use crate::signal;

#[cfg(feature = "hpe")]
use crate::signal::LEN_SIGNAL_HASH;
#[cfg(all(feature = "hpe", feature = "chk-flow"))]
use crate::signal::{LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST, LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST};
use crate::state::SignalState;
#[cfg(feature = "mx")]
use core::ptr;

pub struct SignalledInjectionHasher<H: Hasher, const PF: ProtocolFlags> {
    hasher: H,
    state: SignalState,
}
struct PossiblySubmitResult {
    must_write_data_afterwards: bool,
    #[cfg(debug_assertions)]
    consumed: bool,
}
impl PossiblySubmitResult {
    const fn new(must_write_data_afterwards: bool) -> Self {
        Self {
            must_write_data_afterwards,
            #[cfg(debug_assertions)]
            consumed: false,
        }
    }
    /// Whether the client needs to call hasher.write_XXX(i) afterwards. The caller does NOT need to
    /// do anything else. In particular, the caller
    /// - does NOT need to perform any checks (if enabled with cargo features) - those have already
    ///   been done.
    /// - MUST NOT set/modify the state - because in some cases the new state varies. The state has
    ///   already been set/modified by [SignalledInjectionHasher::possibly_submit].
    #[must_use]
    #[inline(always)]
    fn must_write_data_afterwards(mut self) -> bool {
        #[cfg(debug_assertions)]
        {
            self.consumed = true;
        }
        self.must_write_data_afterwards
    }
}
#[cfg(debug_assertions)]
impl Drop for PossiblySubmitResult {
    fn drop(&mut self) {
        debug_assert!(self.consumed);
    }
}
impl<H: Hasher, const PF: ProtocolFlags> SignalledInjectionHasher<H, PF> {
    #[inline]
    const fn new(hasher: H) -> Self {
        Self {
            hasher,
            state: SignalState::new_nothing_written(),
        }
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn written_ordinary_hash(&mut self) {
        self.state.set_written_ordinary_hash();
    }
    /// Submit, or possibly submit, hash `i`, as appropriate per the state and the flow.
    ///
    /// The caller MUSt use the result and depending on its
    /// [PossiblySubmitResult::must_write_data_afterwards] it must write the given data using the
    /// ordinary `Hasher::write_XXX`. That is somewhat enforced with `#![forbid(unused_must_use)]`
    /// at `src/lib.rs``.
    ///
    /// We do not use a function pointer to call back to write the given data, because the caller's
    /// actual data may also be a `i64, u128, i128`.
    #[must_use]
    fn possibly_submit(&mut self, i: u64) -> PossiblySubmitResult {
        match flags::flow(PF) {
            Flow::SignalFirst => {
                if self.state.is_signalled_proposal_coming(PF) {
                    self.state = SignalState::new_hash_received(i);
                    PossiblySubmitResult::new(false)
                } else {
                    self.state.assert_nothing_written_or_ordinary_hash();
                    self.written_ordinary_hash();
                    PossiblySubmitResult::new(true)
                }
            }
            Flow::SubmitFirst => {
                self.state
                    .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);

                if self.state.is_nothing_written() {
                    self.state = SignalState::new_hash_possibly_submitted(i, PF);
                } else {
                    // In case the hash was "possibly_submitted", submitting any more data (u64 or
                    // otherwise) invalidates it.
                    self.state.set_written_ordinary_hash();
                }
                // Even if we are indeed signalling, after this function returns the client would
                // call  write_XXX(...). The value then written to the underlying Hasher will NOT be
                // used, because finish(&self) then returns the injected hash - instead of calling
                // the underlying Hasher's finish(). So, the compiler may optimize the following
                // call away (thanks to Hasher objects being passed by generic reference - instead
                // of a &dyn trait reference):
                PossiblySubmitResult::new(true)
            }
        }
    }
}
impl<H: Hasher, const PF: ProtocolFlags> Hasher for SignalledInjectionHasher<H, PF> {
    #[inline]
    fn finish(&self) -> u64 {
        if self.state.is_hash_received() {
            self.state.hash
        } else {
            self.state
                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
            self.hasher.finish()
        }
    }
    /// This does NOT signal, even if you handed it the same bytes as [`inject_via_len`] passes
    /// through `write_length_prefix` and `write_u64` when signalling.
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        match flags::signal_via(PF) {
            SignalVia::Len | SignalVia::Str => {
                self.state
                    .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                self.hasher.write(bytes);
                self.written_ordinary_hash();
            }
            SignalVia::U8s => {
                match flags::flow(PF) {
                    Flow::SubmitFirst => {
                        #[cfg(feature = "mx")]
                        if ptr::eq(bytes.as_ptr(), signal::ptr_signal_hash()) {
                            if self.state.is_hash_possibly_submitted(PF) {
                                self.state.set_hash_received();
                            } else {
                                #[cfg(feature = "chk")]
                                assert!(
                                    false,
                                    "Expected state HashPossiblySubmitted, but it was {:?}.",
                                    self.state
                                );

                                self.hasher.write(bytes);
                                self.written_ordinary_hash();
                            }
                        } else {
                            #[cfg(feature = "chk-flow")]
                            {
                                if ptr::eq(
                                    bytes.as_ptr(),
                                    signal::ptr_signal_check_flow_is_submit_first(),
                                ) {
                                    return; // just being checked (no data to write)
                                }
                                assert!(!ptr::eq(
                                    bytes.as_ptr(),
                                    signal::ptr_signal_check_flow_is_signal_first()
                                ));
                            }

                            self.state
                                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                            self.hasher.write(bytes);
                            self.written_ordinary_hash();
                        }
                        #[cfg(not(feature = "mx"))]
                        {
                            self.state
                                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                            self.hasher.write(bytes);
                            self.written_ordinary_hash();
                        }
                    }
                    Flow::SignalFirst => {
                        #[cfg(feature = "mx")]
                        if ptr::eq(bytes.as_ptr(), signal::ptr_signal_hash()) {
                            self.state.assert_nothing_written();
                            self.state.set_signalled_proposal_coming(PF);
                        } else {
                            #[cfg(feature = "chk-flow")]
                            {
                                if ptr::eq(
                                    bytes.as_ptr(),
                                    signal::ptr_signal_check_flow_is_signal_first(),
                                ) {
                                    return; // just being checked (no data to write)
                                }
                                assert!(!ptr::eq(
                                    bytes.as_ptr(),
                                    signal::ptr_signal_check_flow_is_submit_first()
                                ));
                            }

                            self.state.assert_nothing_written_or_ordinary_hash();
                            self.hasher.write(bytes);
                            self.written_ordinary_hash();
                        }
                        #[cfg(not(feature = "mx"))]
                        {
                            self.state
                                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                            self.hasher.write(bytes);
                            self.written_ordinary_hash();
                        }
                    }
                }
            }
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.state
            .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
        self.hasher.write_u8(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.state
            .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
        self.hasher.write_u16(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.state
            .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
        self.hasher.write_u32(i);
        self.written_ordinary_hash();
    }
    fn write_u64(&mut self, i: u64) {
        if flags::is_hash_via_u64(PF) {
            if self.possibly_submit(i).must_write_data_afterwards() {
                self.hasher.write_u64(i);
            }
        } else {
            self.state
                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
            self.hasher.write_u64(i);
            self.written_ordinary_hash();
        }
    }
    #[inline]
    fn write_u128(&mut self, i: u128) {
        if flags::is_hash_via_u128(PF) {
            if self.possibly_submit(i as u64).must_write_data_afterwards() {
                self.hasher.write_u128(i);
            }
        } else {
            self.state
                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
            self.hasher.write_u128(i);
            self.written_ordinary_hash();
        }
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.state
            .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
        self.hasher.write_usize(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.state
            .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
        self.hasher.write_i8(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.state
            .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
        self.hasher.write_i16(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.state
            .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
        self.hasher.write_i32(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i64(&mut self, i: i64) {
        if flags::is_hash_via_i64(PF) {
            if self.possibly_submit(i as u64).must_write_data_afterwards() {
                self.hasher.write_i64(i);
            }
        } else {
            self.state
                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
            self.hasher.write_i64(i);
            self.written_ordinary_hash();
        }
    }
    #[inline]
    fn write_i128(&mut self, i: i128) {
        if flags::is_hash_via_i128(PF) {
            if self.possibly_submit(i as u64).must_write_data_afterwards() {
                self.hasher.write_i128(i);
            }
        } else {
            self.state
                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
            self.hasher.write_i128(i);
            self.written_ordinary_hash();
        }
    }
    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.state
            .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
        self.hasher.write_isize(i);
        self.written_ordinary_hash();
    }
    #[cfg(feature = "hpe")]
    fn write_length_prefix(&mut self, len: usize) {
        // Logical branches/their conditions can get optimized away (const)
        match flags::signal_via(PF) {
            SignalVia::U8s | SignalVia::Str => {
                self.state
                    .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                self.hasher.write_length_prefix(len);
                self.written_ordinary_hash();
            }
            SignalVia::Len => {
                match flags::flow(PF) {
                    Flow::SubmitFirst => {
                        if len == LEN_SIGNAL_HASH {
                            if self.state.is_hash_possibly_submitted(PF) {
                                self.state.set_hash_received();
                            } else {
                                #[cfg(feature = "chk")]
                                assert!(
                                    false,
                                    "Expected state HashPossiblySubmitted, but it was {:?}.",
                                    self.state
                                );

                                self.hasher.write_length_prefix(len);
                                self.written_ordinary_hash();
                            }
                        } else {
                            #[cfg(feature = "chk-flow")]
                            {
                                if len == LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST {
                                    return; // just being checked (no data to write)
                                }
                                assert_ne!(len, LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST);
                            }

                            self.state
                                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                            self.hasher.write_length_prefix(len);
                            self.written_ordinary_hash();
                        }
                    }
                    Flow::SignalFirst => {
                        if len == LEN_SIGNAL_HASH {
                            self.state.assert_nothing_written();
                            self.state.set_signalled_proposal_coming(PF);
                        } else {
                            #[cfg(feature = "chk-flow")]
                            {
                                if len == LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST {
                                    return; // just being checked (no data to write)
                                }
                                assert_ne!(len, LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST);
                            }

                            self.state.assert_nothing_written_or_ordinary_hash();
                            self.hasher.write_length_prefix(len);
                            self.written_ordinary_hash();
                        }
                    }
                }
            }
        }
    }

    #[cfg(feature = "hpe")]
    #[inline]
    fn write_str(&mut self, s: &str) {
        match flags::signal_via(PF) {
            SignalVia::U8s | SignalVia::Len => {
                self.state
                    .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                self.hasher.write_str(s);
                self.written_ordinary_hash();
            }
            SignalVia::Str => {
                match flags::flow(PF) {
                    Flow::SubmitFirst => {
                        #[cfg(feature = "mx")]
                        if ptr::eq(s.as_ptr(), signal::ptr_signal_hash()) {
                            if self.state.is_hash_possibly_submitted(PF) {
                                self.state.set_hash_received();
                            } else {
                                #[cfg(feature = "chk")]
                                assert!(
                                    false,
                                    "Expected state HashPossiblySubmitted, but it was {:?}.",
                                    self.state
                                );

                                self.hasher.write_str(s);
                                self.written_ordinary_hash();
                            }
                        } else {
                            #[cfg(feature = "chk-flow")]
                            {
                                if ptr::eq(
                                    s.as_ptr(),
                                    signal::ptr_signal_check_flow_is_submit_first(),
                                ) {
                                    return; // just being checked (no data to write)
                                }
                                assert!(!ptr::eq(
                                    s.as_ptr(),
                                    signal::ptr_signal_check_flow_is_signal_first()
                                ));
                            }

                            self.state
                                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                            self.hasher.write_str(s);
                            self.written_ordinary_hash();
                        }
                        #[cfg(not(feature = "mx"))]
                        {
                            self.state
                                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                            self.hasher.write_str(s);
                            self.written_ordinary_hash();
                        }
                    }
                    Flow::SignalFirst => {
                        #[cfg(feature = "mx")]
                        if ptr::eq(s.as_ptr(), signal::ptr_signal_hash()) {
                            self.state.assert_nothing_written();
                            self.state.set_signalled_proposal_coming(PF);
                        } else {
                            #[cfg(feature = "chk-flow")]
                            {
                                if ptr::eq(
                                    s.as_ptr(),
                                    signal::ptr_signal_check_flow_is_signal_first(),
                                ) {
                                    return; // just being checked (no data to write)
                                }
                                assert!(!ptr::eq(
                                    s.as_ptr(),
                                    signal::ptr_signal_check_flow_is_submit_first()
                                ));
                            }

                            self.state.assert_nothing_written_or_ordinary_hash();
                            self.hasher.write_str(s);
                            self.written_ordinary_hash();
                        }
                        #[cfg(not(feature = "mx"))]
                        {
                            self.state
                                .assert_nothing_written_or_ordinary_hash_or_possibly_submitted(PF);
                            self.hasher.write_str(s);
                            self.written_ordinary_hash();
                        }
                    }
                }
            }
        }
    }
}

pub struct SignalledInjectionBuildHasher<
    H: Hasher,
    B: BuildHasher<Hasher = H>,
    const PF: ProtocolFlags,
> {
    build: B,
}
impl<H: Hasher, B: BuildHasher<Hasher = H>, const PF: ProtocolFlags>
    SignalledInjectionBuildHasher<H, B, PF>
{
    pub fn new(build: B) -> Self {
        Self { build }
    }
}
impl<H: Hasher, B: BuildHasher<Hasher = H>, const PF: ProtocolFlags> BuildHasher
    for SignalledInjectionBuildHasher<H, B, PF>
{
    type Hasher = SignalledInjectionHasher<H, PF>;

    // Required method
    fn build_hasher(&self) -> Self::Hasher {
        SignalledInjectionHasher::new(self.build.build_hasher())
    }
}
