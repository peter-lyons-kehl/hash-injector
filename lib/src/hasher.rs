use core::hash::{BuildHasher, Hasher};

use crate::flags::{self, Flow, ProtocolFlags, SignalVia};
#[cfg(feature = "mx")]
use crate::signal;
use crate::signal::LEN_SIGNAL_HASH;
#[cfg(feature = "chk-flow")]
use crate::signal::{LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST, LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST};
use crate::state::SignalState;
#[cfg(feature = "mx")]
use core::ptr;

pub struct SignalledInjectionHasher<H: Hasher, const PF: ProtocolFlags> {
    hasher: H,
    state: SignalState,
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
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written(&self) {
        #[cfg(feature = "chk")]
        assert!(self.state.is_nothing_written());
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    #[inline(always)]
    fn assert_nothing_written_or_ordinary_hash(&self) {
        #[cfg(feature = "chk")]
        assert!(
            self.state.is_nothing_written_or_ordinary_hash(),
            "Expecting the state to be NothingWritten or WrittenOrdinaryHash, but the state was: {:?}",
            self.state
        );
    }
    // @TODO if this doesn't optimize away in release, replace with a macro.
    /// Assert that
    /// - no hash has been signalled (if we do signal first - before submitting), and
    /// - no hash has been received (regardless of whether we signal first, or submit first).
    #[inline(always)]
    fn assert_nothing_written_or_ordinary_hash_or_possibly_submitted(&self) {
        #[cfg(feature = "chk")]
        {
            assert!(
                self.state
                    .is_nothing_written_or_ordinary_hash_or_possibly_submitted(PF),
                "Expecting the state to be NothingWritten or WrittenOrdinaryHash, or HashPossiblySubmitted (if applicable), but the state was: {:?}",
                self.state
            );
        }
    }
}
impl<H: Hasher, const PF: ProtocolFlags> Hasher for SignalledInjectionHasher<H, PF> {
    #[inline]
    fn finish(&self) -> u64 {
        if self.state.is_hash_received() {
            self.state.hash
        } else {
            self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
            self.hasher.finish()
        }
    }
    /// This does NOT signal, even if you handed it the same bytes as [`inject_via_len`] passes
    /// through `write_length_prefix` and `write_u64` when signalling.
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write(bytes);
        self.written_ordinary_hash();
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_u8(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_u16(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_u32(i);
        self.written_ordinary_hash();
    }
    fn write_u64(&mut self, i: u64) {
        // the outer if check can get optimized away (const)
        if flags::is_signal_via_str(PF) {
            // @TODO
        }
        if flags::is_signal_first(PF) {
            if self.state.is_signalled_proposal_coming(PF) {
                self.state = SignalState::new_hash_received(i);
            } else {
                self.assert_nothing_written_or_ordinary_hash();
                self.hasher.write_u64(i);
                self.written_ordinary_hash();
            }
        } else {
            self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
            // If we are indeed signalling, then after the following write_u64(...) the value
            // written to the underlying Hasher will NOT be used, because finish(&self) then returns
            // the injected hash - instead of calling the underlying Hasher's finish(). So, the
            // compiler MAY optimize the following call away (thanks to Hasher objects being passed
            // by generic reference - instead of a &dyn trait reference):
            self.hasher.write_u64(i);
            if self.state.is_nothing_written() {
                self.state = SignalState::new_hash_possibly_submitted(i, PF);
            } else {
                // In case the hash was "possibly_submitted", submitting any more data (u64 or
                // otherwise) invalidates it.
                self.state.set_written_ordinary_hash();
            }
        }
    }
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_u128(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_usize(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i8(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i16(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i32(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i64(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_i128(i);
        self.written_ordinary_hash();
    }
    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
        self.hasher.write_isize(i);
        self.written_ordinary_hash();
    }
    fn write_length_prefix(&mut self, len: usize) {
        // Logical branches/their conditions can get optimized away (const)
        match flags::signal_via(PF) {
            SignalVia::Str => {
                self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
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

                            self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
                            self.hasher.write_length_prefix(len);
                            self.written_ordinary_hash();
                        }
                    }
                    Flow::SignalFirst => {
                        if len == LEN_SIGNAL_HASH {
                            self.assert_nothing_written();
                            self.state.set_signalled_proposal_coming(PF);
                        } else {
                            #[cfg(feature = "chk-flow")]
                            {
                                if len == LEN_SIGNAL_CHECK_FLOW_IS_SIGNAL_FIRST {
                                    return; // just being checked (no data to write)
                                }
                                assert_ne!(len, LEN_SIGNAL_CHECK_FLOW_IS_SUBMIT_FIRST);
                            }

                            self.assert_nothing_written_or_ordinary_hash();
                            self.hasher.write_length_prefix(len);
                            self.written_ordinary_hash();
                        }
                    }
                }
            }
        }
    }

    #[inline]
    fn write_str(&mut self, s: &str) {
        match flags::signal_via(PF) {
            SignalVia::Len => {
                self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
                self.hasher.write_str(s);
                self.written_ordinary_hash();
            }
            SignalVia::Str => {
                #[cfg(feature = "mx")]
                match flags::flow(PF) {
                    Flow::SubmitFirst => {
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

                            self.assert_nothing_written_or_ordinary_hash_or_possibly_submitted();
                            self.hasher.write_str(s);
                            self.written_ordinary_hash();
                        }
                    }
                    Flow::SignalFirst => {
                        if ptr::eq(s.as_ptr(), signal::ptr_signal_hash()) {
                            self.assert_nothing_written();
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

                            self.assert_nothing_written_or_ordinary_hash();
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
