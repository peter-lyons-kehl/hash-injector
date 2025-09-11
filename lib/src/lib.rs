#![doc = include_str!("../../README.md")]
#![no_std]
#![feature(hasher_prefixfree_extras)]
#![cfg_attr(feature = "adt-const-params", feature(adt_const_params))]

pub mod hash;
pub mod keys;
