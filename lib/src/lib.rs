#![doc = include_str!("../../README.md")]
#![no_std]
#![feature(hasher_prefixfree_extras)]
#![cfg_attr(feature = "adt-const-params", feature(adt_const_params))]

//#![feature(associated_type_defaults)]
//#![feature(generic_const_exprs)]
pub mod hash;
pub mod keys;
