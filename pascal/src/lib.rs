#![feature(alloc)]
#![feature(const_fn)]
//#![no_std]
extern crate core;
#[macro_use]
extern crate alloc;

extern crate iota_trytes as trytes;

mod pascal;
pub use pascal::*;
