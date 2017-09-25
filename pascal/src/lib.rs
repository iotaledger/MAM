#![feature(alloc)]
#![feature(const_fn)]
#![no_std]

#[macro_use]
extern crate alloc;

extern crate iota_trytes as trytes;

mod pascal;
pub use pascal::*;
