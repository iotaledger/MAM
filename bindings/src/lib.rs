#![feature(alloc)]
#![no_std]

#[macro_use]
extern crate alloc;

extern crate cty;

extern crate iota_bindings_shared as shared;
extern crate iota_mam;
extern crate iota_merkle;
extern crate iota_trytes;
extern crate iota_curl_cpu;
extern crate iota_curl;
extern crate iota_sign;

pub mod mam;
