#![feature(alloc)]
#![feature(const_fn)]
#![no_std]

#[macro_use]
extern crate alloc;

extern crate iota_trytes as trytes;
extern crate iota_tmath as tmath;
extern crate iota_curl as curl;
extern crate iota_sign as sign;
extern crate iota_merkle as merkle;

#[cfg(feature = "default")]
extern crate iota_curl_cpu as curl_cpu;

pub mod pascal;
pub mod errors;
pub mod mask;
mod mam;

pub use mam::*;
/*
 * Address: H ( H ( CKey + Root + Index ) )
 * Tag: Any
 * Message: [ L<NextRoot + Message> + Nonce + Signature + Hashes ]
 *
 * Encryption Key: H^i ( CKey + Root + Index )
 */
