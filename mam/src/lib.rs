//! A tool to create and parse masked authenticated messages
//!
//! # Context
//!
//! Masked Authenticated Messaging is a tool for creating private, signed
//! message streams on the IOTA Tangle. They are located on the tangle from a
//! unique identifier, the merkle root, or public key, of the signed message.
//!
//! This merkle root, along with the index of the signing key within it used in
//! the message is used as the encryption initialization vector for
//! the encryption key.
//!
//! The merkle root should be used as the address for the message published to the tangle.
//!
//! The inner structure of the resulting payload takes the form of:
//!
//! ```
//! [
//!     Encoded Index,
//!     Encoded Message Length,
//!     encrypted[
//!         Message,
//!         Nonce,
//!         Signature,
//!         Encoded Number of Siblings,
//!         Siblings
//!     ]
//! ]
//! ```
//!
//! # Example
//!
//! ```
//! extern crate iota_trytes as trytes;
//! extern crate iota_mam as mam;
//! extern crate iota_curl_cpu as curl;
//! use trytes::*;
//! use curl::*;
//! use mam::*;
//! fn main() {
//!     let mut c1 = CpuCurl::<Trit>::default();
//!     let mut c2 = CpuCurl::<Trit>::default();
//!     let mut bc = CpuCurl::<BCTrit>::default();
//!     let security = 1;
//!     let start = 1;
//!     let index = 1;
//!     // Some seed for signatures
//!     let seed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
//!     // Some message
//!     let message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
//!     let side_key = "EFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDABCD";
//!
//!     // roots and siblings are pre-calculated with the merkle module
//!     let root = "BHJDQMCVCKWWZQEGTXUPWQLW9DBESBKMQUZEKFURUUYJMMLYLHRZLJQNSKWAMLAAREHNWECLLJERNPYFX";
//!     let next_root = "NQZOFWZFXFABNCYLQE9KUCIFBCJWVAKDVNJONDTPSWRT9YKWBFTEBVTQISHKVGWBTPIFKXAO9GQSOW9HG";
//!     let siblings = "A9KDMOZZFMHLH9FFSWPKRHKMCWA9HOYY9VYGUFPVITOZCYTIXFRRL9MJODYHSEVLTCEMAYLVBIPDDEDESVZSPSHRSJANRQSEBMWUPCJZBQG9REHVQWYUERSXCAEJHKTCUKXSALOKMGRMAJHAXHLNMJVY9TSYJMRKHS";
//!
//!     let seed_trits: Vec<Trit> = seed.chars().flat_map(char_to_trits).cloned().collect();
//!     let message_trits: Vec<Trit> = message.chars().flat_map(char_to_trits).cloned().collect();
//!     let side_key_trits: Vec<Trit> = side_key.chars().flat_map(char_to_trits).cloned().collect();
//!     let root_trits: Vec<Trit> = root.chars().flat_map(char_to_trits).cloned().collect();
//!     let next_root_trits: Vec<Trit> = next_root.chars().flat_map(char_to_trits).cloned().collect();
//!     let siblings_trits: Vec<Trit> = siblings.chars().flat_map(char_to_trits).cloned().collect();
//!
//!     // Create the payload
//!     let masked_payload = create::<CpuCurl<Trit>, CpuCurl<BCTrit>, CpuHam>(
//!         &seed_trits,
//!         &message_trits,
//!         &side_key_trits,
//!         &root_trits,
//!         &siblings_trits,
//!         &next_root_trits,
//!         start,
//!         index,
//!         security,
//!         &mut c1,
//!         &mut c2,
//!         &mut bc,
//!     );
//!
//!     // We'll test that it matches the original message
//!     match parse(&masked_payload, &side_key_trits, &root_trits, &mut c1) {
//!         Ok(result) => assert_eq!(result.message, message_trits),
//!         Err(e) => {
//!             match e {
//!                 MamError::InvalidSignature => panic!("Invalid Signature"),
//!                 MamError::InvalidHash => panic!("Invalid Hash"),
//!                 _ => panic!("some other error!"),
//!             }
//!         }
//!     }
//! }
//! ```
//!

#![no_std]
#![feature(alloc)]
#![feature(const_fn)]

#[macro_use]
extern crate alloc;

extern crate iota_trytes as trytes;
extern crate iota_tmath as tmath;
extern crate iota_curl as curl;
extern crate iota_sign as sign;
extern crate iota_merkle as merkle;

#[cfg(test)]
extern crate iota_curl_cpu as curl_cpu;

pub mod pascal;
pub mod errors;
pub mod mask;
mod mam;

pub use mam::*;
pub use errors::*;
/*
 * Address: H ( H ( CKey + Root + Index ) )
 * Tag: Any
 * Message: [ L<NextRoot + Message> + Nonce + Signature + Hashes ]
 *
 * Encryption Key: H^i ( CKey + Root + Index )
 */
