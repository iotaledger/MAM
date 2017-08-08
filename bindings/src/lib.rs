#![feature(start)]
#![feature(alloc)]
#![feature(lang_items)]
#![feature(link_args)]
#![no_std]

#![cfg(not(test))]
#![feature(core_intrinsics)]
#![crate_type = "staticlib"]

extern crate alloc;
extern crate cty;

extern crate iota_mam;
extern crate iota_merkle;
extern crate iota_trytes;
extern crate iota_curl_cpu;
extern crate iota_curl;
extern crate iota_sign;

#[cfg(not(test))]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

#[cfg(not(test))]
#[lang = "panic_fmt"]
fn panic_fmt() -> ! {
    use core::intrinsics;
    unsafe {
        intrinsics::abort();
    }
}

mod util;
pub mod mam;
pub mod merkle;
