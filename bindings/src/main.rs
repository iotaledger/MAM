#![feature(start)]
#![feature(alloc)]
#![feature(lang_items)]
#![feature(link_args)]
#![no_std]

#![cfg(not(test))]
#![feature(core_intrinsics)]

extern crate alloc;
extern crate cty;

extern crate iota_mam;
extern crate iota_merkle;
extern crate iota_trytes;
extern crate iota_curl_cpu;
extern crate iota_curl;
extern crate iota_sign;

pub mod util;
pub mod mam;

#[cfg(any(target_os = "emscripten", target_arch = "wasm32"))]
#[link_args = "-s EXPORTED_FUNCTIONS=['_mam_key','_mam_id','_mam_create','_mam_parse']"]
extern "C" {}


#[cfg(any(target_os = "emscripten", target_arch = "wasm32"))]
extern crate std;

// These functions are used by the compiler, but not
// for a bare-bones hello world. These are normally
// provided by libstd.
/*
#[cfg(not(any(test, target_os = "emscripten", target_arch = "wasm32")))]
#[lang = "eh_personality"]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
*/

// This function may be needed based on the compilation target.
#[cfg(not(any(test, target_os = "emscripten", target_arch = "wasm32")))]
#[lang = "eh_unwind_resume"]
#[no_mangle]
pub extern "C" fn rust_eh_unwind_resume() {}

/*
#[cfg(not(any(test, target_os = "emscripten", target_arch = "wasm32")))]
#[lang = "panic_fmt"]
#[no_mangle]
pub extern "C" fn rust_begin_panic(
    _msg: core::fmt::Arguments,
    _file: &'static str,
    _line: u32,
) -> ! {
    unsafe { core::intrinsics::abort() }
}
*/



#[start]
pub fn main(_: isize, _: *const *const u8) -> isize {
    0
}
