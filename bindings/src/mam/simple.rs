use cty::*;

use core::mem;
use core::ptr;
use alloc::Vec;

use iota_trytes::*;
use iota_mam::*;
use iota_curl_cpu::*;
use iota_curl::*;

use util::c_str_to_static_slice;

#[no_mangle]
pub fn mam_key(c_key: *const c_char, c_root: *const c_char, index: usize) -> *const u8 {
    let key_str = unsafe { c_str_to_static_slice(c_key) };
    let root_str = unsafe { c_str_to_static_slice(c_root) };
    let key: Vec<Trit> = key_str.chars().flat_map(char_to_trits).cloned().collect();
    let root: Vec<Trit> = root_str.chars().flat_map(char_to_trits).cloned().collect();
    let mut c1 = CpuCurl::<Trit>::default();
    message_key(&key, &root, index, &mut c1);
    let out_str = trits_to_string(&c1.state()).unwrap();
    let pointer = out_str.as_ptr();
    mem::forget(out_str);

    pointer
}

#[no_mangle]
pub fn mam_id(c_key: *const c_char, c_root: *const c_char, index: usize) -> *const u8 {
    let key_str = unsafe { c_str_to_static_slice(c_key) };
    let root_str = unsafe { c_str_to_static_slice(c_root) };
    let key: Vec<Trit> = key_str.chars().flat_map(char_to_trits).cloned().collect();
    let root: Vec<Trit> = root_str.chars().flat_map(char_to_trits).cloned().collect();
    let mut c1 = CpuCurl::<Trit>::default();
    message_key(&key, &root, index, &mut c1);
    let mut out: Vec<Trit> = c1.rate().clone().to_vec();
    c1.reset();
    message_id(&mut out, &mut c1);
    let out_str = trits_to_string(&out[..HASH_LENGTH]).unwrap();
    let pointer = out_str.as_ptr();
    mem::forget(out_str);

    pointer
}

#[no_mangle]
pub fn mam_create(
    c_seed: *const c_char,
    c_message: *const c_char,
    c_key: *const c_char,
    c_root: *const c_char,
    c_siblings: *const c_char,
    c_next_root: *const c_char,
    start: isize,
    index: usize,
    security: u8,
) -> *const u8 {
    let seed: Vec<Trit> = {
        let seed_str = unsafe { c_str_to_static_slice(c_seed) };
        seed_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let msg: Vec<Trit> = {
        let msg_str = unsafe { c_str_to_static_slice(c_message) };
        msg_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let key: Vec<Trit> = {
        let key_str = unsafe { c_str_to_static_slice(c_key) };
        key_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let root: Vec<Trit> = {
        let root_str = unsafe { c_str_to_static_slice(c_root) };
        root_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let siblings: Vec<Trit> = {
        let trit_str = unsafe { c_str_to_static_slice(c_siblings) };
        trit_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let next_root: Vec<Trit> = {
        let trit_str = unsafe { c_str_to_static_slice(c_next_root) };
        trit_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let mut c1 = CpuCurl::<Trit>::default();
    let mut c2 = CpuCurl::<Trit>::default();
    let mut b1 = CpuCurl::<BCTrit>::default();

    let masked_payload = create::<CpuCurl<Trit>, CpuCurl<BCTrit>, CpuHam>(
        &seed,
        &msg,
        &key,
        &root,
        &siblings,
        &next_root,
        start,
        index,
        security,
        &mut c1,
        &mut c2,
        &mut b1,
    );

    let out_str = trits_to_string(&masked_payload).unwrap();
    let pointer = out_str.as_ptr();
    mem::forget(out_str);

    pointer
}

#[no_mangle]
pub fn mam_parse(
    c_payload: *const c_char,
    c_key: *const c_char,
    c_root: *const c_char,
    index: usize,
) -> *const u8 {

    let payload: Vec<Trit> = {
        let trits_str = unsafe { c_str_to_static_slice(c_payload) };
        trits_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let root: Vec<Trit> = {
        let root_str = unsafe { c_str_to_static_slice(c_root) };
        root_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let side_key: Vec<Trit> = {
        let key_str = unsafe { c_str_to_static_slice(c_key) };
        key_str.chars().flat_map(char_to_trits).cloned().collect()
    };

    let mut c1 = CpuCurl::<Trit>::default();
    //let mut c2 = CpuCurl::<Trit>::default();

    match parse(&payload, &side_key, &root, index, &mut c1) {
        Ok(result) => {
            let mut out_str = trits_to_string(&result.message).unwrap();
            out_str.push('\n');
            out_str.push_str(&trits_to_string(&result.next).unwrap().as_str());
            out_str.push('\0');
            let pointer = out_str.as_ptr();
            mem::forget(out_str);

            pointer
        }
        _ => ptr::null(),
    }
}
