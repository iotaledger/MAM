use cty::*;

use alloc::Vec;
use alloc::boxed::Box;

use iota_trytes::*;
use iota_mam::*;
use iota_curl_cpu::*;

use util::c_str_to_static_slice;

#[no_mangle]
pub fn mam_create(
    c_seed: *const c_char,
    c_message: *const c_char,
    start: usize,
    count: usize,
    index: usize,
    next_start: usize,
    next_count: usize,
    security: u8,
) -> *const u8 {
    let seed_str = unsafe { c_str_to_static_slice(c_seed) };
    let seed: Vec<Trit> = seed_str.chars().flat_map(char_to_trits).cloned().collect();

    let msg_str = unsafe { c_str_to_static_slice(c_message) };
    let msg: Vec<Trit> = msg_str.chars().flat_map(char_to_trits).cloned().collect();

    let (masked_payload, root) = create::<CpuCurl<Trit>, CpuHam>(
        &seed,
        &msg,
        start,
        count,
        index,
        next_start,
        next_count,
        security,
    );

    let payload_str = {
        let mut out_str = trits_to_string(&masked_payload).unwrap();
        out_str.push('\n');
        out_str.push_str(&trits_to_string(&root).unwrap().as_str());
        out_str.push('\0');
        Box::new(out_str)
    };

    &payload_str.as_bytes()[0] as *const u8
}

#[no_mangle]
pub fn mam_parse(c_payload: *const c_char, c_root: *const c_char, index: usize) -> *const u8 {
    let payload_str = unsafe { c_str_to_static_slice(c_payload) };
    let payload: Vec<Trit> = payload_str
        .chars()
        .flat_map(char_to_trits)
        .cloned()
        .collect();

    let root_str = unsafe { c_str_to_static_slice(c_root) };
    let root: Vec<Trit> = root_str.chars().flat_map(char_to_trits).cloned().collect();

    let result = parse::<CpuCurl<Trit>>(&payload, &root, index);
    let (message, next_root) = result.ok().unwrap();

    let mut out_str = trits_to_string(message.as_slice()).unwrap();
    out_str.push('\n');
    out_str.push_str(trits_to_string(next_root.as_slice()).unwrap().as_str());
    out_str.push('\0');

    let out_box = Box::new(out_str);
    &out_box.as_bytes()[0] as *const u8
}
