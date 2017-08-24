use cty::*;
use core::mem;
use alloc::*;
use alloc::string::String;
use iota_trytes::*;
use iota_merkle::*;
use iota_curl_cpu::*;
use iota_sign::iss;
use util::c_str_to_static_slice;

#[no_mangle]
pub fn merkle_key(c_seed: *const c_char, index: usize, security: u8) -> *const u8 {
    let seed_str = unsafe { c_str_to_static_slice(c_seed) };
    let seed: Vec<Trit> = seed_str.chars().flat_map(char_to_trits).cloned().collect();

    let mut curl = CpuCurl::<Trit>::default();
    let mut key_space = [0 as Trit; iss::KEY_LENGTH];
    key(&seed, index, security, &mut key_space, &mut curl);

    let mut out_str = trits_to_string(&key_space).unwrap();
    out_str.push('\0');

    let ptr = out_str.as_ptr();
    mem::forget(out_str);

    ptr
}

#[no_mangle]
pub fn merkle_siblings(c_addrs: *const c_char, index: usize) -> *const u8 {
    let addrs_str = unsafe { c_str_to_static_slice(c_addrs) };
    let addrs: Vec<Trit> = addrs_str.split("\n").fold(Vec::new(), |mut acc, a| {
        acc.extend(a.chars().flat_map(char_to_trits).cloned());
        acc
    });

    let mut curl = CpuCurl::<Trit>::default();

    let mut sibling_hashes = vec![0 as Trit; siblings_count(addrs.len()) * HASH_LENGTH];
    siblings(&addrs, index, &mut sibling_hashes, &mut curl);

    let siblings_str = sibling_hashes.chunks(HASH_LENGTH).fold(
        String::new(),
        |mut acc, sibling| {
            acc.push_str(trits_to_string(&sibling).unwrap().as_str());
            acc.push('\n');
            acc
        },
    );

    siblings_str.trim();
    let ptr = siblings_str.as_ptr();
    mem::forget(siblings_str);

    ptr
}

#[no_mangle]
pub fn merkle_root(c_addr: *const c_char, c_siblings: *const c_char, index: usize) -> *const u8 {
    let addr_str = unsafe { c_str_to_static_slice(c_addr) };
    let addr: Vec<Trit> = addr_str.chars().flat_map(char_to_trits).cloned().collect();

    let siblings_str = unsafe { c_str_to_static_slice(c_siblings) };
    let siblings: Vec<Trit> = siblings_str
        .split("\n")
        .flat_map(|a| {
            a.chars()
                .flat_map(char_to_trits)
                .cloned()
                .collect::<Vec<Trit>>()
        })
        .collect();

    let mut curl = CpuCurl::<Trit>::default();
    let root = root(&addr, &siblings, index, &mut curl);

    let out_str = trits_to_string(root.as_slice()).unwrap() + "\0";
    let ptr = out_str.as_ptr();
    mem::forget(out_str);

    ptr
}
