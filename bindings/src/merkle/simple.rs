use cty::*;
use alloc::boxed::Box;
use alloc::Vec;
use alloc::string::String;
use iota_trytes::*;
use iota_merkle::*;
use util::c_str_to_static_slice;

#[no_mangle]
pub fn merkle_keys(c_seed: *const c_char, start: usize, count: usize, security: u8) -> *const u8 {
    let seed_str = unsafe { c_str_to_static_slice(c_seed) };
    let seed: Vec<Trit> = seed_str.trits();

    let keys = keys(&seed, start, count, security);

    let out_str = {
        let s = keys.iter().fold(String::new(), |mut acc, key| {
            acc.push_str(trits_to_string(key.trits().as_slice()).unwrap().as_str());
            acc.push('\n');
            acc
        });
        s.trim();
        Box::new(s)
    };
    &out_str.as_bytes()[0] as *const u8
}

#[no_mangle]
pub fn merkle_siblings(c_addrs: *const c_char, index: usize) -> *const u8 {
    let addrs_str = unsafe { c_str_to_static_slice(c_addrs) };
    let addrs: Vec<Vec<Trit>> = addrs_str.split("\n").map(|a| a.trits()).collect();

    let siblings = siblings(&addrs, index);

    let out_str = {
        let siblings_str = siblings.iter().fold(String::new(), |mut acc, sibling| {
            acc.push_str(
                trits_to_string(sibling.trits().as_slice())
                    .unwrap()
                    .as_str(),
            );
            acc.push('\n');
            acc
        });
        siblings_str.trim();
        Box::new(siblings_str)
    };
    &out_str.as_bytes()[0] as *const u8
}

#[no_mangle]
pub fn merkle_root(c_addr: *const c_char, c_siblings: *const c_char, index: usize) -> *const u8 {
    let addr_str = unsafe { c_str_to_static_slice(c_addr) };
    let addr: Vec<Trit> = addr_str.trits();

    let siblings_str = unsafe { c_str_to_static_slice(c_siblings) };
    let siblings: Vec<Vec<Trit>> = siblings_str.split("\n").map(|s| s.trits()).collect();

    let root = root(&addr, &siblings, index);

    let out_str = Box::new(trits_to_string(root.trits().as_slice()).unwrap() + "\0");
    &out_str.as_bytes()[0] as *const u8
}
