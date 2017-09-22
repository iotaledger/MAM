use alloc::boxed::Box;

use core::mem;
use core::ptr;
use alloc::Vec;

use iota_trytes::*;
use iota_mam::*;
use iota_curl_cpu::*;
use iota_curl::*;

use shared::ctrits::*;
use shared::util::*;

#[no_mangle]
pub fn iota_mam_create(
    seed: &CTrits,
    message: &CTrits,
    key: &CTrits,
    root: &CTrits,
    siblings: &CTrits,
    next_root: &CTrits,
    start: isize,
    index: usize,
    security: u8,
) -> *const CTrits {
    let mut c1 = CpuCurl::<Trit>::default();
    let mut c2 = CpuCurl::<Trit>::default();
    let mut b1 = CpuCurl::<BCTrit>::default();

    let masked_payload = create::<CpuCurl<Trit>, CpuCurl<BCTrit>, CpuHam>(
        ctrits_slice_trits(seed),
        ctrits_slice_trits(message),
        ctrits_slice_trits(key),
        ctrits_slice_trits(root),
        ctrits_slice_trits(siblings),
        ctrits_slice_trits(next_root),
        start,
        index,
        security,
        &mut c1,
        &mut c2,
        &mut b1,
    );

    let out = Box::new(ctrits_from_trits(masked_payload));
    Box::into_raw(out)
}

#[no_mangle]
pub fn iota_mam_parse(payload: &CTrits, side_key: &CTrits, root: &CTrits) -> *mut [*mut CTrits; 2] {
    println!(
        "payload {:?} sk {:?} root {:?}",
        payload.encoding,
        side_key.encoding,
        root.encoding
    );

    let mut c1 = CpuCurl::<Trit>::default();
    let result = parse(
        ctrits_slice_trits(payload),
        ctrits_slice_trits(side_key),
        ctrits_slice_trits(root),
        &mut c1,
    ).ok()
        .unwrap();

    let message = Box::new(ctrits_from_trits(result.message));
    let next = Box::new(ctrits_from_trits(result.next.to_vec()));
    let out = Box::new([Box::into_raw(message), Box::into_raw(next)]);

    Box::into_raw(out)
}
