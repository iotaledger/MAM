use alloc::boxed::Box;

use alloc::Vec;

use iota_trytes::*;
use iota_mam;
use iota_curl_cpu::*;

use shared::ctrits::*;

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

    let message_trits = ctrits_slice_trits(message);
    let siblings_trits = ctrits_slice_trits(siblings);
    let mut out: Vec<Trit> = vec![
        0;
        num::round_third(iota_mam::min_length(
        message_trits.len(),
        siblings_trits.len(),
        index,
        security as usize,
    ))
    ];
    iota_mam::create::<CpuCurl<Trit>, CpuCurl<BCTrit>, CpuHam>(
        ctrits_slice_trits(seed),
        message_trits,
        ctrits_slice_trits(key),
        ctrits_slice_trits(root),
        siblings_trits,
        ctrits_slice_trits(next_root),
        start,
        index,
        security,
        &mut out,
        &mut c1,
        &mut c2,
        &mut b1,
    );

    Box::into_raw(Box::new(ctrits_from_trits(out)))
}

#[no_mangle]
pub fn iota_mam_parse(
    payload: &mut CTrits,
    side_key: &CTrits,
    root: &CTrits,
) -> *mut [*mut CTrits; 2] {
    let mut c1 = CpuCurl::<Trit>::default();
    let mut payload_trits = ctrits_slice_trits_mut(payload);
    let result = iota_mam::parse(
        &mut payload_trits,
        ctrits_slice_trits(side_key),
        ctrits_slice_trits(root),
        &mut c1,
    ).ok()
        .unwrap();

    let message = Box::new(ctrits_from_trits(
        payload_trits[result.0 + HASH_LENGTH..result.1].to_vec(),
    ));
    let next = Box::new(ctrits_from_trits(
        payload_trits[result.0..result.0 + HASH_LENGTH].to_vec(),
    ));
    let out = Box::new([Box::into_raw(message), Box::into_raw(next)]);

    Box::into_raw(out)
}
