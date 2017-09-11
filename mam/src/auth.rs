use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use pascal;
use trytes::*;
use errors::*;
use core::slice;

pub fn sign<CT, CB, H>(
    message_in: &[Trit],
    next: &[Trit],
    key: &[Trit],
    hashes: &[Trit],
    security: u8,
    tcurl: &mut CT,
    bcurl: &mut CB,
) -> Vec<Trit>
where
    CT: Curl<Trit>,
    CB: Curl<BCTrit>,
    H: HammingNonce<Trit>,
{
    let mut message = next.to_vec();
    message.extend_from_slice(&message_in);

    let message_length = message.len() / TRITS_PER_TRYTE;
    {
        let mut len = vec![0; num::min_trits(message_length as isize) as usize];
        num::int2trits(message_length as isize, len.as_mut_slice());
        tcurl.absorb(&len);
    }
    tcurl.absorb(&message);
    let nonce_len = H::search::<CT, CB>(security, 0, HASH_LENGTH, tcurl, bcurl).unwrap();
    let message_nonce = tcurl.rate()[0..nonce_len].to_vec();

    tcurl.reset();
    bcurl.reset();

    let signature = {
        // we won't use BCurl anymore and we know
        // that BCurl memory size = 2*Curl
        let bundle: &mut [Trit] = unsafe {
            slice::from_raw_parts_mut(bcurl.state_mut().as_mut_ptr() as *mut Trit, HASH_LENGTH)
        };
        let mut signature = vec![0; security as usize * iss::SIGNATURE_LENGTH];
        let mut len_trits = vec![0; num::min_trits(message_length as isize)];
        num::int2trits(message_length as isize, &mut len_trits);

        tcurl.absorb(&len_trits);
        tcurl.absorb(&message);
        tcurl.absorb(&message_nonce);

        bundle.clone_from_slice(tcurl.rate());
        tcurl.reset();

        signature[0..security as usize * iss::KEY_LENGTH]
            .clone_from_slice(&key[0..security as usize * iss::KEY_LENGTH]);

        iss::signature::<CT>(bundle, &mut signature, tcurl);
        signature
    };

    tcurl.reset();
    bcurl.reset();

    pascal::encode(message_length)
        .iter()
        .chain(message.iter())
        .chain(pascal::encode(message_nonce.len() / TRITS_PER_TRYTE).iter())
        .chain(message_nonce.iter())
        .chain(signature.iter())
        .chain(pascal::encode(hashes.len() / HASH_LENGTH).iter())
        .chain(
            hashes
                .chunks(HASH_LENGTH)
                .into_iter()
                .fold(Vec::with_capacity(hashes.len()), |mut acc, v| {
                    acc.extend(v);
                    acc
                })
                .iter(),
        )
        .cloned()
        .collect()
}

pub fn authenticate<C>(
    payload: &[Trit],
    root: &[Trit],
    index: usize,
    curl1: &mut C,
    curl2: &mut C,
) -> Result<(Vec<Trit>, Vec<Trit>), MamError>
where
    C: Curl<Trit>,
{

    let length;
    let (message_length, message_length_end) = pascal::decode(&payload);
    let mut pos = message_length_end;

    let message = &payload[pos..pos + (message_length * TRITS_PER_TRYTE)];
    pos += message_length * TRITS_PER_TRYTE;
    let nonce = {
        let t = &payload[pos..];
        let (l, e) = pascal::decode(&t);
        length = l * TRITS_PER_TRYTE;
        pos += e;
        &payload[pos..pos + length]
    };

    pos += length;

    let hash = {
        let mut len_trits = vec![0; num::min_trits(message_length as isize)];
        num::int2trits(message_length as isize, &mut len_trits);
        curl1.absorb(&len_trits);
        curl1.absorb(&message);
        curl1.absorb(&nonce);
        curl1.rate().to_vec()
    };
    curl1.reset();

    let security = iss::checksum_security(&hash);
    if security != 0 {
        let calculated_root: Vec<Trit> = {
            let mut signature: Vec<Trit> =
                payload[pos..pos + (security as usize * iss::KEY_LENGTH)].to_vec();
            pos += security as usize * iss::KEY_LENGTH;

            iss::digest_bundle_signature::<C>(&hash, &mut signature, curl1);
            curl1.reset();
            curl2.reset();

            iss::address::<Trit, C>(&mut signature[..iss::DIGEST_LENGTH], curl1);
            curl1.reset();


            let siblings: Vec<Trit> = {
                let end_trits = &payload[pos..];
                let l = pascal::decode(end_trits);
                end_trits[l.1..]
                    .iter()
                    .take(l.0 * HASH_LENGTH)
                    .cloned()
                    .collect()
            };
            merkle::root::<C>(&signature[..iss::ADDRESS_LENGTH], &siblings, index, curl1)
        };

        if calculated_root == root {
            let next_root: Vec<Trit> = message[..HASH_LENGTH].to_vec();
            let message_out: Vec<Trit> = message[HASH_LENGTH..].to_vec();
            Ok((message_out, next_root))
        } else {
            Err(MamError::InvalidSignature)
        }
    } else {
        Err(MamError::InvalidHash)
    }
}
