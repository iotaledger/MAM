use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use pascal;
use trytes::*;
use errors::*;

pub fn sign<CT, CB, H>(
    message_in: &[Trit],
    next: &[Trit],
    key: &[Trit],
    hashes: &[Vec<Trit>],
    security: u8,
    tcurl: &mut CT,
    bcurl: &mut CB,
) -> Vec<Trit>
where
    CT: Curl<Trit>,
    CB: Curl<BCTrit>,
    H: HammingNonce<Trit>,
{
    let mut message: Vec<Trit> = next.to_vec();
    message.extend_from_slice(&message_in);

    let message_length = message.len() / TRITS_PER_TRYTE;
    let mut message_nonce_space = vec![0; HASH_LENGTH];
    let nonce_len = H::search::<CT, CB>(&message, security, TRITS_PER_TRYTE as usize, &mut message_nonce_space, tcurl, bcurl)
        .unwrap();
    let message_nonce = &message_nonce_space[0..nonce_len];

    tcurl.reset();
    bcurl.reset();

    let signature = {
        let mut signature = vec![0; iss::SIGNATURE_LENGTH];
        let mut len_trits = vec![0; num::min_trits(message_length as isize)];
        num::int2trits(message_length as isize, &mut len_trits);

        tcurl.absorb(&len_trits);
        tcurl.absorb(&message);
        tcurl.absorb(&message_nonce);

        let rate = tcurl.rate().to_vec();
        tcurl.reset();

        iss::signature::<CT>(&rate, &key, &mut signature, tcurl);
        signature
    };

    pascal::encode(message_length)
        .into_iter()
        .chain(message.into_iter())
        .chain(
            pascal::encode(message_nonce.len() / TRITS_PER_TRYTE).into_iter(),
        )
        .chain(message_nonce.iter().cloned())
        .chain(signature.into_iter())
        .chain(pascal::encode(hashes.len()).into_iter())
        .chain(
            hashes
                .into_iter()
                .fold(Vec::with_capacity(hashes.len() * HASH_LENGTH), |mut acc,
                 v| {
                    acc.extend(v);
                    acc
                })
                .into_iter(),
        )
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
    let mut payload_iter = payload.iter();
    let (message_length, message_length_end) = pascal::decode(&payload);
    let message: Vec<Trit> = payload_iter
        .by_ref()
        .skip(message_length_end)
        .take(message_length * TRITS_PER_TRYTE)
        .cloned()
        .collect();
    let nonce: Vec<Trit> = payload_iter
        .by_ref()
        .skip({
            let t = &payload[(message_length_end + message.len())..];
            let (l, e) = pascal::decode(&t);
            length = l * TRITS_PER_TRYTE;
            e
        })
        .take(length)
        .cloned()
        .collect();
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
            let mut address = vec![0; iss::ADDRESS_LENGTH];
            let mut digest = vec![0; iss::DIGEST_LENGTH];
            let signature: Vec<Trit> = payload_iter
                .by_ref()
                .take(security * iss::KEY_LENGTH)
                .cloned()
                .collect();

            iss::digest_bundle_signature::<C>(&hash, &signature, &mut digest, curl1, curl2);
            curl1.reset();
            iss::address::<Trit, C>(&digest, &mut address, curl1);
            curl1.reset();

            let siblings: Vec<Vec<Trit>> = {
                let end_trits: Vec<Trit> = payload_iter.by_ref().cloned().collect();
                let l = pascal::decode(&end_trits);
                end_trits[l.1..]
                    .chunks(HASH_LENGTH)
                    .take(l.0)
                    .map(|c| c.to_vec())
                    .collect()
            };
            merkle::root::<C>(&address, &siblings, index, curl1)
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
