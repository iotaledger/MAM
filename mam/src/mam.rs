use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use trytes::*;
use mask::*;
use errors::*;
use pascal;

const MESSAGE_NONCE_LENGTH: usize = HASH_LENGTH / 3;

pub fn id<C: Curl<Trit>>(side_key: &[Trit], root: &[Trit], out: &mut [Trit], c: &mut C) {
    c.absorb(side_key);
    c.absorb(root);
    c.squeeze(out);
    c.reset();
}

pub fn min_length(
    message_length: usize,
    siblings_length: usize,
    index: usize,
    security: usize,
) -> usize {
    pascal::encoded_length(index as isize) +
        pascal::encoded_length((HASH_LENGTH + message_length) as isize) + HASH_LENGTH +
        message_length + MESSAGE_NONCE_LENGTH + security as usize * iss::KEY_LENGTH +
        pascal::encoded_length((siblings_length / HASH_LENGTH) as isize) + siblings_length
}

/// Creates a signed, encrypted payload from a `message`,
///
/// * a `side_key`, which is used for encryption,
/// * a merkle `root` which used as an initialization vector for the encryption,
/// * the `next` merkle root which is copied to the message,
/// * the `start` index of the current merkle tree,
/// * the `index` relative to the tree of the key being used for signing,
/// * the `security` parameter, giving the size of the signature,
/// * a `curl` instance of Trit Curl for use in finding the hamming nonce and signing,
/// * a `encr_curl` instance of Trit Curl for use in encrypting the payload,
/// * a `bcurl` instance of binary coded trits Curl for use in finding the hamming nonce
///
/// Returns the signed, encrypted `payload`
pub fn create<C, CB, H>(
    seed: &[Trit],
    message: &[Trit],
    side_key: &[Trit],
    root: &[Trit],
    siblings: &[Trit],
    next: &[Trit],
    start: isize,
    index: usize,
    security: u8,
    payload: &mut [Trit],
    curl: &mut C,
    encr_curl: &mut C,
    bcurl: &mut CB,
) -> usize
where
    C: Curl<Trit>,
    CB: Curl<BCTrit>,
    H: HammingNonce<Trit>,
{
    // generate the key and the get the merkle tree hashes
    let message_length = message.len();

    let index_p = pascal::encoded_length(index as isize);
    let message_p = pascal::encoded_length(message_length as isize);

    let siblings_length = siblings.len();
    let siblings_count = (siblings.len() / HASH_LENGTH) as isize;
    let siblings_pascal_length = pascal::encoded_length(siblings_count);
    let signature_length = security as usize * iss::KEY_LENGTH;
    let payload_min_length = message_p + HASH_LENGTH + message_length + MESSAGE_NONCE_LENGTH +
        signature_length +
        siblings_pascal_length + siblings_length + index_p;

    let next_root_start = index_p + message_p;
    let next_end = next_root_start + next.len();
    let message_end = next_root_start + HASH_LENGTH + message_length;
    let nonce_end = message_end + MESSAGE_NONCE_LENGTH;
    let signature_end = nonce_end + signature_length;
    let siblings_pascal_end = signature_end + siblings_pascal_length;
    let siblings_end = siblings_pascal_end + siblings_length;

    assert!(
        payload.len() >= payload_min_length,
        "should be: {}, is {}",
        payload_min_length,
        payload.len()
    );

    encr_curl.absorb(side_key);
    encr_curl.absorb(root);
    pascal::encode(index as isize, &mut payload[..index_p]);
    pascal::encode(
        message_length as isize,
        &mut payload[index_p..next_root_start],
    );
    encr_curl.absorb(&payload[..next_root_start]);
    payload[next_root_start..next_end].clone_from_slice(&next);
    payload[next_end..message_end].clone_from_slice(&message);
    mask_slice(&mut payload[next_root_start..message_end], encr_curl);
    curl.state_mut().clone_from_slice(&encr_curl.state());
    H::search(security, 0, HASH_LENGTH / 3, curl, bcurl).unwrap();
    payload[message_end..nonce_end].clone_from_slice(&curl.rate()[..MESSAGE_NONCE_LENGTH]);
    mask_slice(&mut payload[message_end..nonce_end], encr_curl);
    bcurl.reset();
    curl.reset();
    iss::subseed(
        seed,
        start + index as isize,
        &mut payload[nonce_end..nonce_end + HASH_LENGTH],
        curl,
    );
    curl.reset();
    iss::key(
        &mut payload[nonce_end..signature_end],
        security as usize,
        curl,
    );
    curl.reset();
    iss::signature(
        &encr_curl.rate(),
        &mut payload[nonce_end..signature_end],
        curl,
    );
    curl.reset();
    pascal::encode(
        siblings_count,
        &mut payload[signature_end..siblings_pascal_end],
    );
    payload[siblings_pascal_end..siblings_end].clone_from_slice(&siblings);
    mask_slice(&mut payload[nonce_end..siblings_end], encr_curl);
    encr_curl.reset();
    payload_min_length
}

/// Parses an encrypted `payload`, first decrypting it with a
///
///   * `side_key`
///   * `root`
///   * `index`
///
/// as initialization vector.
///
/// Then checks that the signature is valid and with sibling hashes in the payload
/// resolves to the merkle `root`.
///
/// Returns the `message` contained therein if valid, or a MamError if invalid
pub fn parse<C>(
    payload: &mut [Trit],
    side_key: &[Trit],
    root: &[Trit],
    curl: &mut C,
) -> Result<(usize, usize), MamError>
where
    C: Curl<Trit>,
{
    let (index, message_length, next_root_start) = {
        let (index, index_end) = pascal::decode(&payload);
        let (message_length, message_length_end) = pascal::decode(&payload[index_end..]);
        (
            index as usize,
            message_length as usize,
            (index_end + message_length_end) as usize,
        )
    };
    let message_start = next_root_start + HASH_LENGTH;
    let message_end = message_start + message_length;

    curl.absorb(side_key);
    curl.absorb(root);
    if message_length as usize > payload.len() {
        return Err(MamError::ArrayOutOfBounds);
    }
    curl.absorb(&payload[..next_root_start]);

    let mut pos = {
        unmask_slice(&mut payload[next_root_start..message_start], curl);
        unmask_slice(&mut payload[message_start..message_end], curl);
        message_end as usize
    };
    unmask_slice(&mut payload[pos..pos + MESSAGE_NONCE_LENGTH], curl);
    pos += HASH_LENGTH / 3;
    let mut hmac: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    hmac.clone_from_slice(&curl.rate());
    let security = iss::checksum_security(&hmac);
    unmask_slice(&mut payload[pos..], curl);
    if security != 0 {
        let sig_end = pos + security * iss::KEY_LENGTH;
        iss::digest_bundle_signature(&hmac, &mut payload[pos..sig_end], curl);
        hmac.clone_from_slice(&curl.rate());
        curl.reset();
        iss::address(&mut hmac, curl);
        pos = sig_end;
        let l = pascal::decode(&payload[pos..]);
        pos += l.1;
        let sib_end = pos + l.0 as usize * HASH_LENGTH;
        let siblings = &payload[pos..sib_end];
        merkle::root(&hmac, siblings, index as usize, curl);
        let res = if curl.rate() == root {
            Ok((next_root_start, message_end))
        } else {
            Err(MamError::InvalidSignature)
        };
        curl.reset();
        res
    } else {
        curl.reset();
        Err(MamError::InvalidHash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curl_cpu::*;
    use alloc::Vec;
    #[test]
    fn it_works() {
        let seed: Vec<Trit> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9\
                             ABCDEFGHIJKLMNOPQRSTUVWXYZ9\
                             ABCDEFGHIJKLMNOPQRSTUVWXYZ9"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();
        let message: Vec<Trit> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();
        let side_key: Vec<Trit> = "EFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDABCD"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();
        let security: u8 = 1;
        let start: isize = 1;
        let count: usize = 4;
        let next_start = start + count as isize;
        let next_count = 2;

        let mut c1 = CpuCurl::<Trit>::default();
        let mut c2 = CpuCurl::<Trit>::default();
        let mut c3 = CpuCurl::<Trit>::default();
        let mut bc = CpuCurl::<BCTrit>::default();

        let root = merkle::create(
            &seed,
            start,
            count,
            security as usize,
            &mut c1,
            &mut c2,
            &mut c3,
        );
        let next_root = merkle::create(
            &seed,
            next_start,
            next_count,
            security as usize,
            &mut c1,
            &mut c2,
            &mut c3,
        );
        let mut root_trits: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
        let mut next_root_trits: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
        match root {
            merkle::MerkleTree::Node(_, hash, _) => root_trits.clone_from_slice(&hash),
            _ => {}
        }
        match next_root {
            merkle::MerkleTree::Node(_, hash, _) => next_root_trits.clone_from_slice(&hash),
            _ => {}
        }

        for index in 0..count {
            let branch = merkle::branch(&root, index);
            let branch_size = merkle::len(&branch);
            let siblings_length = branch_size * HASH_LENGTH;
            let mut siblings: Vec<Trit> = vec![0; siblings_length];
            merkle::write_branch(&branch, siblings_length - HASH_LENGTH, &mut siblings);

            let mut payload: Vec<Trit> =
                vec![0; min_length(message.len(), siblings.len(), index, security as usize)];

            create::<CpuCurl<Trit>, CpuCurl<BCTrit>, CpuHam>(
                &seed,
                &message,
                &side_key,
                &root_trits,
                &siblings,
                &next_root_trits,
                start,
                index,
                security,
                &mut payload,
                &mut c1,
                &mut c2,
                &mut bc,
            );

            match parse(&mut payload, &side_key, &root_trits, &mut c1) {
                Ok((s, len)) => {
                    assert_eq!(
                        trits_to_string(&payload[s + HASH_LENGTH..len]),
                        trits_to_string(&message)
                    )
                }
                Err(e) => {
                    match e {
                        MamError::InvalidSignature => panic!("Invalid Signature"),
                        MamError::InvalidHash => panic!("Invalid Hash"),
                        MamError::ArrayOutOfBounds => panic!("Array Out of Bounds"),
                        _ => panic!("Some error!"),
                    }
                }
            }
        }
    }
}
