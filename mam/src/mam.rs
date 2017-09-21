use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use trytes::*;
use tmath::*;
use mask::*;
use errors::*;
use pascal;

const MESSAGE_NONCE_LENGTH: usize = HASH_LENGTH / 3;

pub struct Message {
    pub next: [Trit; HASH_LENGTH],
    pub message: Vec<Trit>,
}


/// generate the message key for a root and an index.
/// It copies `root` to `key`, and adds `index` to it.
pub fn message_key<C: Curl<Trit>>(side_key: &[Trit], root: &[Trit], index: usize, curl: &mut C) {
    curl.absorb(side_key);
    let mut root_copy: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    root_copy.clone_from_slice(root);
    add_assign(&mut root_copy, index as isize);
    curl.absorb(&root_copy);
}

/// generates the address for a given mam `key`
/// for a mam, the key should consist of the merkle root and
/// an initialization vector, which is the index of the key  in the
/// merkle tree being used
pub fn message_id<T, C>(key: &mut [T], curl: &mut C)
where
    T: Copy + Clone + Sized,
    C: Curl<T>,
{
    curl.absorb(&key[..HASH_LENGTH]);
    key[..HASH_LENGTH].clone_from_slice(&curl.rate());
    curl.reset();
    curl.absorb(&key[..HASH_LENGTH]);
    key[..HASH_LENGTH].clone_from_slice(&curl.rate());
}

/// Creates a signed, encrypted payload from a `message`,
/// a `side_key`, which is used for encryption,
/// a merkle `root` which used as an initialization vector for the encryption,
/// the `next` merkle root which is copied to the message,
/// the `start` index of the current merkle tree,
/// the `index` relative to the tree of the key being used for signing,
/// the `security` parameter, giving the size of the signature,
/// a `curl` instance of Trit Curl for use in finding the hamming nonce and signing,
/// a `encr_curl` instance of Trit Curl for use in encrypting the payload,
/// and a `bcurl` instance of binary coded trits Curl for use in finding the hamming nonce
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
    curl: &mut C,
    encr_curl: &mut C,
    bcurl: &mut CB,
) -> Vec<Trit>
where
    C: Curl<Trit>,
    CB: Curl<BCTrit>,
    H: HammingNonce<Trit>,
{
    // generate the key and the get the merkle tree hashes
    let message_length = next.len() + message.len();
    let pascal_length = pascal::encoded_length(message_length);
    let signature_length = security as usize * iss::KEY_LENGTH;
    let branch_size = siblings.len() / HASH_LENGTH;
    let siblings_pascal_length = pascal::encoded_length(branch_size);
    let branch_length = branch_size * HASH_LENGTH;
    let payload_min_length = pascal_length + message_length + MESSAGE_NONCE_LENGTH +
        signature_length + siblings_pascal_length + branch_length;
    let mut key: Vec<Trit> = vec![0 as Trit; security as usize * iss::KEY_LENGTH];
    message_key(side_key, &root, index, encr_curl);
    let mut payload: Vec<Trit> = Vec::with_capacity(payload_min_length);
    payload.extend_from_slice(&pascal::encode(message_length));
    encr_curl.absorb(&payload);
    let mut cursor = payload.len();
    cursor = {
        payload.extend_from_slice(&next);
        payload.extend_from_slice(&message);
        let payload_end = payload.len();
        mask_slice(&mut payload[cursor..payload_end], encr_curl);
        payload.len()
    };
    cursor = {
        curl.state_mut().clone_from_slice(&encr_curl.state());
        H::search(security, 0, HASH_LENGTH / 3, curl, bcurl).unwrap();
        payload.extend_from_slice(&curl.rate()[..MESSAGE_NONCE_LENGTH]);
        let end = payload.len();
        mask_slice(&mut payload[cursor..end], encr_curl);
        bcurl.reset();
        curl.reset();
        payload.len()
    };

    iss::subseed(seed, start + index as isize, &mut key[..HASH_LENGTH], curl);
    curl.reset();
    iss::key(&mut key, security, curl);
    curl.reset();
    iss::signature(&encr_curl.rate(), &mut key, curl);
    curl.reset();

    payload.extend_from_slice(&key);
    payload.extend_from_slice(&pascal::encode(branch_size));
    payload.extend_from_slice(&siblings);
    mask_slice(&mut payload[cursor..], encr_curl);
    encr_curl.reset();
    payload
}

/// Parses an encrypted `payload`, first decrypting it with a
/// `side_key` and the `root` and `index` as an initialization vector,
/// and then checks that the signature is valid and
/// with sibling hashes in the payload resolves to the merkle `root`
/// Returns the `message` contained therein if valid, or a MamError if invalid
pub fn parse<C>(
    payload: &[Trit],
    side_key: &[Trit],
    root: &[Trit],
    index: usize,
    sponge: &mut C,
) -> Result<Message, MamError>
where
    C: Curl<Trit>,
{
    let mut hash: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    sponge.reset();
    message_key(side_key, root, index, sponge);

    let (message_length, message_length_end) = pascal::decode(&payload);
    if message_length > payload.len() {
        return Err(MamError::ArrayOutOfBounds);
    }
    sponge.absorb(&payload[..message_length_end]);
    let mut out: Vec<Trit> = (&payload[message_length_end..payload.len()])
        .clone()
        .to_vec();
    let mut pos = {
        unmask_slice(&mut out[..message_length], sponge);
        message_length
    };
    unmask_slice(&mut out[pos..pos + HASH_LENGTH / 3], sponge);
    pos += HASH_LENGTH / 3;
    let mut hmac: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    hmac.clone_from_slice(&sponge.rate());
    let security = iss::checksum_security(&hmac);
    let out_len = out.len();
    unmask_slice(&mut out[pos..out_len], sponge);
    hash.clone_from_slice(sponge.rate());
    if security != 0 {
        let sig_end = pos + security * iss::KEY_LENGTH;
        iss::digest_bundle_signature(&hmac, &mut out[pos..sig_end], sponge);
        hash.clone_from_slice(&sponge.rate());
        sponge.reset();
        iss::address(&mut hash, sponge);
        pos = sig_end;
        let l = pascal::decode(&out[pos..]);
        pos += l.1;
        let sib_end = pos + l.0 * HASH_LENGTH;
        let siblings = &out[pos..sib_end];
        merkle::root(&hash, siblings, index, sponge);
        hash.clone_from_slice(&sponge.rate());
        if hash.iter()
            .zip(root.iter())
            .take_while(|&(&a, &b)| a != b)
            .count() == 0
        {
            let mut out_message = Message {
                next: [0; HASH_LENGTH],
                message: Vec::with_capacity(message_length),
            };
            out_message.next.clone_from_slice(&out[..HASH_LENGTH]);
            out_message.message.extend_from_slice(
                &out[HASH_LENGTH..message_length],
            );
            Ok(out_message)
        } else {
            Err(MamError::InvalidSignature)
        }
    } else {
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
        let index = 1;

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

        let branch = merkle::branch(&root, index);
        let branch_size = merkle::len(&branch);
        let branch_length = branch_size * HASH_LENGTH;
        let mut siblings: Vec<Trit> = vec![0; branch_length];
        merkle::write_branch(&branch, branch_length - HASH_LENGTH, &mut siblings);

        let masked_payload = create::<CpuCurl<Trit>, CpuCurl<BCTrit>, CpuHam>(
            &seed,
            &message,
            &side_key,
            &root_trits,
            &siblings,
            &next_root_trits,
            start,
            index,
            security,
            &mut c1,
            &mut c2,
            &mut bc,
        );

        match root {
            merkle::MerkleTree::Node(_, hash, _) => root_trits.clone_from_slice(&hash),
            _ => {}
        }
        match parse(&masked_payload, &side_key, &root_trits, index, &mut c1) {
            Ok(result) => assert_eq!(result.message, message),
            Err(e) => {
                match e {
                    MamError::InvalidSignature => assert!(false, "Invalid Signature"),
                    MamError::InvalidHash => assert!(false, "Invalid Hash"),
                    _ => assert!(false, "some other error!"),
                }
            }
        }
    }
}
