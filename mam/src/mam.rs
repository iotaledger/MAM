use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use trytes::*;
use tmath::*;
use mask::*;
use errors::*;
use pascal;

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
pub fn message_id<T, C>(curl: &mut C, key: &mut [T])
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

pub fn create<C, CB, H>(
    seed: &[Trit],
    message: &[Trit],
    side_key: &[Trit],
    root: &[Trit],
    siblings: &[Trit],
    next: &[Trit],
    start: usize,
    index: usize,
    security: u8,
    sponge: &mut C,
    bcurl: &mut CB,
) -> Vec<Trit>
where
    C: Curl<Trit>,
    CB: Curl<BCTrit>,
    H: HammingNonce<Trit>,
{
    // generate the key and the get the merkle tree hashes
    let mut key: Vec<Trit> = vec![0 as Trit; security as usize * iss::KEY_LENGTH];
    let mut curl_bak: [Trit; STATE_LENGTH] = [0; STATE_LENGTH];
    sponge.reset();

    merkle::key(seed, start + index, security, &mut key, sponge);
    sponge.reset();
    message_key(side_key, root, index, sponge);
    let mut payload: Vec<Trit> = Vec::new();
    {
        {
            // add the pascal encoded message length ( and absorb it)
            let message_length = next.len() + message.len();
            let pascal_length = pascal::encoded_length(message_length);
            let mut v: [Trit; 10] = [0; 10];
            num::int2trits(message_length as isize, &mut v);
            let nt = num::min_trits(message_length as isize);
            let val = trits_to_string(&v);
            payload.extend_from_slice(&pascal::encode(message_length));
            sponge.absorb(&payload);
            //not masking the length
            //mask_slice(&mut payload, sponge);
        }
        let mut cursor = payload.len();
        cursor = {
            // add the next channel key and message, and mask it
            payload.extend_from_slice(&next);
            payload.extend_from_slice(&message);
            let end = payload.len();
            mask_slice(&mut payload[cursor..end], sponge);
            end
        };
        cursor = {
            // get the hamming nonce, append and mask it to payload
            curl_bak.clone_from_slice(&sponge.state());
            H::search(security, 0, HASH_LENGTH / 3, sponge, bcurl).unwrap();
            payload.extend_from_slice(&sponge.rate()[..HASH_LENGTH / 3]);
            let end = payload.len();
            sponge.state_mut().clone_from_slice(&curl_bak);
            mask_slice(&mut payload[cursor..end], sponge);
            bcurl.reset();
            end
        };
        curl_bak.clone_from_slice(&sponge.state());
        sponge.reset();
        iss::signature(&curl_bak[..HASH_LENGTH], &mut key, sponge);
        sponge.state_mut().clone_from_slice(&curl_bak);
        payload.extend_from_slice(&key);
        payload.extend_from_slice(&pascal::encode(siblings.len() / HASH_LENGTH));
        payload.extend_from_slice(&siblings);
        let end = payload.len();
        mask_slice(&mut payload[cursor..end], sponge);
        sponge.reset();
    }
    payload
}
enum UnmaskPascalStatus {
    /// Message Hash did not have any hamming weight of zero
    Searching,
    /// Signature did not match expected root
    Finalizing,
    /// Array was too short
    Done,
}

pub fn parse<C>(
    payload: &[Trit],
    side_key: &[Trit],
    root: &[Trit],
    index: usize,
    sponge: &mut C,
) -> Result<(Vec<Trit>, Vec<Trit>), MamError>
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
        let end = merkle::root(&hash, siblings, index, sponge);
        hash.clone_from_slice(&sponge.rate());

        if hash.iter()
            .zip(root.iter())
            .take_while(|&(&a, &b)| a != b)
            .count() == 0
        {
            let next_root: Vec<Trit> = out[..HASH_LENGTH].to_vec();
            let message_out: Vec<Trit> = out[HASH_LENGTH..message_length].to_vec();
            Ok((message_out, next_root))
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
        let security = 1;
        let start = 1;
        let count = 4;
        let next_start = start + count;
        let next_count = 2;
        let index = 1;

        let mut c1 = CpuCurl::<Trit>::default();
        let mut c2 = CpuCurl::<Trit>::default();
        let mut bc = CpuCurl::<BCTrit>::default();

        let mut key: Vec<Trit> = vec![0 as Trit; security as usize * iss::KEY_LENGTH];
        let (siblings, root) = {
            let mut digest = [0 as Trit; iss::DIGEST_LENGTH];

            let addresses: Vec<Vec<Trit>> = {
                let mut addr = Vec::new();
                for i in start..(start + count) {
                    merkle::key(&seed, i, security, &mut key, &mut c1);
                    c1.reset();

                    iss::digest_key(&key, &mut digest, &mut c1, &mut c2);
                    c1.reset();
                    c2.reset();
                    iss::address(&mut digest, &mut c1);
                    c1.reset();
                    addr.push(digest[..iss::ADDRESS_LENGTH].to_vec());
                }

                c1.reset();

                addr
            };

            let mut siblings =
                vec![0 as Trit; merkle::siblings_count(addresses.len()) * HASH_LENGTH];
            merkle::siblings(&addresses, index, &mut siblings, &mut c1);
            c1.reset();
            merkle::root(&addresses[index], &siblings, index, &mut c1);
            let root: Vec<Trit> = c1.rate().clone().to_vec();
            c1.reset();
            (siblings, root)
        };

        let next = {
            let mut digest = [0 as Trit; iss::DIGEST_LENGTH];
            let next_addrs: Vec<Vec<Trit>> = {
                let mut addr = Vec::new();
                for i in next_start..(next_start + next_count) {
                    merkle::key(&seed, i, security, &mut key, &mut c1);
                    c1.reset();

                    iss::digest_key(&key, &mut digest, &mut c1, &mut c2);
                    c1.reset();
                    c2.reset();
                    iss::address(&mut digest, &mut c1);
                    c1.reset();
                    addr.push(digest[..iss::ADDRESS_LENGTH].to_vec());
                }
                addr
            };
            c1.reset();
            c2.reset();

            let mut siblings =
                vec![0 as Trit; merkle::siblings_count(next_addrs.len()) * HASH_LENGTH];
            merkle::siblings(&next_addrs, 0, &mut siblings, &mut c1);
            c1.reset();
            merkle::root(&next_addrs[0], &siblings, 0, &mut c1);
            let mut next_root: Vec<Trit> = c1.rate().clone().to_vec();
            next_root
        };

        let masked_payload = create::<CpuCurl<Trit>, CpuCurl<BCTrit>, CpuHam>(
            &seed,
            &message,
            &side_key,
            &root,
            &siblings,
            &next,
            start,
            index,
            security,
            &mut c1,
            &mut bc,
        );
        c1.reset();

        let mut out: Vec<Trit> = vec![0; masked_payload.len()];
        let result = parse(&masked_payload, &side_key, &root, index, &mut c1)
            .ok()
            .unwrap();
        assert_eq!(result.0, message);
    }
}
/*
        {
            let mut pascals_length: Vec<Trit> = Vec::new();
            let mut status: UnmaskPascalStatus = UnmaskPascalStatus::Searching;
            let mut key_chunk: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
            let mut num_encoders = 0;
            let mut tryte_count = 0;
            let mut pascal_end = 0;
            key_chunk.clone_from_slice(&curl1.rate());
            for chunk in out.chunks_mut(HASH_LENGTH) {
                let len = chunk.len();
                for i in 0..len {
                    key_chunk[i] = trit_sum(chunk[i], -key_chunk[i]);
                }
                let end = match status {
                    UnmaskPascalStatus::Searching => {
                        for t in key_chunk.chunks(TRITS_PER_TRYTE) {
                            if num::trits2int(t) > 0 {
                                status = UnmaskPascalStatus::Finalizing;
                                num_encoders = tryte_count / TRITS_PER_TRYTE;
                                if tryte_count % 3 != 0 {
                                    num_encoders += 1;
                                }
                                num_encoders *= 2;
                                tryte_count += 1;
                                tryte_count *= 3;
                                tryte_count += num_encoders;
                                break;
                            }
                            tryte_count += 1;
                        }
                        match num_encoders {
                            0 => len,
                            _ => {
                                if tryte_count - pascal_end <= HASH_LENGTH {
                                    tryte_count - pascal_end
                                } else {
                                    len
                                }
                            }
                        }
                    }
                    UnmaskPascalStatus::Finalizing => {
                        if num_encoders < HASH_LENGTH {
                            status = UnmaskPascalStatus::Done;
                            num_encoders
                        } else {
                            num_encoders -= HASH_LENGTH;
                            len
                        }
                    }
                    _ => 0,
                };
                pascal_end += end;

                let k_str = trits_to_string(&chunk);
                let n_str = trits_to_string(&key_chunk);
                if end != 0 {
                    chunk[..end].clone_from_slice(&key_chunk[..end]);
                    curl1.absorb(&key_chunk[..end]);
                    key_chunk[..len].clone_from_slice(&curl1.rate()[..len]);
                }
                if end != HASH_LENGTH {
                    break;
                }
            }
            pascal::decode(&out[..pascal_end])
        };
 */
