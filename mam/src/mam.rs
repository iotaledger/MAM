use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use trytes::*;
use tmath::*;
use auth::*;
use mask::*;
use errors::*;

/// generate the message key for a root and an index.
/// It copies `root` to `key`, and adds `index` to it.
pub fn message_key(root: &[Trit], index: usize, key: &mut [Trit]) -> Result<usize, MamError> {
    assert!(root.len() >= HASH_LENGTH);
    assert!(key.len() >= HASH_LENGTH);
    key[..HASH_LENGTH].clone_from_slice(&root[..HASH_LENGTH]);
    add_assign(&mut key[..HASH_LENGTH], index as isize);
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

pub fn create<C, CB, H>(
    seed: &[Trit],
    message: &[Trit],
    start: usize,
    count: usize,
    index: usize,
    next_start: usize,
    next_count: usize,
    security: u8,
    curl1: &mut C,
    curl2: &mut C,
    bcurl: &mut CB,
) -> (Vec<Trit>, Vec<Trit>)
where
    C: Curl<Trit>,
    CB: Curl<BCTrit>,
    H: HammingNonce<Trit>,
{
    // generate the key and the get the merkle tree hashes
    let mut key = [0 as Trit; iss::KEY_LENGTH];
    let (siblings, root) = {
        let mut digest = [0 as Trit; iss::DIGEST_LENGTH];

        let addresses: Vec<Vec<Trit>> = {
            let mut addr = Vec::new();
            for i in start..(start + count) {
                merkle::key(seed, i, security, &mut key, curl1);
                curl1.reset();

                iss::digest_key::<Trit, C>(&key, &mut digest, curl1, curl2);
                curl1.reset();
                curl2.reset();
                iss::address::<Trit, C>(&mut digest, curl1);
                curl1.reset();
                addr.push(digest[..iss::ADDRESS_LENGTH].to_vec());
            }

            curl1.reset();

            addr
        };
        let siblings = merkle::siblings(&addresses, index, curl1);
        curl1.reset();
        let root = merkle::root(&addresses[index], &siblings, index, curl1);
        curl1.reset();
        (siblings, root)
    };

    let next = {
        let mut digest = [0 as Trit; iss::DIGEST_LENGTH];
        let next_addrs: Vec<Vec<Trit>> = {
            let mut addr = Vec::new();
            for i in next_start..(next_start + next_count) {
                merkle::key(seed, i, security, &mut key, curl1);
                curl1.reset();

                iss::digest_key::<Trit, C>(&key, &mut digest, curl1, curl2);
                curl1.reset();
                curl2.reset();
                iss::address::<Trit, C>(&mut digest, curl1);
                curl1.reset();
                addr.push(digest[..iss::ADDRESS_LENGTH].to_vec());
            }
            addr
        };
        curl1.reset();
        curl2.reset();
        merkle::root(
            &next_addrs[0],
            &merkle::siblings(&next_addrs, 0, curl2),
            0,
            curl1,
        )
    };

    curl1.reset();
    curl2.reset();

    merkle::key(seed, start + index, security, &mut key, curl1);
    curl1.reset();
    let mut payload = sign::<C, CB, H>(message, &next, &key, &siblings, security, curl1, bcurl);

    {
        let mut index_trits = vec![0; num::min_trits(index as isize)];
        num::int2trits(index as isize, &mut index_trits);
        let channel_key: [&[Trit]; 2] = [&root, &index_trits];
        mask::<C>(&mut payload, &channel_key, curl2);
    }
    (payload, root)
}

pub fn parse<C>(
    payload: &[Trit],
    root: &[Trit],
    index: usize,
    curl1: &mut C,
    curl2: &mut C,
) -> Result<(Vec<Trit>, Vec<Trit>), MamError>
where
    C: Curl<Trit>,
{
    let mut index_trits = vec![0; num::min_trits(index as isize)];
    num::int2trits(index as isize, &mut index_trits);
    let channel_key: [&[Trit]; 2] = [&root, &index_trits];
    let mut unmasked_payload = payload.to_vec();
    unmask::<C>(&mut unmasked_payload, &channel_key, curl1);

    curl1.reset();
    authenticate::<C>(&unmasked_payload, root, index, curl1, curl2)
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
        let message: Vec<Trit> = "IAMSOMEMESSAGE9HEARMEROARMYMESSAGETOTHEWORLDYOUHEATHEN"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();
        let security = 1;
        let start = 1;
        let count = 9;
        let next_start = start + count;
        let next_count = 4;
        let index = 3;

        let mut c1 = CpuCurl::<Trit>::default();
        let mut c2 = CpuCurl::<Trit>::default();
        let mut bc = CpuCurl::<BCTrit>::default();

        let (masked_payload, root) = create::<CpuCurl<Trit>, CpuCurl<BCTrit>, CpuHam>(
            &seed,
            &message,
            start,
            count,
            index,
            next_start,
            next_count,
            security,
            &mut c1,
            &mut c2,
            &mut bc,
        );
        c1.reset();
        c2.reset();

        let result = parse::<CpuCurl<Trit>>(&masked_payload, &root, index, &mut c1, &mut c2)
            .ok()
            .unwrap();
        assert_eq!(result.0, message);
    }
}
