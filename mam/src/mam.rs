use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use trytes::*;
use auth::*;
use mask::*;
use errors::*;

pub fn message_id<T, C>(keys: &[Vec<T>], curl: &mut C) -> Vec<T>
where
    T: Copy + Clone + Sized,
    C: Curl<T>,
{
    for key in keys {
        curl.absorb(key.as_slice());
    }
    let mask = curl.rate().to_vec();
    curl.reset();
    curl.absorb(&mask);
    curl.rate().to_vec()
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
    curl3: &mut C,
    bcurl: &mut CB,
) -> (Vec<Trit>, Vec<Trit>)
where
    C: Curl<Trit>,
    CB: Curl<BCTrit>,
    H: HammingNonce<Trit>,
{

    let mut digest = vec![0; iss::DIGEST_LENGTH];

    // generate the key and the get the merkle tree hashes
    let (key, siblings, root) = {
        let mut key = [0 as Trit; iss::KEY_LENGTH];
        let addresses: Vec<Vec<Trit>>;
        {
            addresses = merkle::keys(seed, start, count, security, curl3)
                .enumerate()
                .map(|(i, ref k)| {
                    if i == index {
                        key.clone_from_slice(k);
                    }

                    iss::digest_key::<Trit, C>(k, &mut digest, curl1, curl2);
                    curl1.reset();
                    curl2.reset();
                    iss::address::<Trit, C>(&mut digest, curl1);
                    curl1.reset();
                    digest[..iss::ADDRESS_LENGTH].to_vec()
                })
                .collect();

            curl3.reset();
        }
        let siblings = merkle::siblings(&addresses, index, curl1);
        curl1.reset();
        let root = merkle::root(&addresses[index], &siblings, index, curl1);
        curl1.reset();
        (key, siblings, root)
    };

    let next = {
        let next_addrs: Vec<Vec<Trit>> =
            merkle::keys(seed, next_start, next_count, security, curl3)
                .map(|ref key| {
                    curl1.reset();
                    curl2.reset();
                    iss::digest_key::<Trit, C>(key, &mut digest, curl1, curl2);
                    curl1.reset();
                    iss::address::<Trit, C>(&mut digest, curl1);
                    digest[..iss::ADDRESS_LENGTH].to_vec()
                })
                .collect();
        curl1.reset();
        curl2.reset();
        curl3.reset();
        merkle::root(
            &next_addrs[0],
            &merkle::siblings(&next_addrs, 0, curl2),
            0,
            curl1,
        )
    };

    curl1.reset();
    curl2.reset();

    let channel_key: Vec<Vec<Trit>> = vec![
        root.clone(),
        {
            let mut t = vec![0; num::min_trits(index as isize)];
            num::int2trits(index as isize, &mut t);
            t
        },
    ];

    let masked_payload = mask::<C>(
        &sign::<C, CB, H>(message, &next, &key, &siblings, security, curl1, bcurl),
        &channel_key,
        curl2,
    );
    (masked_payload, root)
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
    let channel_key: Vec<Vec<Trit>> = vec![
        root.to_vec(),
        {
            let mut index_trits = vec![0; num::min_trits(index as isize)];
            num::int2trits(index as isize, &mut index_trits);

            index_trits
        },
    ];
    let unmasked_payload = unmask::<C>(payload, &channel_key, curl1);

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
        let mut c3 = CpuCurl::<Trit>::default();
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
            &mut c3,
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
