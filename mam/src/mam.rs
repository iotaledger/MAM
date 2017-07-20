use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use trytes::*;
use auth::*;
use mask::*;
use errors::*;

pub fn message_id<T, C>(keys: &[Vec<T>]) -> Vec<T>
where
    T: Copy + Clone + Sized,
    C: Curl<T>,
{
    let mut c = C::default();
    for key in keys {
        c.absorb(key.as_slice());
    }
    let mask = c.rate().to_vec();
    c.reset();
    c.absorb(&mask);
    c.rate().to_vec()
}

pub fn create<C, H>(
    seed: &[Trit],
    message: &[Trit],
    start: usize,
    count: usize,
    index: usize,
    next_start: usize,
    next_count: usize,
    security: u8,
) -> (Vec<Trit>, Vec<Trit>)
where
    C: Curl<Trit>,
    H: HammingNonce<Trit>,
{
    // generate the key and the get the merkle tree hashes
    let (key, siblings, root) = {
        let key: Vec<Trit>;
        let addresses: Vec<Vec<Trit>>;
        {
            let keys = merkle::keys(seed, start, count, security);
            key = keys[index].clone();
            addresses = keys.iter()
                .map(|ref k| iss::address::<Trit, C>(&iss::digest_key::<Trit, C>(&k.as_slice())))
                .collect();
        }
        let siblings = merkle::siblings(&addresses, index);
        let root = merkle::root(&addresses[index], &siblings, index);
        (key, siblings, root)
    };
    let next = {
        let next_addrs: Vec<Vec<Trit>> = merkle::keys(seed, next_start, next_count, security)
            .iter()
            .map(|ref key| {
                iss::address::<Trit, C>(&iss::digest_key::<Trit, C>(&key.as_slice()))
            })
            .collect();
        merkle::root(&next_addrs[0].clone(), &merkle::siblings(&next_addrs, 0), 0)
    };

    let channel_key: Vec<Vec<Trit>> =
        vec![
            root.clone(),
            num::int2trits(index as isize, num::min_trits(index as isize)),
        ];
    let masked_payload = mask::<C>(
        &sign::<C, H>(message, &next, &key, &siblings, security),
        &channel_key,
    );
    (masked_payload, root)
}

pub fn parse<C>(
    payload: &[Trit],
    root: &[Trit],
    index: usize,
) -> Result<(Vec<Trit>, Vec<Trit>), MamError>
where
    C: Curl<Trit>,
{
    let index_trits = num::int2trits(index as isize, num::min_trits(index as isize));
    let channel_key: Vec<Vec<Trit>> = vec![root.to_vec(), index_trits];
    let unmasked_payload = unmask::<C>(payload, &channel_key);
    authenticate::<C>(&unmasked_payload, root, index)
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
            .trits();
        let message: Vec<Trit> = "IAMSOMEMESSAGE9HEARMEROARMYMESSAGETOTHEWORLDYOUHEATHEN".trits();
        let security = 1;
        let start = 1;
        let count = 9;
        let next_start = start + count;
        let next_count = 4;
        let index = 3;

        let (masked_payload, root) = create::<CpuCurl<Trit>, CpuHam>(
            &seed,
            &message,
            start,
            count,
            index,
            next_start,
            next_count,
            security,
        );
        let result = parse::<CpuCurl<Trit>>(&masked_payload, &root, index)
            .ok()
            .unwrap();
        assert_eq!(result.0, message);
    }
}
