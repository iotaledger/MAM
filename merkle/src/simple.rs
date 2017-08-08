use trytes::*;
use tmath::*;
use curl::*;
use sign::iss;
use core::mem;
use alloc::*;

pub fn key<C: Curl<Trit>>(seed: &[Trit], index: usize, security: u8, out: &mut [Trit], curl: &mut C) {
    let mut subseed = [0; HASH_LENGTH];

    subseed[0..HASH_LENGTH].clone_from_slice(&seed);
    for _ in 0..index {
        (&mut subseed[0..HASH_LENGTH]).incr();
    }

    iss::subseed::<C>(&subseed[0..HASH_LENGTH], 0, out, curl);
    curl.reset();
    iss::key::<Trit, C>(out, security, curl);
}

pub fn siblings<C: Curl<Trit>>(addrs: &[Vec<Trit>], index: usize, curl: &mut C) -> Vec<Vec<Trit>> {
    let usize_size = mem::size_of::<usize>() * 8;
    let hash_count = usize_size - index.leading_zeros() as usize;

    let mut out: Vec<Vec<Trit>> = Vec::with_capacity(hash_count);
    let mut hash_index = if index & 1 == 0 { index + 1 } else { index - 1 };
    let mut hashes: Vec<Vec<Trit>> = addrs.to_vec();
    let mut length = hashes.len();

    while length > 1 {
        if length & 1 == 1 {
            hashes.push(vec![0; HASH_LENGTH]);
            length += 1;
        }

        out.push(hashes[hash_index].clone());
        hash_index = hash_index / 2;
        if hash_index & 1 == 0 {
            hash_index += 1;
        } else {
            hash_index -= 1;
        }

        length /= 2;
        for i in 0..length {
            curl.absorb(&hashes[i * 2]);
            curl.absorb(&hashes[i * 2 + 1]);

            hashes[i] = curl.rate().to_vec();
            curl.reset();
        }

        hashes.truncate(length);
    }
    out
}

pub fn root<C: Curl<Trit>>(
    address: &[Trit],
    hashes: &[Vec<Trit>],
    index: usize,
    curl: &mut C,
) -> Vec<Trit> {
    let mut i = 1;

    let mut out = address.to_vec();
    let mut helper = |out: &mut [Trit], hash: &[Trit]| {
        curl.reset();
        if i & index == 0 {
            curl.absorb(&out);
            curl.absorb(&hash);
        } else {
            curl.absorb(&hash);
            curl.absorb(&out);
        }
        i <<= 1;

        out.clone_from_slice(curl.rate());
    };

    for hash in hashes {
        helper(&mut out, hash);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sign::iss;
    use curl_cpu::*;
    #[test]
    fn it_does_not_panic() {
        let seed: Vec<Trit> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9\
                             ABCDEFGHIJKLMNOPQRSTUVWXYZ9\
                             ABCDEFGHIJKLMNOPQRSTUVWXYZ9"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();

        let mut c1 = CpuCurl::<Trit>::default();
        let mut c2 = CpuCurl::<Trit>::default();
        let mut c3 = CpuCurl::<Trit>::default();

        let start = 1;
        let count = 9;
        let security = 1;

        let mut digest = vec![0; iss::DIGEST_LENGTH];
        /*let addresses: Vec<Vec<Trit>> = keys(&seed, start, count, security, &mut c1)
            .map(|k| {
                iss::digest_key(&k, &mut digest, &mut c2, &mut c3);
                c2.reset();
                c3.reset();
                iss::address(&mut digest, &mut c2);
                c2.reset();

                digest[0..iss::ADDRESS_LENGTH].to_vec()
            })
            .collect();
        let hashes = siblings(&addresses, 0, &mut c1);
        c1.reset();
        let expect = root(&addresses[0], &hashes, 0, &mut c1);
        for index in 0..count {
            c1.reset();
            let hashes = siblings(&addresses, index, &mut c1);
            c1.reset();
            let root = root(&addresses[index], &hashes, index, &mut c1);
            assert_eq!(trits_to_string(&root), trits_to_string(&expect));
        }*/
    }
}
