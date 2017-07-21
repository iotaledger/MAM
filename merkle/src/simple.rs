use trytes::*;
use tmath::*;
use curl::*;
use curl_cpu::*;
use sign::iss;
use core::mem;
use alloc::*;

pub fn keys(seed: &[Trit], start: usize, count: usize, security: u8) -> Vec<Vec<Trit>> {
    let mut trits: Vec<Trit> = seed.to_vec();
    for _ in 0..start {
        trits.as_mut_slice().incr();
    }
    let mut out: Vec<Vec<Trit>> = Vec::with_capacity(count);
    for _ in 0..count {
        let subseed = iss::subseed::<CpuCurl<Trit>>(&trits, 0);
        trits.as_mut_slice().incr();
        out.push(iss::key::<Trit, CpuCurl<Trit>>(&subseed, security));
    }
    out
}

pub fn siblings(addrs: &[Vec<Trit>], index: usize) -> Vec<Vec<Trit>> {
    let usize_size = mem::size_of::<usize>() * 8;
    let hash_count = usize_size - index.leading_zeros() as usize;
    let mut out: Vec<Vec<Trit>> = Vec::with_capacity(hash_count);
    let mut curl = CpuCurl::<Trit>::default();
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

pub fn root(address: &[Trit], hashes: &[Vec<Trit>], index: usize) -> Vec<Trit> {
    let mut curl = CpuCurl::<Trit>::default();
    let mut i = 1;
    hashes.into_iter().fold(address.to_vec(), |acc, hash| {
        curl.reset();
        if i & index == 0 {
            curl.absorb(&acc);
            curl.absorb(&hash);
        } else {
            curl.absorb(&hash);
            curl.absorb(&acc);
        }
        i <<= 1;
        curl.rate().to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sign::iss;
    #[test]
    fn it_does_not_panic() {
        let seed: Vec<Trit> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9\
                             ABCDEFGHIJKLMNOPQRSTUVWXYZ9\
                             ABCDEFGHIJKLMNOPQRSTUVWXYZ9"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();

        let start = 1;
        let count = 9;
        let security = 1;
        let keys = keys(&seed, start, count, security);
        let addresses: Vec<Vec<Trit>> = keys.iter()
            .map(|k| {
                iss::address::<Trit, CpuCurl<Trit>>(
                    &iss::digest_key::<Trit, CpuCurl<Trit>>(&k.as_slice()),
                )
            })
            .collect();
        let hashes = siblings(&addresses, 0);
        let expect = root(&addresses[0], &hashes, 0);
        for index in 0..count {
            let hashes = siblings(&addresses, index);
            let root = root(&addresses[index], &hashes, index);
            assert_eq!(trits_to_string(&root), trits_to_string(&expect));
        }
    }
}
