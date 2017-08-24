use trytes::*;
use tmath::*;
use curl::*;
use sign::iss;
use core::mem;
use alloc::*;

pub fn key<C: Curl<Trit>>(
    seed: &[Trit],
    index: usize,
    security: u8,
    out: &mut [Trit],
    curl: &mut C,
) {
    let mut subseed = [0; HASH_LENGTH];

    subseed[0..HASH_LENGTH].clone_from_slice(&seed);
    for _ in 0..index {
        (&mut subseed[0..HASH_LENGTH]).incr();
    }

    iss::subseed::<C>(&subseed[0..HASH_LENGTH], 0, out, curl);
    curl.reset();
    iss::key::<Trit, C>(out, security, curl);
}

#[inline]
pub fn siblings_count(addr_count: usize) -> usize {
    let usize_size = mem::size_of::<usize>() * 8;
    // == ceil(log2(addrs.len()))
    usize_size - addr_count.leading_zeros() as usize
}

pub fn siblings<C: Curl<Trit>>(addrs: &[Trit], index: usize, out: &mut [Trit], curl: &mut C) {
    let hash_count = siblings_count(addrs.len() / HASH_LENGTH);

    assert_eq!(out.len(), hash_count * HASH_LENGTH);

    const EMPTY: &'static [Trit; 243] = &[0 as Trit; 243];

    #[inline]
    fn addr_idx(addrs: &[Trit], idx: usize) -> &[Trit] {
        if idx >= addrs.len() / HASH_LENGTH {
            EMPTY
        } else {
            &addrs[idx * HASH_LENGTH..(idx + 1) * HASH_LENGTH]
        }
    }

    #[inline]
    fn helper<C: Curl<Trit>>(
        rank: usize,
        idx: usize,
        addrs: &[Trit],
        space: &mut [Trit],
        curl: &mut C,
    ) {
        if idx * (1 << rank) > addrs.len() / HASH_LENGTH {
            space[rank * HASH_LENGTH..(rank + 1) * HASH_LENGTH].clone_from_slice(EMPTY);
        } else if rank == 0 {
            space[..HASH_LENGTH].clone_from_slice(addr_idx(addrs, idx));
        } else if rank == 1 {
            curl.absorb(addr_idx(addrs, idx * 2));
            curl.absorb(addr_idx(addrs, idx * 2 + 1));
            space[rank * HASH_LENGTH..(rank + 1) * HASH_LENGTH].clone_from_slice(curl.rate());
            curl.reset();
        } else {
            helper(
                rank - 1,
                idx * 2,
                addrs,
                &mut space[..rank * HASH_LENGTH],
                curl,
            );

            {
                let (a, b) = space.split_at_mut(rank * HASH_LENGTH);
                b.clone_from_slice(&a[(rank - 1) * HASH_LENGTH..]);
            }

            helper(
                rank - 1,
                idx * 2 + 1,
                addrs,
                &mut space[..rank * HASH_LENGTH],
                curl,
            );
            curl.absorb(&space[rank * HASH_LENGTH..]);
            curl.absorb(&space[(rank - 1) * HASH_LENGTH..rank * HASH_LENGTH]);
            space[rank * HASH_LENGTH..].clone_from_slice(curl.rate());
            curl.reset();
        }
    };

    for rank in (0..hash_count).rev() {
        let mut hash_index = index ^ 0x1;
        for _ in 0..rank {
            hash_index = (hash_index / 2) ^ 0x1;
        }

        helper(
            rank,
            hash_index,
            addrs,
            &mut out[..(rank + 1) * HASH_LENGTH],
            curl,
        );
    }
}

pub fn root<C: Curl<Trit>>(
    address: &[Trit],
    hashes: &[Trit],
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

    for hash in hashes.chunks(HASH_LENGTH) {
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
    fn correct_siblings() {
        let mut c1 = CpuCurl::<Trit>::default();
        let mut c2 = CpuCurl::<Trit>::default();
        let mut c3 = CpuCurl::<Trit>::default();

        let index = 4;
        let start = 3;
        let mut count = 11;
        let security = 1;

        let seed: Vec<Trit> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9\
                               ABCDEFGHIJKLMNOPQRSTUVWXYZ9\
                               ABCDEFGHIJKLMNOPQRSTUVWXYZ9"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();
        let mut digest = vec![0; iss::DIGEST_LENGTH];
        let mut key = [0 as Trit; iss::KEY_LENGTH];

        {
            let mut addresses: Vec<Trit> = Vec::with_capacity(count);
            for idx in start..start + count {
                super::key(&seed, idx, security, &mut key, &mut c1);
                iss::digest_key(&key, &mut digest, &mut c2, &mut c3);
                c2.reset();
                c3.reset();
                iss::address(&mut digest, &mut c2);
                c2.reset();
                addresses.extend(&digest[0..iss::ADDRESS_LENGTH]);
            }
            c1.reset();

            let mut hashes =
                vec![0 as Trit; siblings_count(addresses.len() / HASH_LENGTH) * HASH_LENGTH];
            siblings(&addresses, index, &mut hashes, &mut c1);

            let ex_hashes = vec![
                "SLCYEUY9MAFEWLCWF9LTZNPYAIGIXGJKDSFGEAZDCVOUCSLSGVZOYIHUTW9VUCE9VJXCQLGZIRDHKLHIE",
                "FFUBQXBR9FUVBVNTSZKKO9JNJHZFOEZZVJSDUIIQJUGXFZWXFWBQO9CYRIARXFOSNUPGCKUCRKAIKGOWC",
                "EDWVZSBDW9RPNICLFWSEEFASNIAWUHDWWQSHMMACGGCFIBVEEFJAAWHIEVAE9XNODNFUGFLDFESOINSEJ",
                "EZQAGTTPSS9IRNYRBEXAPWMTQTPUKNQ9IUGFWVMJCKYYAFWWSMWNUCKENSBQLQFDMOEBVVXPPGCLXJYXQ",
            ];
            let out_hashes: Vec<String> = hashes
                .chunks(HASH_LENGTH)
                .map(|h| trits_to_string(h).unwrap())
                .collect();
            assert_eq!(&ex_hashes, &out_hashes);
        }

        count = 17;
        {
            let addresses: Vec<Trit> = (start..(start + count))
                .map(|idx| {
                    super::key(&seed, idx, security, &mut key, &mut c1);
                    iss::digest_key(&key, &mut digest, &mut c2, &mut c3);
                    c2.reset();
                    c3.reset();
                    iss::address(&mut digest, &mut c2);
                    c2.reset();

                    digest[0..iss::ADDRESS_LENGTH].to_vec()
                })
                .fold(Vec::with_capacity(count * HASH_LENGTH), |mut acc, x| {
                    acc.extend(x);
                    acc
                });

            c1.reset();
            let mut hashes =
                vec![0 as Trit; siblings_count(addresses.len() / HASH_LENGTH) * HASH_LENGTH];
            siblings(&addresses, 0, &mut hashes, &mut c1);

            let ex_hashes = vec![
                "YZWDXCFFFFUIRNOZSNQEIQPVIIKRUNNONBWOJQBAJYNWFFEP9BGWF9OCUPHDHIXCY9IYW9LTKIVFZUOWF",
                "HTCECMIQNWZJFCLHZ9VUJLPBMK99QIKOIZDUIEWOMJKKGT9NHNOGXCTIXOLQEV99XHAKPHCRTVFBLMNDP",
                "N9VWIEOYEJILHRFLZHZETQSXJPULQYHLRQTPZGZZFBHGKENRKAIIZEATOCHLNAZEWRFCUPVLHEMGGSVZZ",
                "XALVXVGTHVKNSHLCKBTNYPYDTSGJUESBHXPPNTEZWLBPQDSTNOJHVZT99GSDJY9LNRWEWWLQQPOKQYRKD",
                "IHTWSNXCMGYBVQYDLPENCHOVCZOBGNXYJJKQOHZOSLYSHIVNPVDERZFNYBXYGGXCKSOIFL9BQLJPXEPSK",
            ];
            let out_hashes: Vec<String> = hashes
                .chunks(HASH_LENGTH)
                .map(|h| trits_to_string(h).unwrap())
                .collect();
            assert_eq!(&ex_hashes, &out_hashes);
        }
    }
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
