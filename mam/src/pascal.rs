use core::iter;

use alloc::*;
use trytes::constants::*;
use trytes::num;

const ENCODER_MASK: isize = 7;

pub fn decode(input: &[Trit]) -> (usize, usize) {
    let mut positive: Vec<Trit> = Vec::with_capacity(TRITS_PER_TRYTE);
    let negative: Vec<Trit> = input
        .chunks(TRITS_PER_TRYTE)
        .take_while(|tryte| {
            let val = num::trits2int(tryte);
            if val.is_positive() {
                positive.extend_from_slice(*tryte);
                false
            } else {
                true
            }
        })
        .flat_map(|t| t.to_vec())
        .collect();
    let encoders_start = negative.len() + positive.len();
    let num_encoder_pairs = {
        let num_negative_trytes = negative.len() / 3;
        num_negative_trytes / 3 + if num_negative_trytes % 3 == 0 { 0 } else { 1 }
    };
    let encoders: Vec<isize> = input[encoders_start..]
        .chunks(2)
        .take(num_encoder_pairs)
        .map(num::trits2int)
        .collect();
    let corrected_negatives: Vec<Trit> = negative
        .chunks(TRITS_PER_TRYTE.pow(2))
        .zip(encoders.iter())
        .flat_map(|(trytes, e)| {
            let mut i = 0;
            let encoder = *e + TRITS_PER_TRYTE as isize;
            let mut trytes_out: Vec<Trit> = Vec::with_capacity(trytes.len());
            for tryte in trytes.chunks(TRITS_PER_TRYTE) {
                if ((encoder >> i) & 1isize) != 0isize {
                    let mut neg: Vec<Trit> = tryte.iter().map(|trit| -trit).collect();
                    trytes_out.append(&mut neg);
                } else {
                    trytes_out.extend_from_slice(tryte)
                };
                i += 1;
            }
            trytes_out.into_iter()
        })
        .chain(positive.into_iter())
        .collect();
    (
        num::trits2int(&corrected_negatives) as usize,
        encoders_start + num::round_third(num_encoder_pairs * 2),
    )
}

pub fn encoded_length(input: usize) -> usize {
    let length = num::round_third(num::min_trits(input as isize) as usize);
    let negative_length = (length - TRITS_PER_TRYTE) / TRITS_PER_TRYTE;
    let triplet_count = negative_length / TRITS_PER_TRYTE +
        if negative_length % TRITS_PER_TRYTE == 0 {
            0
        } else {
            1
        };
    let encoder_trit_count = triplet_count * 2;
    length + encoder_trit_count
}

pub fn encode(input: usize) -> Vec<Trit> {
    let length = num::round_third(num::min_trits(input as isize) as usize) as u8;
    let negative_length = (length as usize - TRITS_PER_TRYTE) / TRITS_PER_TRYTE;
    let triplet_count = negative_length / TRITS_PER_TRYTE +
        if negative_length % TRITS_PER_TRYTE == 0 {
            0
        } else {
            1
        };
    let encoder_trit_count = triplet_count * 2;
    let encoder_trits_size = num::round_third(encoder_trit_count);
    let mut encoding = 0;
    let mut trits: Vec<Trit> = {
        let mut myvec = vec![0; length as usize];
        num::int2trits(input as isize, &mut myvec);

        {
            let delta = myvec.capacity() - myvec.len();
            if delta != 0 {
                myvec.append(&mut iter::repeat(0 as Trit).take(delta).collect());
            }
        }

        let mut index = 0;
        myvec
            .chunks(TRITS_PER_TRYTE)
            .map(|c| {
                let val = num::trits2int(c);
                let out = if val.is_positive() && index < negative_length {
                    encoding |= 1 << index;
                    c.iter().map(|t| -t).collect()
                } else {
                    c.to_vec()
                };
                index += 1;
                out
            })
            .fold(
                Vec::with_capacity(length as usize + encoder_trits_size),
                |mut acc, mut v| {
                    acc.append(&mut v);
                    acc
                },
            )
    };
    trits.extend({
        let mut out: Vec<Trit> = (0..triplet_count)
            .into_iter()
            .map(|i| {
                let j = i * 3;
                let val = ((encoding >> j) & ENCODER_MASK) as isize - TRITS_PER_TRYTE as isize;
                let mut res = vec![0; 2];
                num::int2trits(val, &mut res);
                res
            })
            .fold(Vec::with_capacity(encoder_trits_size), |mut acc, mut v| {
                acc.append(&mut v);
                acc
            });

        let delta = out.capacity() - out.len();

        if delta != 0 {
            let mut add: Vec<Trit> = iter::repeat(0 as Trit).take(delta).collect();
            out.append(&mut add);
        }
        out
    });
    trits
}

#[cfg(test)]
mod tests {
    use super::*;
    use trytes::num;
    use trytes::string::*;

    #[test]
    fn from_encoder_trytes() {
        let num_trytes: Vec<Trit> = "ABXDEFG".chars().flat_map(char_to_trits).cloned().collect();
        let num_val = num::trits2int(&num_trytes) as usize;
        let length = encode(num_val);
        let expect_trytes: Vec<Trit> = "ZYXWVUGIA"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();

        assert_eq!(expect_trytes, length);
        let (val, end) = decode(&length);
        assert_eq!(val, num_val);
        assert_eq!(end, expect_trytes.len());
    }
}
