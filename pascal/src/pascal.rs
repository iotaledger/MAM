use trytes::constants::*;
use trytes::num;

const ZERO: [Trit; 4] = [1, 0, 0, -1];

fn end(trits: &[Trit]) -> usize {
    if num::trits2int(&trits[..TRITS_PER_TRYTE]).is_positive() {
        TRITS_PER_TRYTE
    } else {
        TRITS_PER_TRYTE + end(&trits[TRITS_PER_TRYTE..])
    }
}

pub fn decode(input: &[Trit]) -> (isize, usize) {
    if &input[..4] == &ZERO {
        (0, 4)
    } else {
        let encoders_start = end(input);
        let input_end = encoders_start +
            pascal_min_trits(2usize.pow((encoders_start / TRITS_PER_TRYTE) as u32) - 1);
        let encoder = num::trits2int(&input[encoders_start..input_end]) as isize;
        (
            input[..encoders_start]
                .chunks(TRITS_PER_TRYTE)
                .enumerate()
                .fold(0, |acc, (i, tryte)| {
                    acc +
                        27_isize.pow(i as u32) *
                            if ((encoder >> i) & 1_isize) != 0_isize {
                                (-num::trits2int(tryte)) as isize
                            } else {
                                num::trits2int(tryte) as isize
                            }
                }),
            input_end,
        )
    }
}

fn min_trits_helper(input: usize, base: usize) -> usize {
    if input <= base {
        1
    } else {
        1 + min_trits_helper(input, 1 + base * RADIX as usize)
    }
}

fn pascal_min_trits(input: usize) -> usize {
    min_trits_helper(input, 1)
}

fn write_trits(input: isize, out: &mut [Trit]) -> usize {
    match input {
        0 => 0,
        _ => {
            let mut abs = input / RADIX as isize;
            out[0] = {
                let mut r = input % RADIX as isize;
                if r > 1 {
                    abs += 1;
                    r = -1;
                }
                r as Trit
            };
            1 + write_trits(abs, &mut out[1..])
        }
    }
}

fn int2trits(input: isize, out: &mut [Trit]) -> usize {
    let end = write_trits(input.abs(), out);
    if input.is_negative() {
        for t in out.iter_mut() {
            *t = -*t;
        }
    }
    end
}

pub fn encoded_length(input: isize) -> usize {
    if input == 0 {
        ZERO.len()
    } else {
        let length = num::round_third(pascal_min_trits(input.abs() as usize) as i64) as usize;
        length + pascal_min_trits(2usize.pow((length / TRITS_PER_TRYTE) as u32) - 1)
    }
}

pub fn encode(input: isize, out: &mut [Trit]) {
    if input == 0 {
        out.clone_from_slice(&ZERO);
    } else {
        let length = num::round_third(pascal_min_trits(input.abs() as usize) as i64) as usize;
        let mut encoding = 0;
        int2trits(input, out);
        let mut index = 0;
        for c in out[..length - TRITS_PER_TRYTE].chunks_mut(TRITS_PER_TRYTE) {
            if num::trits2int(c).is_positive() {
                encoding |= 1 << index;
                for t in c.iter_mut() {
                    *t = -*t;
                }
            }
            index += 1;
        }
        if num::trits2int(&out[length - TRITS_PER_TRYTE..length]).is_negative() {
            encoding |= 1 << index;
            for t in out[length - TRITS_PER_TRYTE..length].iter_mut() {
                *t = -*t;
            }
        }
        int2trits(encoding, &mut out[length..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::Vec;

    fn test_encoding(i: isize) {
        let mut e: Vec<Trit> = vec![0; encoded_length(i)];
        encode(i, &mut e);
        let d = decode(&e);
        assert_eq!(i, d.0, "Output should match for {}, {:?}", i, e);
        assert_eq!(e.len(), d.1, "Length should match for {}", e.len());
    }
    #[test]
    fn encode_numbers() {
        for i in 0..1000 {
            test_encoding(-i);
        }
        for i in 0..1000 {
            test_encoding(i);
        }
        for i in 10000000..10000100 {
            test_encoding(i);
        }
        for i in 10000000..10000100 {
            test_encoding(-i);
        }
    }
}
