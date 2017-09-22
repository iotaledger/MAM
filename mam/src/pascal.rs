use trytes::constants::*;
use trytes::num;

const ENCODER_MASK: isize = 7;
const TRITS_PER_PAIR: usize = 2;
const ZERO: [Trit; 5] = [1, 0, 0, -1, -1];

fn end(trits: &[Trit]) -> usize {
    if num::trits2int(&trits[..TRITS_PER_TRYTE]).is_positive() {
        TRITS_PER_TRYTE
    } else {
        TRITS_PER_TRYTE + end(&trits[TRITS_PER_TRYTE..])
    }
}

pub fn decode(input: &[Trit]) -> (isize, usize) {
    if &input[..5] == &ZERO {
        (0, 5)
    } else {
        let encoders_start = end(input);
        let num_encoder_pairs = {
            let num_negative_trytes = encoders_start / TRITS_PER_TRYTE;
            num_negative_trytes / TRITS_PER_TRYTE +
                if num_negative_trytes % TRITS_PER_TRYTE == 0 {
                    0
                } else {
                    1
                }
        };
        let mut i = 0;
        (
            input[encoders_start..]
                .chunks(TRITS_PER_PAIR)
                .take(num_encoder_pairs)
                .map(num::trits2int)
                .zip(input[..encoders_start].chunks(9))
                .fold(0, |acc, (e, trytes)| {
                    let encoder = e + TRITS_PER_TRYTE as isize;
                    trytes.chunks(TRITS_PER_TRYTE).fold(acc, |out, tryte| {
                        let ret = out as isize +
                            27isize.pow(i) * num::trits2int(tryte) *
                                if ((encoder >> i) & 1isize) != 0isize {
                                    -1
                                } else {
                                    1
                                };
                        i += 1;
                        ret
                    })
                }),
            encoders_start + num_encoder_pairs * TRITS_PER_PAIR,
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

fn write_trits(input: usize, out: &mut [Trit]) -> usize {
    match input {
        0 => 0,
        _ => {
            let mut abs = input / RADIX as usize;
            out[0] = {
                let mut r = input as isize % RADIX as isize;
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
    let end = write_trits(input.abs() as usize, out);
    if input.is_negative() {
        for t in out.iter_mut() {
            *t = -*t;
        }
    }
    end
}

fn trit_count(length: usize) -> usize {
    match length {
        0 => 1,
        _ => length / TRITS_PER_TRYTE + if length % TRITS_PER_TRYTE == 0 { 0 } else { 1 },
    }

}

fn number_of_flipped_trytes(input: isize, length: usize) -> usize {
    (length -
         if input.is_negative() {
             0
         } else {
             TRITS_PER_TRYTE
         })
}

pub fn encoded_length(input: isize) -> usize {
    if input == 0 {
        ZERO.len()
    } else {
        let length = num::round_third(pascal_min_trits(input.abs() as usize));
        length + trit_count(length / TRITS_PER_TRYTE) * TRITS_PER_PAIR
    }
}

pub fn encode(input: isize, out: &mut [Trit]) {
    if input == 0 {
        out.clone_from_slice(&ZERO);
    } else {
        let length = num::round_third(pascal_min_trits(input.abs() as usize));
        let mut encoding = 0;
        int2trits(input, out);
        let mut index = 0;
        for c in out[..number_of_flipped_trytes(input, length)].chunks_mut(TRITS_PER_TRYTE) {
            if num::trits2int(c).is_positive() {
                encoding |= 1 << index;
                for t in c.iter_mut() {
                    *t = -*t;
                }
            }
            index += 1;
        }
        for (i, res) in out[length..
                                length + trit_count(length / TRITS_PER_TRYTE) * TRITS_PER_PAIR]
            .chunks_mut(TRITS_PER_PAIR)
            .enumerate()
        {
            int2trits(
                ((encoding >> (i * 3)) & ENCODER_MASK) as isize - TRITS_PER_TRYTE as isize,
                res,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    //use trytes::num;

    #[test]
    fn encode_numbers() {
        for i in 0..100000 {
            //isize::max_value() / 2 {
            let mut e: Vec<Trit> = vec![0; encoded_length(i)];
            encode(i, &mut e);
            //println!("i:{} - {:?}", i, e);
            let d = decode(&e);
            assert_eq!(i, d.0, "Output should match for {}", i);
            assert_eq!(e.len(), d.1, "Length should match for {}", e.len());
        }
    }
}
