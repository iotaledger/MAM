use trytes::*;
use tmath::*;
use curl::*;
use alloc::Vec;

pub fn mask<C>(payload: &[Trit], keys: &[Vec<Trit>], curl: &mut C) -> Vec<Trit>
where
    C: Curl<Trit>,
{
    let mut out: Vec<Trit> = Vec::with_capacity(payload.len());
    for key in keys {
        curl.absorb(&key);
    }
    let mut key_chunk: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    curl.squeeze(&mut key_chunk);
    for chunk in payload.chunks(HASH_LENGTH) {
        let len = chunk.len();
        for i in 0..len {
            key_chunk[i] = trit_sum(chunk[i], key_chunk[i]);
        }
        out.extend_from_slice(&key_chunk[..len]);
        curl.duplex(&chunk, &mut key_chunk);
    }
    out
}

pub fn unmask<C>(payload: &[Trit], keys: &[Vec<Trit>], curl: &mut C) -> Vec<Trit>
where
    C: Curl<Trit>,
{
    let mut out: Vec<Trit> = Vec::with_capacity(payload.len());
    for key in keys {
        curl.absorb(&key);
    }

    let mut key_chunk: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    curl.squeeze(&mut key_chunk);
    for chunk in payload.chunks(HASH_LENGTH) {
        let len = chunk.len();
        for i in 0..len {
            key_chunk[i] = trit_sum(chunk[i], -key_chunk[i]);
        }

        out.extend_from_slice(&key_chunk[..len]);
        curl.absorb(&key_chunk[..len]);
        key_chunk[..len].clone_from_slice(&curl.rate()[..len]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use curl_cpu::*;
    use alloc::Vec;
    use alloc::*;
    #[test]
    fn it_can_unmask() {
        let payload: Vec<Trit> = "AAMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9AMESSAGEFORYOU9MESSAGEFORYOU9"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();
        let auth_id: Vec<Trit> = "MYMERKLEROOTHASH"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();
        let index: Vec<Trit> = "AEOWJID999999"
            .chars()
            .flat_map(char_to_trits)
            .cloned()
            .collect();
        let mut curl = CpuCurl::<Trit>::default();
        let keys: Vec<Vec<Trit>> = vec![auth_id, index];
        let cipher = mask::<CpuCurl<Trit>>(&payload, &keys, &mut curl);
        curl.reset();
        let plain: Vec<Trit> = unmask::<CpuCurl<Trit>>(&cipher.clone(), &keys, &mut curl);
        assert_eq!(trits_to_string(&payload), trits_to_string(&plain));
    }
}
