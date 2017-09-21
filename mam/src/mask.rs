use trytes::*;
use tmath::*;
use curl::*;

pub fn mask<C>(payload: &mut [Trit], key: &[Trit], curl: &mut C)
where
    C: Curl<Trit>,
{
    curl.absorb(key);
    let mut key_chunk: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    curl.squeeze(&mut key_chunk);
    for chunk in payload.chunks_mut(HASH_LENGTH) {
        let len = chunk.len();
        for i in 0..len {
            key_chunk[i] = trit_sum(chunk[i], key_chunk[i]);
        }
        curl.absorb(chunk);
        chunk.clone_from_slice(&key_chunk[..len]);
        key_chunk[..len].clone_from_slice(&curl.rate()[..len]);
    }
}
pub fn unmask<C>(payload: &mut [Trit], key: &[Trit], curl: &mut C)
where
    C: Curl<Trit>,
{
    curl.absorb(key);
    let mut key_chunk: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    curl.squeeze(&mut key_chunk);
    for chunk in payload.chunks_mut(HASH_LENGTH) {
        let len = chunk.len();
        for i in 0..len {
            key_chunk[i] = trit_sum(chunk[i], -key_chunk[i]);
        }

        chunk.clone_from_slice(&key_chunk[..len]);
        curl.absorb(&key_chunk[..len]);
        key_chunk[..len].clone_from_slice(&curl.rate()[..len]);
    }
}
pub fn mask_slice<C>(payload: &mut [Trit], curl: &mut C)
where
    C: Curl<Trit>,
{
    let mut key_chunk: [Trit; HASH_LENGTH] = [0; HASH_LENGTH];
    key_chunk.clone_from_slice(curl.rate());
    for chunk in payload.chunks_mut(HASH_LENGTH) {
        curl.absorb(chunk);
        let len = chunk.len();
        for i in 0..len {
            chunk[i] = trit_sum(chunk[i], key_chunk[i]);
        }
        key_chunk[..len].clone_from_slice(&curl.rate()[..len]);
    }
}

pub fn unmask_slice<C>(payload: &mut [Trit], curl: &mut C)
where
    C: Curl<Trit>,
{
    for chunk in payload.chunks_mut(HASH_LENGTH) {
        for i in 0..chunk.len() {
            chunk[i] = trit_sum(chunk[i], -curl.rate()[i]);
        }
        curl.absorb(&chunk);
    }
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
        let index: usize = 5;
        let mut curl = CpuCurl::<Trit>::default();
        let mut keys: Vec<Trit> = auth_id.clone(); // vec![&auth_id, &index];
        add_assign(&mut keys, index as isize);
        let mut cipher = payload.clone();
        mask::<CpuCurl<Trit>>(&mut cipher, &keys, &mut curl);
        curl.reset();
        unmask::<CpuCurl<Trit>>(&mut cipher, &keys, &mut curl);
        assert_eq!(trits_to_string(&payload), trits_to_string(&cipher));
    }
}
