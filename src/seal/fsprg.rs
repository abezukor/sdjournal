use super::{FSPRG_RECOMMENDED_SECPAR, FSPRG_RECOMMENDED_SEEDLEN, RND_GEN_P, RND_GEN_Q, RND_GEN_X};
use crate::error::{Result, SdJournalError};
use num_bigint::{BigInt, BigUint};
use num_traits::{One as _, Signed as _, Zero as _};
use sha2::{Digest as _, Sha256};

#[derive(Debug)]
pub(crate) struct FsprgParams {
    p: BigUint,
    q: BigUint,
    n: BigUint,
    x0: BigUint,
    inv_p_mod_q: BigUint,
    n_bytes: usize,
}

impl FsprgParams {
    pub(crate) fn new(seed: &[u8; FSPRG_RECOMMENDED_SEEDLEN]) -> Result<Self> {
        let secpar = FSPRG_RECOMMENDED_SECPAR as usize;
        if !secpar.is_multiple_of(16) || !(16..=16384).contains(&secpar) {
            return Err(SdJournalError::Unsupported {
                reason: "unsupported FSPRG security parameter".to_string(),
            });
        }

        let half = secpar / 2;
        let p = genprime3mod4(half, seed, RND_GEN_P)?;
        let q = genprime3mod4(half, seed, RND_GEN_Q)?;

        let n = &p * &q;
        let n_bits = bit_length(&n);
        if n_bits != secpar {
            return Err(SdJournalError::Corrupt {
                path: None,
                offset: None,
                reason: format!(
                    "FSPRG modulus size mismatch (expected {secpar} bits, got {n_bits})"
                ),
            });
        }

        let x0 = gensquare(&n, seed, RND_GEN_X, secpar)?;
        let inv_p_mod_q = modinv(&p, &q).ok_or_else(|| SdJournalError::Corrupt {
            path: None,
            offset: None,
            reason: "FSPRG CRT inverse does not exist".to_string(),
        })?;

        Ok(Self {
            p,
            q,
            n,
            x0,
            inv_p_mod_q,
            n_bytes: secpar / 8,
        })
    }
}

#[derive(Debug)]
pub(super) struct FsprgState<'a> {
    params: &'a FsprgParams,
    epoch: u64,
    x: BigUint,
}

impl<'a> FsprgState<'a> {
    pub(super) fn new(params: &'a FsprgParams) -> Self {
        Self {
            params,
            epoch: 0,
            x: params.x0.clone(),
        }
    }

    pub(super) fn seek(&mut self, goal: u64) -> Result<()> {
        if goal == self.epoch {
            return Ok(());
        }
        if goal == self.epoch.saturating_add(1) {
            return self.evolve();
        }

        let xp0 = &self.params.x0 % &self.params.p;
        let xq0 = &self.params.x0 % &self.params.q;

        let kp = twopowmodphi(goal, &self.params.p);
        let kq = twopowmodphi(goal, &self.params.q);

        let xp = xp0.modpow(&kp, &self.params.p);
        let xq = xq0.modpow(&kq, &self.params.q);

        self.x = crt_compose(
            &xp,
            &xq,
            &self.params.p,
            &self.params.q,
            &self.params.inv_p_mod_q,
        )?;
        self.epoch = goal;

        Ok(())
    }

    pub(super) fn get_key(&self, keylen: usize, idx: u32) -> Vec<u8> {
        let mut seed = Vec::with_capacity(self.params.n_bytes * 2 + 8);
        seed.extend_from_slice(&to_be_padded(&self.params.n, self.params.n_bytes));
        seed.extend_from_slice(&to_be_padded(&self.x, self.params.n_bytes));
        seed.extend_from_slice(&self.epoch.to_be_bytes());

        let mut out = vec![0u8; keylen];
        det_randomize(&mut out, &seed, idx);
        out
    }

    fn evolve(&mut self) -> Result<()> {
        self.x = (&self.x * &self.x) % &self.params.n;
        self.epoch = self.epoch.saturating_add(1);
        Ok(())
    }
}

fn det_randomize(buf: &mut [u8], seed: &[u8], idx: u32) {
    let mut base = Sha256::new();
    base.update(seed);
    base.update(idx.to_be_bytes());

    let mut ctr = 0u32;
    let mut out = buf;
    while !out.is_empty() {
        let mut h = base.clone();
        h.update(ctr.to_be_bytes());
        let digest = h.finalize();
        let take = std::cmp::min(out.len(), digest.len());
        out[..take].copy_from_slice(&digest[..take]);
        out = &mut out[take..];
        ctr = ctr.wrapping_add(1);
    }
}

fn genprime3mod4(bits: usize, seed: &[u8], idx: u32) -> Result<BigUint> {
    if !bits.is_multiple_of(8) || bits == 0 {
        return Err(SdJournalError::Unsupported {
            reason: "unsupported prime size for FSPRG".to_string(),
        });
    }

    let len = bits / 8;
    let mut buf = vec![0u8; len];
    det_randomize(&mut buf, seed, idx);
    buf[0] |= 0xc0;
    buf[len - 1] |= 0x03;

    let mut p = BigUint::from_bytes_be(&buf);
    while !is_probable_prime(&p) {
        p += 4u8;
    }
    Ok(p)
}

fn gensquare(n: &BigUint, seed: &[u8], idx: u32, secpar: usize) -> Result<BigUint> {
    if !secpar.is_multiple_of(8) {
        return Err(SdJournalError::Unsupported {
            reason: "unsupported FSPRG security parameter".to_string(),
        });
    }

    let len = secpar / 8;
    let mut buf = vec![0u8; len];
    det_randomize(&mut buf, seed, idx);
    buf[0] &= 0x7f;

    let x = BigUint::from_bytes_be(&buf);
    if x >= *n {
        return Err(SdJournalError::Corrupt {
            path: None,
            offset: None,
            reason: "FSPRG seed produced x >= n".to_string(),
        });
    }

    Ok((&x * &x) % n)
}

fn twopowmodphi(epoch: u64, p: &BigUint) -> BigUint {
    let two: BigUint = BigUint::from(2u8);
    let phi = p - BigUint::one();
    two.modpow(&BigUint::from(epoch), &phi)
}

fn crt_compose(
    xp: &BigUint,
    xq: &BigUint,
    p: &BigUint,
    q: &BigUint,
    inv_p_mod_q: &BigUint,
) -> Result<BigUint> {
    let xp_mod_q = xp % q;
    let mut a = if xq >= &xp_mod_q {
        xq - &xp_mod_q
    } else {
        (xq + q) - &xp_mod_q
    };
    if a >= *q {
        a %= q;
    }

    a = (a * inv_p_mod_q) % q;
    Ok(p * a + xp)
}

fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = BigInt::from(m.clone());
    let mut new_r = BigInt::from(a.clone());

    while !new_r.is_zero() {
        let q = &r / &new_r;
        let next_t = &t - &q * &new_t;
        t = new_t;
        new_t = next_t;

        let next_r = &r - &q * &new_r;
        r = new_r;
        new_r = next_r;
    }

    if r != BigInt::one() {
        return None;
    }

    if t.is_negative() {
        t += BigInt::from(m.clone());
    }

    t.to_biguint()
}

fn bit_length(n: &BigUint) -> usize {
    let bytes = n.to_bytes_be();
    let Some((&first, rest)) = bytes.split_first() else {
        return 0;
    };
    let leading = first.leading_zeros() as usize;
    rest.len().saturating_add(1).saturating_mul(8) - leading
}

fn to_be_padded(n: &BigUint, len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    if bytes.len() >= len {
        if bytes.len() == len {
            return bytes;
        }
        return bytes[bytes.len() - len..].to_vec();
    }

    let mut out = vec![0u8; len];
    out[len - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn is_probable_prime(n: &BigUint) -> bool {
    let one: BigUint = BigUint::one();
    let two: BigUint = BigUint::from(2u8);
    let three: BigUint = BigUint::from(3u8);

    if n < &two {
        return false;
    }
    if n == &two || n == &three {
        return true;
    }
    if (n & &one).is_zero() {
        return false;
    }

    const SMALL_PRIMES: &[u32] = &[
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    ];
    for &p in SMALL_PRIMES {
        if (n % p).is_zero() {
            return false;
        }
    }

    miller_rabin(n, 32)
}

fn miller_rabin(n: &BigUint, rounds: usize) -> bool {
    let one: BigUint = BigUint::one();
    let two: BigUint = BigUint::from(2u8);

    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0u32;
    while (&d & &one).is_zero() {
        d >>= 1;
        s = s.saturating_add(1);
    }

    let n_bytes = n.to_bytes_be();
    for i in 0..rounds {
        let mut h = Sha256::new();
        h.update(&n_bytes);
        h.update((i as u32).to_be_bytes());
        let digest = h.finalize();

        let mut a = BigUint::from_bytes_be(&digest);
        if a >= n_minus_one {
            a %= &n_minus_one;
        }
        if a < two {
            a += &two;
        }

        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }

        let mut witness = true;
        for _ in 0..s.saturating_sub(1) {
            x = (&x * &x) % n;
            if x == n_minus_one {
                witness = false;
                break;
            }
            if x == one {
                return false;
            }
        }
        if witness {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::{
        FSPRG_RECOMMENDED_SEEDLEN, FsprgParams, FsprgState, genprime3mod4, gensquare, modinv,
    };
    use crate::seal::{HmacSha256, RND_GEN_P, RND_GEN_Q, RND_GEN_X};
    use crate::util::hex_encode;
    use hmac::{KeyInit as _, Mac as _};

    #[test]
    fn fsprg_random_seek_and_hmac_match_systemd_vectors() {
        // Fixed seed and epoch 0..3 vectors from systemd's libgcrypt/OpenSSL interop test:
        // https://github.com/systemd/systemd/blob/a7fc55f8654bef6a01c72ae7a6efa3357d1f344b/src/test/test-fsprg.c
        let expected_keys = [
            "cae42eba74554f104f72a43a0b00a0c8d88fa7118d562a72e4a8d269f9d8a0f1",
            "631d5211ed13a88e4ce0062ee6a3a1f67af1c41e18bf74e2522386561b0e787d",
            "3fb2b639e3544104f3485f50f78bd6e78e45c2eebfddfd83347a9a8af34dd4c6",
            "987629e227f00e2affc8fd3bcfcb9f6de980fe6ed9c04329c5535ff786333b70",
        ];
        let expected_tags = [
            "10a41419ecf19b6de5e3122b06ee5baca7110b7015fd47a4b9d745194bde925d",
            "75545b6afb30433b299458ee62d9622b6188edcec9951e829ed6d19023c69065",
            "2f8b64a421e87493a23a6aa90d7eb080ce7480b906aeec864c3299f9481f0cad",
            "399ef6c31eca02b26ae2a6470bb5b6af46d79913c607a88073357573fd035b3e",
        ];
        let seed = std::array::from_fn(|i| u8::try_from(i).unwrap());
        let params = FsprgParams::new(&seed).unwrap();
        let mut state = FsprgState::new(&params);

        // Include forward jumps, backward jumps, repeated seeks, and a single-step evolve.
        // Sequential seeks alone take the evolve fast path and never exercise CRT seeking.
        for epoch in [0usize, 3, 1, 2, 2, 0] {
            state.seek(epoch as u64).unwrap();
            assert_eq!(state.epoch, epoch as u64);
            let key = state.get_key(32, 0);
            assert_eq!(hex_encode(&key), expected_keys[epoch], "epoch {epoch}");

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(format!("dummy data: {epoch}, hoge hoge hoge hoge hoge").as_bytes());
            assert_eq!(
                hex_encode(&mac.finalize().into_bytes()),
                expected_tags[epoch],
                "epoch {epoch}"
            );
        }
    }

    #[test]
    fn fsprg_seek_matches_evolve_small_secpar() {
        let seed = [0x11u8; FSPRG_RECOMMENDED_SEEDLEN];

        let secpar = 128usize;
        let half = secpar / 2;
        let p = genprime3mod4(half, &seed, RND_GEN_P).unwrap();
        let q = genprime3mod4(half, &seed, RND_GEN_Q).unwrap();
        let n = &p * &q;
        let x0 = gensquare(&n, &seed, RND_GEN_X, secpar).unwrap();
        let inv = modinv(&p, &q).unwrap();
        let params = FsprgParams {
            p,
            q,
            n,
            x0,
            inv_p_mod_q: inv,
            n_bytes: secpar / 8,
        };

        let mut a = FsprgState::new(&params);
        let mut b = FsprgState::new(&params);

        for epoch in 0..32u64 {
            if epoch > 0 {
                a.evolve().unwrap();
            }
            b.seek(epoch).unwrap();
            assert_eq!(a.epoch, epoch);
            assert_eq!(b.epoch, epoch);
            assert_eq!(a.x, b.x);

            let ka = a.get_key(32, 0);
            let kb = b.get_key(32, 0);
            assert_eq!(ka, kb);
        }
    }
}
