//! BLAKE2s and HMAC-BLAKE2s, sized for the handful of cold call sites that
//! use them: key derivation, handshake transcripts, announce proofs and
//! admission cookies.

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// A BLAKE2s hash in progress, optionally keyed, with an output length of
/// 1 to 32 bytes.
pub struct Blake2s {
    h: [u32; 8],
    t: u64,
    buf: [u8; 64],
    len: usize,
}

impl Blake2s {
    pub fn new(outlen: usize, key: &[u8]) -> Self {
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ outlen as u32;
        let mut s = Blake2s {
            h,
            t: 0,
            buf: [0; 64],
            len: 0,
        };
        if !key.is_empty() {
            s.buf[..key.len()].copy_from_slice(key);
            s.len = 64;
        }
        s
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.len == 64 {
                self.t += 64;
                compress(&mut self.h, &self.buf, self.t, false);
                self.len = 0;
            }
            let n = data.len().min(64 - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
        }
    }

    /// The final state; the digest is its first `outlen` bytes.
    pub fn finalize(mut self) -> [u8; 32] {
        self.t += self.len as u64;
        self.buf[self.len..].fill(0);
        compress(&mut self.h, &self.buf, self.t, true);
        let mut out = [0u8; 32];
        for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.h) {
            *o = w.to_le_bytes();
        }
        out
    }
}

#[inline(never)]
fn compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for (w, b) in m.iter_mut().zip(block.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*b);
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
    }
    macro_rules! g {
        ($a:literal, $b:literal, $c:literal, $d:literal, $x:expr, $y:expr) => {
            v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($x);
            v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
            v[$c] = v[$c].wrapping_add(v[$d]);
            v[$b] = (v[$b] ^ v[$c]).rotate_right(12);
            v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($y);
            v[$d] = (v[$d] ^ v[$a]).rotate_right(8);
            v[$c] = v[$c].wrapping_add(v[$d]);
            v[$b] = (v[$b] ^ v[$c]).rotate_right(7);
        };
    }
    macro_rules! round {
        ($($i:literal),*) => { round_words!([$($i),*]) };
    }
    macro_rules! round_words {
        ([$m0:literal, $m1:literal, $m2:literal, $m3:literal, $m4:literal, $m5:literal, $m6:literal, $m7:literal,
          $m8:literal, $m9:literal, $m10:literal, $m11:literal, $m12:literal, $m13:literal, $m14:literal, $m15:literal]) => {
            g!(0, 4, 8, 12, m[$m0], m[$m1]);
            g!(1, 5, 9, 13, m[$m2], m[$m3]);
            g!(2, 6, 10, 14, m[$m4], m[$m5]);
            g!(3, 7, 11, 15, m[$m6], m[$m7]);
            g!(0, 5, 10, 15, m[$m8], m[$m9]);
            g!(1, 6, 11, 12, m[$m10], m[$m11]);
            g!(2, 7, 8, 13, m[$m12], m[$m13]);
            g!(3, 4, 9, 14, m[$m14], m[$m15]);
        };
    }
    round!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    round!(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    round!(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    round!(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    round!(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    round!(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    round!(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    round!(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    round!(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    round!(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2s-256 over the concatenation of `parts`.
pub fn blake2s(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s::new(32, &[]);
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// HMAC-BLAKE2s over the concatenation of `parts`.
pub fn hmac_blake2s(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let hashed;
    let key = if key.len() > 64 {
        hashed = blake2s(&[key]);
        &hashed[..]
    } else {
        key
    };
    let mut pad = [0x36u8; 64];
    for (p, k) in pad.iter_mut().zip(key) {
        *p ^= k;
    }
    let mut inner = Blake2s::new(32, &[]);
    inner.update(&pad);
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    for p in pad.iter_mut() {
        *p ^= 0x36 ^ 0x5c;
    }
    blake2s(&[&pad, &inner])
}

/// Whether `a` and `b` are equal, in time that depends on their length alone.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= std::hint::black_box(x ^ y);
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::digest::Mac;
    use blake2::Digest;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Deterministic pseudo-random bytes for the equivalence tests.
    fn junk(seed: u32, len: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    #[test]
    fn blake2s_rfc7693_vector() {
        assert_eq!(
            hex(&blake2s(&[b"abc"])),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
    }

    #[test]
    fn blake2s_matches_the_crate_across_lengths_and_keys() {
        for len in (0..200).chain([255, 256, 257, 1000, 4096]) {
            let data = junk(len as u32, len);
            assert_eq!(
                blake2s(&[&data]),
                <[u8; 32]>::from(blake2::Blake2s256::digest(&data)),
                "len {len}"
            );
            let split = len / 3;
            assert_eq!(
                blake2s(&[&data[..split], &data[split..]]),
                blake2s(&[&data]),
                "split {len}"
            );
            let key = junk(len as u32 + 7, 32);
            let mut mac =
                <blake2::Blake2sMac<blake2::digest::consts::U16> as Mac>::new_from_slice(&key)
                    .unwrap();
            mac.update(&data);
            let want: [u8; 16] = mac.finalize().into_bytes().into();
            let mut h = Blake2s::new(16, &key);
            h.update(&data);
            assert_eq!(h.finalize()[..16], want, "keyed {len}");
        }
    }

    #[test]
    fn hmac_matches_the_crate() {
        for (klen, len) in [
            (0, 0),
            (1, 1),
            (32, 0),
            (32, 33),
            (63, 100),
            (64, 64),
            (65, 5),
            (200, 300),
        ] {
            let key = junk(klen as u32, klen);
            let data = junk(len as u32 + 99, len);
            let mut mac =
                <hmac::SimpleHmac<blake2::Blake2s256> as Mac>::new_from_slice(&key).unwrap();
            mac.update(&data);
            let want: [u8; 32] = mac.finalize().into_bytes().into();
            assert_eq!(hmac_blake2s(&key, &[&data]), want, "key {klen} data {len}");
            let split = len / 2;
            assert_eq!(hmac_blake2s(&key, &[&data[..split], &data[split..]]), want);
        }
    }

    #[test]
    fn ct_eq_compares_whole_slices() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }
}
