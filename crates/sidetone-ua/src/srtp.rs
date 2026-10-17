//! SRTP (RFC 3711) with SDES keys (RFC 4568): AES_CM_128_HMAC_SHA1_80 and
//! AES_CM_128_HMAC_SHA1_32. RTP only; SRTCP is not sent.

use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    Sha80,
    Sha32,
}

impl Suite {
    pub fn name(self) -> &'static str {
        match self {
            Suite::Sha80 => "AES_CM_128_HMAC_SHA1_80",
            Suite::Sha32 => "AES_CM_128_HMAC_SHA1_32",
        }
    }
    fn tag_len(self) -> usize {
        match self {
            Suite::Sha80 => 10,
            Suite::Sha32 => 4,
        }
    }
    pub fn parse(s: &str) -> Option<Suite> {
        match s {
            "AES_CM_128_HMAC_SHA1_80" => Some(Suite::Sha80),
            "AES_CM_128_HMAC_SHA1_32" => Some(Suite::Sha32),
            _ => None,
        }
    }
}

/// Master key (16 bytes) and salt (14 bytes) as carried in a=crypto.
#[derive(Clone)]
pub struct KeyMaterial {
    pub suite: Suite,
    pub key: [u8; 16],
    pub salt: [u8; 14],
}

impl KeyMaterial {
    pub fn random(suite: Suite) -> KeyMaterial {
        let h = crate::ua::rand_hex(60);
        let b: Vec<u8> = (0..30)
            .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(i as u8))
            .collect();
        let mut key = [0u8; 16];
        let mut salt = [0u8; 14];
        key.copy_from_slice(&b[..16]);
        salt.copy_from_slice(&b[16..30]);
        KeyMaterial { suite, key, salt }
    }

    /// "a=crypto:<tag> <suite> inline:<base64>" value (without "a=crypto:").
    pub fn sdp(&self, tag: u32) -> String {
        let mut b = self.key.to_vec();
        b.extend_from_slice(&self.salt);
        format!(
            "{tag} {} inline:{}",
            self.suite.name(),
            base64::engine::general_purpose::STANDARD.encode(b)
        )
    }

    /// Parses the value of an a=crypto line: (tag, keys).
    pub fn parse_sdp(v: &str) -> Option<(u32, KeyMaterial)> {
        let v = v
            .trim()
            .trim_start_matches("a=crypto:")
            .trim_start_matches("crypto:");
        let mut it = v.split_whitespace();
        let tag = it.next()?.parse().ok()?;
        let suite = Suite::parse(it.next()?)?;
        let params = it.next()?;
        let inline = params.strip_prefix("inline:")?;
        let b64 = inline.split('|').next()?;
        let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        if raw.len() < 30 {
            return None;
        }
        let mut key = [0u8; 16];
        let mut salt = [0u8; 14];
        key.copy_from_slice(&raw[..16]);
        salt.copy_from_slice(&raw[16..30]);
        Some((tag, KeyMaterial { suite, key, salt }))
    }
}

/// Session keys and rollover state for one direction.
pub struct Context {
    suite: Suite,
    enc: [u8; 16],
    auth: [u8; 20],
    salt: [u8; 14],
    roc: u32,
    last_seq: Option<u16>,
}

/// AES-CM key derivation (RFC 3711 4.3.1, key derivation rate 0).
fn derive(km: &KeyMaterial, label: u8, out: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&km.salt);
    iv[7] ^= label;
    let cipher = aes::Aes128::new(&km.key.into());
    for (counter, chunk) in out.chunks_mut(16).enumerate() {
        let mut block = iv;
        block[14..].copy_from_slice(&(counter as u16).to_be_bytes());
        let mut b = aes::Block::from(block);
        cipher.encrypt_block(&mut b);
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

impl Context {
    pub fn new(km: &KeyMaterial) -> Context {
        let mut enc = [0u8; 16];
        let mut auth = [0u8; 20];
        let mut salt = [0u8; 14];
        derive(km, 0, &mut enc);
        derive(km, 1, &mut auth);
        derive(km, 2, &mut salt);
        Context {
            suite: km.suite,
            enc,
            auth,
            salt,
            roc: 0,
            last_seq: None,
        }
    }

    fn keystream_xor(&self, ssrc: u32, index: u64, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
            iv[4 + i] ^= b;
        }
        let idx = index.to_be_bytes(); // 8 bytes, the 48-bit index in the low 6
        for i in 0..6 {
            iv[8 + i] ^= idx[2 + i];
        }
        let mut c = Aes128Ctr::new(&self.enc.into(), &iv.into());
        c.apply_keystream(data);
    }

    fn tag(&self, auth_portion: &[u8], roc: u32) -> Vec<u8> {
        let mut m = <Hmac<Sha1> as Mac>::new_from_slice(&self.auth).expect("hmac key");
        m.update(auth_portion);
        m.update(&roc.to_be_bytes());
        m.finalize().into_bytes()[..self.suite.tag_len()].to_vec()
    }

    /// Encrypts an RTP packet in place and appends the authentication tag.
    pub fn protect(&mut self, pkt: &mut Vec<u8>) {
        let Some(h) = rtp_header_len(pkt) else { return };
        let seq = u16::from_be_bytes([pkt[2], pkt[3]]);
        let ssrc = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
        if let Some(last) = self.last_seq {
            if seq < last && last - seq > 0x8000 {
                self.roc = self.roc.wrapping_add(1);
            }
        }
        self.last_seq = Some(seq);
        let index = ((self.roc as u64) << 16) | seq as u64;
        self.keystream_xor(ssrc, index, &mut pkt[h..]);
        let tag = self.tag(pkt, self.roc);
        pkt.extend_from_slice(&tag);
    }

    /// Verifies and decrypts in place; returns the plain RTP length, or None
    /// when authentication fails.
    pub fn unprotect(&mut self, pkt: &mut [u8]) -> Option<usize> {
        let tl = self.suite.tag_len();
        if pkt.len() < 12 + tl {
            return None;
        }
        let n = pkt.len() - tl;
        let h = rtp_header_len(&pkt[..n])?;
        let seq = u16::from_be_bytes([pkt[2], pkt[3]]);
        let ssrc = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
        // RFC 3711 3.3.1: guess the rollover counter from the highest sequence seen.
        let roc = match self.last_seq {
            None => self.roc,
            Some(s_l) => {
                if s_l < 0x8000 {
                    if seq as i32 - s_l as i32 > 0x8000 {
                        self.roc.wrapping_sub(1)
                    } else {
                        self.roc
                    }
                } else if (s_l as i32 - 0x8000) > seq as i32 {
                    self.roc.wrapping_add(1)
                } else {
                    self.roc
                }
            }
        };
        let expect = self.tag(&pkt[..n], roc);
        if expect != pkt[n..] {
            return None;
        }
        let index = ((roc as u64) << 16) | seq as u64;
        self.keystream_xor(ssrc, index, &mut pkt[h..n]);
        if roc == self.roc.wrapping_add(1) {
            self.roc = roc;
            self.last_seq = Some(seq);
        } else if roc == self.roc && self.last_seq.map(|s| seq > s).unwrap_or(true) {
            self.last_seq = Some(seq);
        }
        Some(n)
    }
}

fn rtp_header_len(p: &[u8]) -> Option<usize> {
    if p.len() < 12 || p[0] >> 6 != 2 {
        return None;
    }
    let cc = (p[0] & 0x0f) as usize;
    let mut h = 12 + 4 * cc;
    if p[0] & 0x10 != 0 {
        if p.len() < h + 4 {
            return None;
        }
        let words = u16::from_be_bytes([p[h + 2], p[h + 3]]) as usize;
        h += 4 + 4 * words;
    }
    if h > p.len() {
        None
    } else {
        Some(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc3711_key_derivation() {
        // RFC 3711 appendix B.3.
        let mut km = KeyMaterial {
            suite: Suite::Sha80,
            key: [0; 16],
            salt: [0; 14],
        };
        km.key
            .copy_from_slice(&hex("E1F97A0D3E018BE0D64FA32C06DE4139"));
        km.salt
            .copy_from_slice(&hex("0EC675AD498AFEEBB6960B3AABE6"));
        let mut enc = [0u8; 16];
        derive(&km, 0, &mut enc);
        assert_eq!(enc.to_vec(), hex("C61E7A93744F39EE10734AFE3FF7A087"));
        let mut salt = [0u8; 14];
        derive(&km, 2, &mut salt);
        assert_eq!(salt.to_vec(), hex("30CBBC08863D8C85D49DB34A9AE1"));
        let mut auth = [0u8; 20];
        derive(&km, 1, &mut auth);
        assert_eq!(
            auth.to_vec(),
            hex("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4")
        );
    }

    #[test]
    fn roundtrip_and_tamper() {
        let km = KeyMaterial::random(Suite::Sha80);
        let (_, parsed) = KeyMaterial::parse_sdp(&km.sdp(1)).unwrap();
        let mut tx = Context::new(&km);
        let mut rx = Context::new(&parsed);
        for seq in [65530u16, 65535, 0, 1, 2] {
            let mut p = vec![0x80, 0, 0, 0, 0, 0, 0, 160, 1, 2, 3, 4];
            p[2..4].copy_from_slice(&seq.to_be_bytes());
            p.extend_from_slice(&[0x55u8; 160]);
            let plain = p.clone();
            tx.protect(&mut p);
            assert_eq!(p.len(), plain.len() + 10);
            assert_ne!(&p[12..172], &plain[12..172]);
            let mut q = p.clone();
            let n = rx.unprotect(&mut q).expect("authentic");
            assert_eq!(&q[..n], &plain[..]);
            p[20] ^= 1;
            assert!(Context::new(&parsed).unprotect(&mut p).is_none());
        }
    }
}
