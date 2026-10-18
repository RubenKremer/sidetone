//! SRTP (RFC 3711, AEAD per RFC 7714) for RTP. Keys come from SDES a=crypto
//! (RFC 4568) or from a DTLS-SRTP handshake (RFC 5764).
//! Suites: AES_CM_128_HMAC_SHA1_80 and _32, AEAD_AES_128_GCM, AEAD_AES_256_GCM.
//! RTP only; SRTCP is not sent.

use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::aead::{AeadInPlace, Nonce};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    Sha80,
    Sha32,
    Gcm128,
    Gcm256,
}

impl Suite {
    pub fn name(self) -> &'static str {
        match self {
            Suite::Sha80 => "AES_CM_128_HMAC_SHA1_80",
            Suite::Sha32 => "AES_CM_128_HMAC_SHA1_32",
            Suite::Gcm128 => "AEAD_AES_128_GCM",
            Suite::Gcm256 => "AEAD_AES_256_GCM",
        }
    }
    fn tag_len(self) -> usize {
        match self {
            Suite::Sha80 => 10,
            Suite::Sha32 => 4,
            Suite::Gcm128 | Suite::Gcm256 => 16,
        }
    }
    pub fn key_len(self) -> usize {
        if self == Suite::Gcm256 {
            32
        } else {
            16
        }
    }
    pub fn salt_len(self) -> usize {
        match self {
            Suite::Gcm128 | Suite::Gcm256 => 12,
            _ => 14,
        }
    }
    fn aead(self) -> bool {
        matches!(self, Suite::Gcm128 | Suite::Gcm256)
    }
    pub fn parse(s: &str) -> Option<Suite> {
        match s {
            "AES_CM_128_HMAC_SHA1_80" => Some(Suite::Sha80),
            "AES_CM_128_HMAC_SHA1_32" => Some(Suite::Sha32),
            "AEAD_AES_128_GCM" => Some(Suite::Gcm128),
            "AEAD_AES_256_GCM" => Some(Suite::Gcm256),
            _ => None,
        }
    }
}

/// Master key and salt, as carried in a=crypto or exported by DTLS.
#[derive(Clone)]
pub struct KeyMaterial {
    pub suite: Suite,
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
}

impl KeyMaterial {
    pub fn random(suite: Suite) -> KeyMaterial {
        let n = suite.key_len() + suite.salt_len();
        let h = crate::ua::rand_hex(n * 2);
        let b: Vec<u8> = (0..n)
            .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(i as u8))
            .collect();
        KeyMaterial {
            suite,
            key: b[..suite.key_len()].to_vec(),
            salt: b[suite.key_len()..].to_vec(),
        }
    }

    /// Splits DTLS-SRTP keying material (RFC 5764 4.2: client key, server
    /// key, client salt, server salt) into (what we send with, what we
    /// receive with).
    pub fn from_dtls(
        suite: Suite,
        m: &[u8],
        we_are_client: bool,
    ) -> Option<(KeyMaterial, KeyMaterial)> {
        let (k, s) = (suite.key_len(), suite.salt_len());
        if m.len() < 2 * (k + s) {
            return None;
        }
        let client = KeyMaterial {
            suite,
            key: m[..k].to_vec(),
            salt: m[2 * k..2 * k + s].to_vec(),
        };
        let server = KeyMaterial {
            suite,
            key: m[k..2 * k].to_vec(),
            salt: m[2 * k + s..2 * k + 2 * s].to_vec(),
        };
        Some(if we_are_client {
            (client, server)
        } else {
            (server, client)
        })
    }

    /// "a=crypto:<tag> <suite> inline:<base64>" value (without "a=crypto:").
    pub fn sdp(&self, tag: u32) -> String {
        let mut b = self.key.clone();
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
        let (k, s) = (suite.key_len(), suite.salt_len());
        if raw.len() < k + s {
            return None;
        }
        Some((
            tag,
            KeyMaterial {
                suite,
                key: raw[..k].to_vec(),
                salt: raw[k..k + s].to_vec(),
            },
        ))
    }
}

enum Cipher {
    Cm { enc: [u8; 16], auth: [u8; 20] },
    Gcm128(Box<Aes128Gcm>),
    Gcm256(Box<Aes256Gcm>),
}

/// Session keys and rollover state for one direction.
pub struct Context {
    suite: Suite,
    cipher: Cipher,
    /// Session salt: 14 bytes for AES-CM, 12 for GCM.
    salt: Vec<u8>,
    roc: u32,
    last_seq: Option<u16>,
}

/// SRTP key derivation (RFC 3711 4.3.1, key derivation rate 0) with the
/// AES-CM PRF keyed by the master key (AES-128 or AES-256). The master salt
/// sits left-aligned in 112 bits (RFC 7714 section 11 pads 96-bit salts).
fn derive(km: &KeyMaterial, label: u8, out: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..km.salt.len().min(14)].copy_from_slice(&km.salt[..km.salt.len().min(14)]);
    iv[7] ^= label;
    let mut blocks = Vec::new();
    for counter in 0..out.len().div_ceil(16) {
        let mut block = iv;
        block[14..].copy_from_slice(&(counter as u16).to_be_bytes());
        blocks.push(aes::Block::from(block));
    }
    if km.key.len() == 32 {
        aes::Aes256::new_from_slice(&km.key)
            .expect("key")
            .encrypt_blocks(&mut blocks);
    } else {
        aes::Aes128::new_from_slice(&km.key)
            .expect("key")
            .encrypt_blocks(&mut blocks);
    }
    for (chunk, b) in out.chunks_mut(16).zip(blocks.iter()) {
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

impl Context {
    pub fn new(km: &KeyMaterial) -> Context {
        let suite = km.suite;
        let mut salt = vec![0u8; suite.salt_len()];
        derive(km, 2, &mut salt);
        let cipher = match suite {
            Suite::Gcm128 => {
                let mut k = [0u8; 16];
                derive(km, 0, &mut k);
                Cipher::Gcm128(Box::new(Aes128Gcm::new_from_slice(&k).expect("key")))
            }
            Suite::Gcm256 => {
                let mut k = [0u8; 32];
                derive(km, 0, &mut k);
                Cipher::Gcm256(Box::new(Aes256Gcm::new_from_slice(&k).expect("key")))
            }
            _ => {
                let mut enc = [0u8; 16];
                let mut auth = [0u8; 20];
                derive(km, 0, &mut enc);
                derive(km, 1, &mut auth);
                Cipher::Cm { enc, auth }
            }
        };
        Context {
            suite,
            cipher,
            salt,
            roc: 0,
            last_seq: None,
        }
    }

    fn cm_keystream_xor(&self, enc: &[u8; 16], ssrc: u32, index: u64, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
            iv[4 + i] ^= b;
        }
        let idx = index.to_be_bytes(); // 8 bytes, the 48-bit index in the low 6
        for i in 0..6 {
            iv[8 + i] ^= idx[2 + i];
        }
        let mut c = Aes128Ctr::new(enc.into(), &iv.into());
        c.apply_keystream(data);
    }

    fn cm_tag(&self, auth: &[u8; 20], auth_portion: &[u8], roc: u32) -> Vec<u8> {
        let mut m = <Hmac<Sha1> as Mac>::new_from_slice(auth).expect("hmac key");
        m.update(auth_portion);
        m.update(&roc.to_be_bytes());
        m.finalize().into_bytes()[..self.suite.tag_len()].to_vec()
    }

    /// RFC 7714 8.1: 12-byte IV from SSRC, ROC and SEQ, XORed with the salt.
    fn gcm_iv(&self, ssrc: u32, roc: u32, seq: u16) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[6..10].copy_from_slice(&roc.to_be_bytes());
        iv[10..12].copy_from_slice(&seq.to_be_bytes());
        for (a, b) in iv.iter_mut().zip(self.salt.iter()) {
            *a ^= b;
        }
        iv
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
        let roc = self.roc;
        match &self.cipher {
            Cipher::Cm { enc, auth } => {
                let index = ((roc as u64) << 16) | seq as u64;
                let (enc, auth) = (*enc, *auth);
                self.cm_keystream_xor(&enc, ssrc, index, &mut pkt[h..]);
                let tag = self.cm_tag(&auth, pkt, roc);
                pkt.extend_from_slice(&tag);
            }
            Cipher::Gcm128(_) | Cipher::Gcm256(_) => {
                let iv = self.gcm_iv(ssrc, roc, seq);
                let (head, body) = pkt.split_at_mut(h);
                let nonce = Nonce::<Aes128Gcm>::from_slice(&iv);
                let tag = match &self.cipher {
                    Cipher::Gcm128(c) => c.encrypt_in_place_detached(nonce, head, body),
                    Cipher::Gcm256(c) => c.encrypt_in_place_detached(nonce, head, body),
                    Cipher::Cm { .. } => unreachable!(),
                };
                if let Ok(tag) = tag {
                    pkt.extend_from_slice(&tag);
                }
            }
        }
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
                    // A late packet from before the last rollover; there is none before ROC 0.
                    if seq as i32 - s_l as i32 > 0x8000 && self.roc > 0 {
                        self.roc - 1
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
        if self.suite.aead() {
            let iv = self.gcm_iv(ssrc, roc, seq);
            let nonce = Nonce::<Aes128Gcm>::from_slice(&iv);
            let (head, rest) = pkt.split_at_mut(h);
            let (body, tag) = rest.split_at_mut(n - h);
            let tag = aes_gcm::Tag::from_slice(tag);
            let ok = match &self.cipher {
                Cipher::Gcm128(c) => c.decrypt_in_place_detached(nonce, head, body, tag),
                Cipher::Gcm256(c) => c.decrypt_in_place_detached(nonce, head, body, tag),
                Cipher::Cm { .. } => unreachable!(),
            };
            ok.ok()?;
        } else {
            let Cipher::Cm { enc, auth } = &self.cipher else {
                return None;
            };
            let (enc, auth) = (*enc, *auth);
            let expect = self.cm_tag(&auth, &pkt[..n], roc);
            if expect != pkt[n..] {
                return None;
            }
            let index = ((roc as u64) << 16) | seq as u64;
            self.cm_keystream_xor(&enc, ssrc, index, &mut pkt[h..n]);
        }
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
        let km = KeyMaterial {
            suite: Suite::Sha80,
            key: hex("E1F97A0D3E018BE0D64FA32C06DE4139"),
            salt: hex("0EC675AD498AFEEBB6960B3AABE6"),
        };
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

    /// Packets protected by libsrtp 2 (through pylibsrtp) with the same keys:
    /// SSRC 0x11223344, sequence 0x1234, 0xffff and 0 (rollover), 40 bytes of
    /// payload (i * 7).
    #[test]
    fn matches_libsrtp() {
        let cases: [(Suite, &str, [&str; 3]); 3] = [
            (
                Suite::Sha80,
                "0102030405060708090a0b0c0d0e0f10a0a1a2a3a4a5a6a7a8a9aaabacad",
                [
                    "8000123411223344cafebabee8a7fc711a3691dc90aafc25f7570b7e54f5b0812da802db3c6d2974dba8e71acadb25257fc9232fe9d227f9531ba2f6bebc",
                    "8000ffff11223344cafebabe138ad51c336e33be040fc44e947a6bef81da245351277d4a55a113e01b9b1f591cd6bdecf61b22af11021ffcf8e93b823ff0",
                    "8000000011223344cafebabe1d23bc507f329c9680590047257737464bd8aec4995144be1e59acd816cd6ef2cb11e3f0810dd998e028eae261af101a940f",
                ],
            ),
            (
                Suite::Gcm128,
                "0102030405060708090a0b0c0d0e0f10a0a1a2a3a4a5a6a7a8a9aaab",
                [
                    "8000123411223344cafebabec64a819c76625c8a7aa69c5665d8a66fa6c897fd1645c4e472b72c86edb910be48e4ab5e444454de45a085b2810226c46ce13e3ea3d47b25",
                    "8000ffff11223344cafebabe9507a8e2978ee9545a9154ced85c83747ccc858597861b591270c7ad85d36b017e18befeb8a4a518afbaaa327806ff193a617178d85ea543",
                    "8000000011223344cafebabecce78d6fbef29251369fcee60ab7f31e0e47e60686f672f2d6e75146df7a1f2a6c0536decde8948e297a3d7dfdcb393a6d5088762bd59cb9",
                ],
            ),
            (
                Suite::Gcm256,
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a0a1a2a3a4a5a6a7a8a9aaab",
                [
                    "8000123411223344cafebabedbc8a78f9a1c089146108b83470670a9e73ea5770c1c7396e4c50446567232c5e74faa82fa9e857f2e7f5641ddb066aa7f4ca7abea2bd66e",
                    "8000ffff11223344cafebabe1ab4ce548c8849bc90ffd4f904e2920e079e4c3082abf980737403e26160de05c0504ebf61f5c1807430621d0feedc978e5d45f3f41728ae",
                    "8000000011223344cafebabe6039d93293754e73f68dd3ce649071811ee326c8399ded6db37942c161bfc4ebebd9bfd867d820efa4f4b05cdcd9fb2cd73b04824b60a720",
                ],
            ),
        ];
        for (suite, keys, expect) in cases {
            let raw = hex(keys);
            let km = KeyMaterial {
                suite,
                key: raw[..suite.key_len()].to_vec(),
                salt: raw[suite.key_len()..].to_vec(),
            };
            let mut tx = Context::new(&km);
            let mut rx = Context::new(&km);
            for (seq, want) in [0x1234u16, 0xffff, 0].iter().zip(expect) {
                let mut p = vec![0x80, 0];
                p.extend_from_slice(&seq.to_be_bytes());
                p.extend_from_slice(&hex("11223344cafebabe"));
                let plain_payload: Vec<u8> = (0..40u32).map(|i| (i * 7) as u8).collect();
                p.extend_from_slice(&plain_payload);
                let plain = p.clone();
                tx.protect(&mut p);
                assert_eq!(p, hex(want), "{suite:?} seq {seq:#x}");
                let n = rx
                    .unprotect(&mut p)
                    .unwrap_or_else(|| panic!("{suite:?} seq {seq:#x} authentic"));
                assert_eq!(&p[..n], &plain[..], "{suite:?} decrypts");
            }
        }
    }

    #[test]
    fn roundtrip_and_tamper() {
        for suite in [Suite::Sha80, Suite::Sha32, Suite::Gcm128, Suite::Gcm256] {
            let km = KeyMaterial::random(suite);
            let (_, parsed) = KeyMaterial::parse_sdp(&km.sdp(1)).unwrap();
            let mut tx = Context::new(&km);
            let mut rx = Context::new(&parsed);
            for seq in [65530u16, 65535, 0, 1, 2] {
                let mut p = vec![0x80, 0, 0, 0, 0, 0, 0, 160, 1, 2, 3, 4];
                p[2..4].copy_from_slice(&seq.to_be_bytes());
                p.extend_from_slice(&[0x55u8; 160]);
                let plain = p.clone();
                tx.protect(&mut p);
                assert_eq!(p.len(), plain.len() + suite.tag_len());
                assert_ne!(&p[12..172], &plain[12..172]);
                let mut q = p.clone();
                let n = rx.unprotect(&mut q).expect("authentic");
                assert_eq!(&q[..n], &plain[..]);
                p[20] ^= 1;
                assert!(Context::new(&parsed).unprotect(&mut p).is_none());
            }
        }
    }

    #[test]
    fn dtls_keying_material_split() {
        let m: Vec<u8> = (0..60u8).collect();
        let (tx, rx) = KeyMaterial::from_dtls(Suite::Sha80, &m, true).unwrap();
        assert_eq!(tx.key, (0..16).collect::<Vec<u8>>());
        assert_eq!(rx.key, (16..32).collect::<Vec<u8>>());
        assert_eq!(tx.salt, (32..46).collect::<Vec<u8>>());
        assert_eq!(rx.salt, (46..60).collect::<Vec<u8>>());
        let (tx2, _) = KeyMaterial::from_dtls(Suite::Sha80, &m, false).unwrap();
        assert_eq!(tx2.key, rx.key);
    }
}
