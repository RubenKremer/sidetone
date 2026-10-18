//! DTLS-SRTP (RFC 5763/5764) for the native phone: a DTLS 1.2 handshake on
//! the RTP socket, the peer certificate checked against a=fingerprint, and
//! SRTP keys exported from the session.

use crate::srtp::{KeyMaterial, Suite};
use dimpl::{Config, Dtls, DtlsCertificate, Output, SrtpProfile};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// One self-signed certificate per run, like browsers do.
fn local() -> &'static (DtlsCertificate, String) {
    static C: OnceLock<(DtlsCertificate, String)> = OnceLock::new();
    C.get_or_init(|| {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Sidetone");
        let serial = crate::ua::rand_hex(32);
        params.serial_number = Some(
            (0..16)
                .map(|i| u8::from_str_radix(&serial[i * 2..i * 2 + 2], 16).unwrap_or(1) & 0x7f)
                .collect::<Vec<u8>>()
                .into(),
        );
        let cert = params.self_signed(&key).expect("self-signed certificate");
        let der = cert.der().to_vec();
        let fp = fingerprint(&der);
        (
            DtlsCertificate {
                certificate: der,
                private_key: key.serialize_der(),
            },
            fp,
        )
    })
}

/// "AB:CD:..." SHA-256 of a DER certificate.
pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Our a=fingerprint value.
pub fn local_fingerprint() -> String {
    format!("sha-256 {}", local().1)
}

/// What the far end said about its certificate and our role.
#[derive(Debug, Clone)]
pub struct DtlsParams {
    /// We send the ClientHello (a=setup:active on our side).
    pub client: bool,
    /// The far end's a=fingerprint, e.g. "sha-256 AB:CD:...".
    pub remote_fingerprint: String,
}

/// Keys and the state text, once the handshake has an outcome.
pub enum Event {
    Keys(KeyMaterial, KeyMaterial, String),
    Failed(String),
}

pub struct DtlsSrtp {
    dtls: Dtls,
    params: DtlsParams,
    peer_ok: Option<bool>,
    next: Option<Instant>,
    pub state: String,
    done: bool,
}

impl DtlsSrtp {
    pub fn new(params: DtlsParams) -> DtlsSrtp {
        let config = Arc::new(Config::default());
        let now = Instant::now();
        let mut dtls = Dtls::new_12(config, local().0.clone(), now);
        dtls.set_active(params.client);
        // The engine sets up its randoms on the first timeout, before any
        // ClientHello arrives.
        let init = dtls.handle_timeout(now);
        DtlsSrtp {
            dtls,
            params,
            peer_ok: None,
            next: Some(now),
            state: if init.is_ok() {
                "DTLS handshake".into()
            } else {
                "DTLS could not start".into()
            },
            done: init.is_err(),
        }
    }

    /// True for a datagram that belongs to DTLS (RFC 7983: first byte 20..63).
    pub fn is_dtls(pkt: &[u8]) -> bool {
        matches!(pkt.first(), Some(20..=63))
    }

    /// Feeds a received datagram; packets to send go to `out`.
    pub fn handle(&mut self, pkt: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Event> {
        if self.done && self.peer_ok != Some(true) {
            return None;
        }
        let dtls = &mut self.dtls;
        // A malformed peer must not take the media thread down with it.
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dtls.handle_packet(pkt))) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return self.fail(format!("DTLS error: {e}")),
            Err(_) => return self.fail("DTLS error: internal failure on a received record".into()),
        }
        self.drain(out)
    }

    /// Retransmissions and the first flight; call often.
    pub fn tick(&mut self, out: &mut Vec<Vec<u8>>) -> Option<Event> {
        if self.done && self.peer_ok.is_some() {
            return None;
        }
        let now = Instant::now();
        if self.done {
            return None;
        }
        if self.next.map(|t| now >= t).unwrap_or(false) {
            let dtls = &mut self.dtls;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dtls.handle_timeout(now)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return self.fail(format!("DTLS handshake failed: {e}")),
                Err(_) => return self.fail("DTLS error: internal failure on a timer".into()),
            }
        }
        self.drain(out)
    }

    fn fail(&mut self, why: String) -> Option<Event> {
        if self.done {
            return None;
        }
        self.done = true;
        self.state = why.clone();
        Some(Event::Failed(why))
    }

    fn drain(&mut self, out: &mut Vec<Vec<u8>>) -> Option<Event> {
        let mut buf = vec![0u8; 2048];
        let mut ev = None;
        loop {
            match self.dtls.poll_output(&mut buf) {
                Output::Packet(p) => out.push(p.to_vec()),
                Output::BufferTooSmall { needed } => buf.resize(needed, 0),
                Output::Timeout(t) => {
                    self.next = Some(t);
                    break;
                }
                Output::PeerCert(der) => {
                    let want = self.params.remote_fingerprint.trim().to_string();
                    let (algo, value) = want.split_once(' ').unwrap_or(("sha-256", want.as_str()));
                    let ok = if algo.eq_ignore_ascii_case("sha-256") {
                        value.trim().eq_ignore_ascii_case(&fingerprint(der))
                    } else {
                        // Only SHA-256 fingerprints can be checked here.
                        false
                    };
                    self.peer_ok = Some(ok);
                    if !ok {
                        ev = self.fail(format!(
                            "the far end's DTLS certificate does not match a=fingerprint ({algo})"
                        ));
                    }
                }
                Output::KeyingMaterial(km, profile) => {
                    if self.peer_ok != Some(true) {
                        continue;
                    }
                    let suite = match profile {
                        SrtpProfile::AES128_CM_SHA1_80 => Suite::Sha80,
                        SrtpProfile::AEAD_AES_128_GCM => Suite::Gcm128,
                        SrtpProfile::AEAD_AES_256_GCM => Suite::Gcm256,
                        _ => {
                            ev = self.fail(format!("unsupported SRTP profile {profile}"));
                            continue;
                        }
                    };
                    match KeyMaterial::from_dtls(suite, &km, self.params.client) {
                        Some((tx, rx)) => {
                            self.done = true;
                            self.state = format!("DTLS-SRTP {profile}, fingerprint verified");
                            ev = Some(Event::Keys(tx, rx, self.state.clone()));
                        }
                        None => ev = self.fail("short DTLS keying material".into()),
                    }
                }
                Output::Connected => {}
                Output::ApplicationData(_) => {}
                Output::CloseNotify => {
                    ev = self.fail("the far end closed DTLS".into());
                }
                _ => {}
            }
        }
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two endpoints complete the handshake in memory and derive mirrored keys.
    #[test]
    fn handshake_in_memory() {
        let fp = local_fingerprint();
        let mut a = DtlsSrtp::new(DtlsParams {
            client: true,
            remote_fingerprint: fp.clone(),
        });
        let mut b = DtlsSrtp::new(DtlsParams {
            client: false,
            remote_fingerprint: fp,
        });
        let (mut ka, mut kb) = (None, None);
        let mut to_b = Vec::new();
        let mut to_a = Vec::new();
        for _ in 0..50 {
            if let Some(Event::Keys(tx, rx, _)) = a.tick(&mut to_b) {
                ka = Some((tx, rx));
            }
            for p in std::mem::take(&mut to_b) {
                if let Some(Event::Keys(tx, rx, _)) = b.handle(&p, &mut to_a) {
                    kb = Some((tx, rx));
                }
            }
            for p in std::mem::take(&mut to_a) {
                if let Some(Event::Keys(tx, rx, _)) = a.handle(&p, &mut to_b) {
                    ka = Some((tx, rx));
                }
            }
            if ka.is_some() && kb.is_some() {
                break;
            }
            let _ = b.tick(&mut to_a);
        }
        let (atx, arx) = ka.expect("client keys");
        let (btx, brx) = kb.expect("server keys");
        assert_eq!(atx.key, brx.key);
        assert_eq!(arx.key, btx.key);
        assert_eq!(atx.salt, brx.salt);
        assert!(a.state.contains("fingerprint verified"), "{}", a.state);
    }

    #[test]
    fn wrong_fingerprint_fails() {
        let mut a = DtlsSrtp::new(DtlsParams {
            client: true,
            remote_fingerprint: "sha-256 00:11".into(),
        });
        let mut b = DtlsSrtp::new(DtlsParams {
            client: false,
            remote_fingerprint: local_fingerprint(),
        });
        let (mut to_a, mut to_b) = (Vec::new(), Vec::new());
        let mut failed = false;
        for _ in 0..50 {
            if let Some(Event::Failed(_)) = a.tick(&mut to_b) {
                failed = true;
            }
            for p in std::mem::take(&mut to_b) {
                let _ = b.handle(&p, &mut to_a);
            }
            for p in std::mem::take(&mut to_a) {
                if let Some(Event::Failed(_)) = a.handle(&p, &mut to_b) {
                    failed = true;
                }
            }
            if failed {
                break;
            }
        }
        assert!(failed, "a mismatching certificate must stop the handshake");
    }
}
