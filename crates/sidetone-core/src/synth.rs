//! Synthetic captures with known problems. Used by tests, the CLI
//! (`sidetone samples`) and the web demo, so every rule can be seen in action
//! without real customer traffic.

use crate::net::build_udp_packet;
use crate::pcap::{write_pcapng, OutPacket, PcapngOptions, LINKTYPE_RAW};
use std::net::SocketAddr;

/// 2026-10-17 10:00:00 UTC in nanoseconds.
const BASE_NS: i64 = 1_792_231_200 * 1_000_000_000;

pub struct Synth {
    pkts: Vec<(i64, Vec<u8>)>,
    t0_ms: i64,
    /// Streams (by SSRC) whose payload is digital silence.
    silent: Vec<u32>,
}

fn sa(s: &str) -> SocketAddr {
    s.parse().expect("valid socket address")
}

/// Builds a SIP message text with a correct Content-Length.
pub fn sip_text(start: &str, headers: &[(String, String)], body: &str) -> String {
    let mut s = String::new();
    s.push_str(start);
    s.push_str("\r\n");
    for (k, v) in headers {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push_str("\r\n");
    }
    if !body.is_empty() {
        s.push_str("Content-Type: application/sdp\r\n");
    }
    s.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    s.push_str(body);
    s
}

pub fn sdp_body(ip: &str, port: u16, proto: &str, pts: &[(u8, &str)], extra: &[&str]) -> String {
    let fmts: Vec<String> = pts.iter().map(|p| p.0.to_string()).collect();
    let mut s = format!(
        "v=0\r\no=- 3912345 3912345 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\nm=audio {port} {proto} {}\r\n",
        fmts.join(" ")
    );
    for (pt, name) in pts {
        s.push_str(&format!("a=rtpmap:{pt} {name}\r\n"));
        if name.starts_with("telephone-event") {
            s.push_str(&format!("a=fmtp:{pt} 0-16\r\n"));
        }
    }
    s.push_str("a=ptime:20\r\n");
    for e in extra {
        s.push_str(e);
        s.push_str("\r\n");
    }
    s
}

impl Synth {
    pub fn new(t0_ms: i64) -> Self {
        Synth {
            silent: Vec::new(),
            pkts: Vec::new(),
            t0_ms,
        }
    }

    /// RTCP sender report with one reception report block.
    #[allow(clippy::too_many_arguments)]
    pub fn rtcp_sr(
        &mut self,
        t_ms: i64,
        src: &str,
        dst: &str,
        ssrc: u32,
        ntp_mid: u32,
        packets: u32,
        about: Option<(u32, u8, u32, u32, u32)>,
    ) {
        let n = about.is_some() as u8;
        let mut p = vec![0x80 | n, 200, 0, if n == 1 { 12 } else { 6 }];
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&(ntp_mid >> 16).to_be_bytes());
        p.extend_from_slice(&(ntp_mid << 16).to_be_bytes());
        p.extend_from_slice(&(packets * 160).to_be_bytes());
        p.extend_from_slice(&packets.to_be_bytes());
        p.extend_from_slice(&(packets * 160).to_be_bytes());
        if let Some(b) = about {
            p.extend(report_block(b));
        }
        self.pkts.push((
            BASE_NS + (self.t0_ms + t_ms) * 1_000_000,
            build_udp_packet(sa(src), sa(dst), &p),
        ));
    }

    /// RTCP receiver report: (about SSRC, fraction lost /256, jitter units, LSR, DLSR).
    pub fn rtcp_rr(
        &mut self,
        t_ms: i64,
        src: &str,
        dst: &str,
        ssrc: u32,
        about: (u32, u8, u32, u32, u32),
    ) {
        let mut p = vec![0x81, 201, 0, 7];
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend(report_block(about));
        self.pkts.push((
            BASE_NS + (self.t0_ms + t_ms) * 1_000_000,
            build_udp_packet(sa(src), sa(dst), &p),
        ));
    }

    pub fn sip(&mut self, t_ms: i64, src: &str, dst: &str, text: &str) {
        let pkt = build_udp_packet(sa(src), sa(dst), text.as_bytes());
        self.pkts
            .push((BASE_NS + (self.t0_ms + t_ms) * 1_000_000, pkt));
    }

    /// Any UDP datagram.
    pub fn udp(&mut self, t_ms: i64, src: &str, dst: &str, payload: &[u8]) {
        let pkt = build_udp_packet(sa(src), sa(dst), payload);
        self.pkts
            .push((BASE_NS + (self.t0_ms + t_ms) * 1_000_000, pkt));
    }

    /// RTP stream: `count` packets every 20 ms. `lose` drops given indices, `jitter_ms`
    /// adds a deterministic pseudo-random delay, `dtmf` sends digits at given packet indices.
    #[allow(clippy::too_many_arguments)]
    pub fn rtp(
        &mut self,
        start_ms: i64,
        src: &str,
        dst: &str,
        pt: u8,
        ssrc: u32,
        count: u32,
        lose: &dyn Fn(u32) -> bool,
        jitter_ms: i64,
        dtmf: &[(u32, u8)],
    ) {
        let mut seq: u16 = (ssrc & 0x7fff) as u16;
        let mut ts: u32 = ssrc.wrapping_mul(7);
        let mut rng: u32 = ssrc ^ 0x9e37_79b9;
        let mut i = 0u32;
        while i < count {
            if let Some(&(_, digit)) = dtmf.iter().find(|d| d.0 == i) {
                // RFC 4733 event: 3 updates then 3 end packets, same timestamp.
                for k in 0..6u16 {
                    let end = k >= 3;
                    let dur = 160 * (k as u32 + 1);
                    let mut p = vec![0x80, if k == 0 { 0x80 | 101 } else { 101 }];
                    p.extend_from_slice(&seq.to_be_bytes());
                    p.extend_from_slice(&ts.to_be_bytes());
                    p.extend_from_slice(&ssrc.to_be_bytes());
                    p.extend_from_slice(&[digit, if end { 0x8a } else { 0x0a }]);
                    p.extend_from_slice(&(dur.min(0xffff) as u16).to_be_bytes());
                    let t = start_ms + (i as i64 + k as i64) * 20;
                    let pkt = build_udp_packet(sa(src), sa(dst), &p);
                    self.pkts
                        .push((BASE_NS + (self.t0_ms + t) * 1_000_000, pkt));
                    seq = seq.wrapping_add(1);
                }
                ts = ts.wrapping_add(160 * 6);
                i += 6;
                continue;
            }
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            let jit = if jitter_ms > 0 {
                (rng % (jitter_ms as u32 + 1)) as i64
            } else {
                0
            };
            if !lose(i) {
                let mut p = vec![0x80, if i == 0 { 0x80 | pt } else { pt }];
                p.extend_from_slice(&seq.to_be_bytes());
                p.extend_from_slice(&ts.to_be_bytes());
                p.extend_from_slice(&ssrc.to_be_bytes());
                // A voice-like signal (voiced syllables with pauses) so playback
                // and the waveform show something; pitch differs per stream.
                let f0 = 110.0 + (ssrc % 7) as f64 * 15.0;
                let mute = self.silent.contains(&ssrc);
                for k in 0..160u32 {
                    if mute {
                        p.push(if pt == 8 { 0xd5 } else { 0xff });
                        continue;
                    }
                    let n = ts.wrapping_add(k) as f64 / 8000.0;
                    let syl = (n * 3.3 * std::f64::consts::PI).sin().max(0.0);
                    let gate = if (n * 0.7).fract() < 0.75 { 1.0 } else { 0.0 };
                    let env = syl * syl * gate;
                    let w = 2.0 * std::f64::consts::PI * f0 * (1.0 + 0.05 * (n * 1.7).sin()) * n;
                    let v = env * (0.5 * w.sin() + 0.25 * (2.0 * w).sin() + 0.12 * (3.0 * w).sin());
                    let x = (v * 9000.0) as i16;
                    p.push(if pt == 8 { lin2alaw(x) } else { lin2ulaw(x) });
                }
                let t_ns =
                    BASE_NS + (self.t0_ms + start_ms + i as i64 * 20) * 1_000_000 + jit * 1_000_000;
                self.pkts
                    .push((t_ns, build_udp_packet(sa(src), sa(dst), &p)));
            }
            seq = seq.wrapping_add(1);
            ts = ts.wrapping_add(160);
            i += 1;
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.pkts.sort_by_key(|p| p.0);
        let out: Vec<OutPacket<'_>> = self
            .pkts
            .iter()
            .map(|(t, d)| OutPacket {
                ts_ns: *t,
                linktype: LINKTYPE_RAW,
                data: d,
                orig_len: d.len() as u32,
                comment: None,
            })
            .collect();
        write_pcapng(
            &out,
            &PcapngOptions {
                user_appl: Some("Sidetone synthetic sample".into()),
                ..Default::default()
            },
        )
    }
}

fn hdrs(
    via: &str,
    from: &str,
    to: &str,
    cid: &str,
    cseq: &str,
    extra: &[(&str, String)],
) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = [
        ("Via", via),
        ("Max-Forwards", "70"),
        ("From", from),
        ("To", to),
        ("Call-ID", cid),
        ("CSeq", cseq),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, val) in extra {
        v.push((k.to_string(), val.clone()));
    }
    v
}

/// Healthy registration with digest auth followed by a good call with DTMF.
pub fn scenario_good_call(s: &mut Synth) {
    let ua = "10.20.0.15:5060";
    let pbx = "10.20.0.1:5060";
    let via = "SIP/2.0/UDP 10.20.0.15:5060;branch=z9hG4bKreg1;rport";
    let from = "\"Agent 2001\" <sip:2001@pbx.lab>;tag=r1";
    let to = "<sip:2001@pbx.lab>";
    let cid = "reg-2001@10.20.0.15";
    let ua_h = ("User-Agent", "Sidetone/0.1".to_string());
    s.sip(
        0,
        ua,
        pbx,
        &sip_text(
            "REGISTER sip:pbx.lab SIP/2.0",
            &hdrs(
                via,
                from,
                to,
                cid,
                "1 REGISTER",
                &[
                    ("Contact", "<sip:2001@10.20.0.15:5060>".into()),
                    ("Expires", "3600".into()),
                    ua_h.clone(),
                ],
            ),
            "",
        ),
    );
    s.sip(
        4,
        pbx,
        ua,
        &sip_text(
            "SIP/2.0 401 Unauthorized",
            &hdrs(
                &format!("{via};received=10.20.0.15;rport=5060"),
                from,
                &format!("{to};tag=srv1"),
                cid,
                "1 REGISTER",
                &[
                    (
                        "WWW-Authenticate",
                        "Digest realm=\"pbx.lab\", nonce=\"abc123\", algorithm=MD5, qop=\"auth\""
                            .into(),
                    ),
                    ("Server", "LabPBX 18.2".into()),
                ],
            ),
            "",
        ),
    );
    let via2 = "SIP/2.0/UDP 10.20.0.15:5060;branch=z9hG4bKreg2;rport";
    s.sip(10, ua, pbx, &sip_text("REGISTER sip:pbx.lab SIP/2.0", &hdrs(via2, from, to, cid, "2 REGISTER", &[("Contact", "<sip:2001@10.20.0.15:5060>".into()), ("Expires", "3600".into()), ("Authorization", "Digest username=\"2001\", realm=\"pbx.lab\", nonce=\"abc123\", uri=\"sip:pbx.lab\", response=\"0f1e2d3c4b5a69788796a5b4c3d2e1f0\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"xyz\"".into()), ua_h.clone()]), ""));
    s.sip(
        14,
        pbx,
        ua,
        &sip_text(
            "SIP/2.0 200 OK",
            &hdrs(
                &format!("{via2};received=10.20.0.15;rport=5060"),
                from,
                &format!("{to};tag=srv2"),
                cid,
                "2 REGISTER",
                &[
                    ("Contact", "<sip:2001@10.20.0.15:5060>;expires=3600".into()),
                    ("Server", "LabPBX 18.2".into()),
                ],
            ),
            "",
        ),
    );

    let cid = "call-good-1@10.20.0.15";
    let from = "\"Agent 2001\" <sip:2001@pbx.lab>;tag=g1";
    let to = "<sip:+5511912345678@pbx.lab>";
    let via = "SIP/2.0/UDP 10.20.0.15:5060;branch=z9hG4bKinv1;rport";
    let offer = sdp_body(
        "10.20.0.15",
        40000,
        "RTP/AVP",
        &[
            (0, "PCMU/8000"),
            (8, "PCMA/8000"),
            (101, "telephone-event/8000"),
        ],
        &["a=sendrecv"],
    );
    let answer = sdp_body(
        "10.20.0.1",
        30000,
        "RTP/AVP",
        &[(0, "PCMU/8000"), (101, "telephone-event/8000")],
        &["a=sendrecv"],
    );
    let base = 1000;
    s.sip(
        base,
        ua,
        pbx,
        &sip_text(
            "INVITE sip:+5511912345678@pbx.lab SIP/2.0",
            &hdrs(
                via,
                from,
                to,
                cid,
                "1 INVITE",
                &[
                    ("Contact", "<sip:2001@10.20.0.15:5060>".into()),
                    (
                        "Allow",
                        "INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, UPDATE".into(),
                    ),
                    ua_h.clone(),
                ],
            ),
            &offer,
        ),
    );
    let to_t = format!("{to};tag=pbx77");
    let rvia = format!("{via};received=10.20.0.15;rport=5060");
    s.sip(
        base + 6,
        pbx,
        ua,
        &sip_text(
            "SIP/2.0 100 Trying",
            &hdrs(&rvia, from, to, cid, "1 INVITE", &[]),
            "",
        ),
    );
    s.sip(
        base + 900,
        pbx,
        ua,
        &sip_text(
            "SIP/2.0 180 Ringing",
            &hdrs(
                &rvia,
                from,
                &to_t,
                cid,
                "1 INVITE",
                &[("Contact", "<sip:+5511912345678@10.20.0.1:5060>".into())],
            ),
            "",
        ),
    );
    s.sip(
        base + 4200,
        pbx,
        ua,
        &sip_text(
            "SIP/2.0 200 OK",
            &hdrs(
                &rvia,
                from,
                &to_t,
                cid,
                "1 INVITE",
                &[
                    ("Contact", "<sip:+5511912345678@10.20.0.1:5060>".into()),
                    ("Server", "LabPBX 18.2".into()),
                ],
            ),
            &answer,
        ),
    );
    s.sip(
        base + 4210,
        ua,
        pbx,
        &sip_text(
            "ACK sip:+5511912345678@10.20.0.1:5060 SIP/2.0",
            &hdrs(
                "SIP/2.0/UDP 10.20.0.15:5060;branch=z9hG4bKack1;rport",
                from,
                &to_t,
                cid,
                "1 ACK",
                &[],
            ),
            "",
        ),
    );
    s.rtp(
        base + 4220,
        "10.20.0.15:40000",
        "10.20.0.1:30000",
        0,
        0x1111_0001,
        400,
        &|_| false,
        2,
        &[(150, 1), (200, 2), (250, 3), (300, 11)],
    );
    s.rtp(
        base + 4230,
        "10.20.0.1:30000",
        "10.20.0.15:40000",
        0,
        0x2222_0001,
        400,
        &|_| false,
        3,
        &[],
    );
    s.sip(
        base + 12300,
        ua,
        pbx,
        &sip_text(
            "BYE sip:+5511912345678@10.20.0.1:5060 SIP/2.0",
            &hdrs(
                "SIP/2.0/UDP 10.20.0.15:5060;branch=z9hG4bKbye1;rport",
                from,
                &to_t,
                cid,
                "2 BYE",
                &[(
                    "Reason",
                    "Q.850;cause=16;text=\"Normal call clearing\"".into(),
                )],
            ),
            "",
        ),
    );
    s.sip(
        base + 12308,
        pbx,
        ua,
        &sip_text(
            "SIP/2.0 200 OK",
            &hdrs(
                "SIP/2.0/UDP 10.20.0.15:5060;branch=z9hG4bKbye1;rport;received=10.20.0.15",
                from,
                &to_t,
                cid,
                "2 BYE",
                &[],
            ),
            "",
        ),
    );
}

/// Remote worker behind NAT: private SDP/Contact, no ACK reaches the callee,
/// one-way audio, call dropped at 32 s. Captured at the SBC.
pub fn scenario_nat_one_way(s: &mut Synth) {
    let ua = "198.51.100.20:5060";
    let sbc = "203.0.113.10:5060";
    let cid = "nat-call-7@192.168.1.50";
    let from = "<sip:3005@voice.example>;tag=n1";
    let to = "<sip:2001@voice.example>";
    let via = "SIP/2.0/UDP 192.168.1.50:5060;branch=z9hG4bKnat1";
    let offer = sdp_body(
        "192.168.1.50",
        16384,
        "RTP/AVP",
        &[
            (8, "PCMA/8000"),
            (0, "PCMU/8000"),
            (101, "telephone-event/8000"),
        ],
        &[],
    );
    let answer = sdp_body(
        "203.0.113.10",
        20000,
        "RTP/AVP",
        &[(8, "PCMA/8000"), (101, "telephone-event/8000")],
        &[],
    );
    let base = 20_000;
    s.sip(
        base,
        ua,
        sbc,
        &sip_text(
            "INVITE sip:2001@voice.example SIP/2.0",
            &hdrs(
                via,
                from,
                to,
                cid,
                "1 INVITE",
                &[
                    ("Contact", "<sip:3005@192.168.1.50:5060>".into()),
                    ("User-Agent", "HomePhone 2.1".into()),
                ],
            ),
            &offer,
        ),
    );
    let rvia = format!("{via};received=198.51.100.20");
    let to_t = format!("{to};tag=sbc9");
    s.sip(
        base + 12,
        sbc,
        ua,
        &sip_text(
            "SIP/2.0 100 Trying",
            &hdrs(&rvia, from, to, cid, "1 INVITE", &[]),
            "",
        ),
    );
    s.sip(
        base + 1500,
        sbc,
        ua,
        &sip_text(
            "SIP/2.0 180 Ringing",
            &hdrs(&rvia, from, &to_t, cid, "1 INVITE", &[]),
            "",
        ),
    );
    let ok = sip_text(
        "SIP/2.0 200 OK",
        &hdrs(
            &rvia,
            from,
            &to_t,
            cid,
            "1 INVITE",
            &[
                ("Contact", "<sip:2001@203.0.113.10:5060>".into()),
                ("Server", "EdgeSBC 9.1".into()),
                ("Session-Expires", "1800;refresher=uac".into()),
            ],
        ),
        &answer,
    );
    let t_ok = base + 3000;
    // Retransmitted 200 OK: 0.5, 1, 2, 4, 4, 4... until 32 s.
    let mut t = 0;
    let mut step = 500;
    s.sip(t_ok, sbc, ua, &ok);
    while t + step < 32_000 {
        t += step;
        s.sip(t_ok + t, sbc, ua, &ok);
        step = (step * 2).min(4000);
    }
    // Phone sends media from its public mapping; SBC media never reaches 192.168.1.50.
    s.rtp(
        t_ok + 40,
        "198.51.100.20:16384",
        "203.0.113.10:20000",
        8,
        0x3333_0001,
        1550,
        &|_| false,
        4,
        &[],
    );
    s.sip(
        t_ok + 32_000,
        sbc,
        ua,
        &sip_text(
            "BYE sip:3005@192.168.1.50:5060 SIP/2.0",
            &hdrs(
                "SIP/2.0/UDP 203.0.113.10:5060;branch=z9hG4bKsbcbye",
                &to_t,
                from,
                cid,
                "1 BYE",
                &[("Reason", "SIP;cause=408;text=\"ACK timeout\"".into())],
            ),
            "",
        ),
    );
}

/// Carrier rejects a G.729-only offer.
pub fn scenario_codec_488(s: &mut Synth) {
    let pbx = "10.20.0.1:5060";
    let carrier = "192.0.2.80:5060";
    let cid = "trunk-488@10.20.0.1";
    let from = "<sip:+351220000001@pbx.lab>;tag=t488";
    let to = "<sip:+4930123456@carrier.example>";
    let via = "SIP/2.0/UDP 10.20.0.1:5060;branch=z9hG4bK488a";
    let offer = sdp_body(
        "10.20.0.1",
        31000,
        "RTP/AVP",
        &[(18, "G729/8000")],
        &["a=fmtp:18 annexb=no"],
    );
    let base = 60_000;
    s.sip(
        base,
        pbx,
        carrier,
        &sip_text(
            "INVITE sip:+4930123456@carrier.example SIP/2.0",
            &hdrs(
                via,
                from,
                to,
                cid,
                "10 INVITE",
                &[("Contact", "<sip:+351220000001@10.20.0.1:5060>".into())],
            ),
            &offer,
        ),
    );
    s.sip(
        base + 40,
        carrier,
        pbx,
        &sip_text(
            "SIP/2.0 100 Trying",
            &hdrs(via, from, to, cid, "10 INVITE", &[]),
            "",
        ),
    );
    s.sip(
        base + 90,
        carrier,
        pbx,
        &sip_text(
            "SIP/2.0 488 Not Acceptable Here",
            &hdrs(
                via,
                from,
                &format!("{to};tag=c1"),
                cid,
                "10 INVITE",
                &[
                    (
                        "Warning",
                        "304 carrier.example \"Media type not available\"".into(),
                    ),
                    ("Reason", "Q.850;cause=65".into()),
                ],
            ),
            "",
        ),
    );
    s.sip(
        base + 95,
        pbx,
        carrier,
        &sip_text(
            "ACK sip:+4930123456@carrier.example SIP/2.0",
            &hdrs(via, from, &format!("{to};tag=c1"), cid, "10 ACK", &[]),
            "",
        ),
    );
}

/// Answered call with heavy loss, jitter and a dropout.
pub fn scenario_bad_quality(s: &mut Synth) {
    let a = "10.30.0.5:5060";
    let b = "10.30.0.9:5060";
    let cid = "q-77@10.30.0.5";
    let from = "<sip:4001@lab>;tag=q1";
    let to = "<sip:4002@lab>";
    let via = "SIP/2.0/UDP 10.30.0.5:5060;branch=z9hG4bKq1";
    let to_t = format!("{to};tag=q2");
    let base = 70_000;
    s.sip(
        base,
        a,
        b,
        &sip_text(
            "INVITE sip:4002@10.30.0.9 SIP/2.0",
            &hdrs(
                via,
                from,
                to,
                cid,
                "1 INVITE",
                &[("Contact", "<sip:4001@10.30.0.5>".into())],
            ),
            &sdp_body("10.30.0.5", 42000, "RTP/AVP", &[(0, "PCMU/8000")], &[]),
        ),
    );
    s.sip(
        base + 5,
        b,
        a,
        &sip_text(
            "SIP/2.0 100 Trying",
            &hdrs(via, from, to, cid, "1 INVITE", &[]),
            "",
        ),
    );
    s.sip(
        base + 700,
        b,
        a,
        &sip_text(
            "SIP/2.0 200 OK",
            &hdrs(
                via,
                from,
                &to_t,
                cid,
                "1 INVITE",
                &[("Contact", "<sip:4002@10.30.0.9>".into())],
            ),
            &sdp_body("10.30.0.9", 52000, "RTP/AVP", &[(0, "PCMU/8000")], &[]),
        ),
    );
    s.sip(
        base + 705,
        a,
        b,
        &sip_text(
            "ACK sip:4002@10.30.0.9 SIP/2.0",
            &hdrs(
                "SIP/2.0/UDP 10.30.0.5:5060;branch=z9hG4bKq1a",
                from,
                &to_t,
                cid,
                "1 ACK",
                &[],
            ),
            "",
        ),
    );
    s.rtp(
        base + 720,
        "10.30.0.5:42000",
        "10.30.0.9:52000",
        0,
        0x4444_0001,
        500,
        &|i| i % 14 == 3 || (i > 200 && i % 9 == 0),
        140,
        &[],
    );
    s.rtp(
        base + 725,
        "10.30.0.9:52000",
        "10.30.0.5:42000",
        0,
        0x5555_0001,
        500,
        &|i| (300..375).contains(&i),
        8,
        &[],
    );
    s.sip(
        base + 11_000,
        b,
        a,
        &sip_text(
            "BYE sip:4001@10.30.0.5 SIP/2.0",
            &hdrs(
                "SIP/2.0/UDP 10.30.0.9:5060;branch=z9hG4bKqb",
                &to_t,
                from,
                cid,
                "1 BYE",
                &[],
            ),
            "",
        ),
    );
    s.sip(
        base + 11_004,
        a,
        b,
        &sip_text(
            "SIP/2.0 200 OK",
            &hdrs(
                "SIP/2.0/UDP 10.30.0.9:5060;branch=z9hG4bKqb",
                &to_t,
                from,
                cid,
                "1 BYE",
                &[],
            ),
            "",
        ),
    );
}

/// REGISTER to an unreachable registrar from a different subnet (retransmissions only).
pub fn scenario_register_timeout(s: &mut Synth) {
    let ua = "192.168.56.1:51234";
    let reg = "192.168.10.30:5060";
    let text = sip_text(
        "REGISTER sip:192.168.10.30 SIP/2.0",
        &hdrs(
            "SIP/2.0/UDP 192.168.56.1:51234;branch=z9hG4bKrt1;rport",
            "\"7100\" <sip:7100@192.168.10.30>;tag=rt",
            "\"7100\" <sip:7100@192.168.10.30>",
            "rt-1@192.168.56.1",
            "1 REGISTER",
            &[
                ("Contact", "<sip:7100@192.168.56.1:51234>".into()),
                ("Expires", "3600".into()),
                ("User-Agent", "DeskSoft/2.4".into()),
            ],
        ),
        "",
    );
    let base = 90_000;
    for t in [
        0, 500, 1500, 3500, 7500, 11500, 15500, 19500, 23500, 27500, 31500,
    ] {
        s.sip(base + t, ua, reg, &text);
    }
}

fn dhcp_msg(
    op: u8,
    kind: u8,
    xid: u32,
    mac: [u8; 6],
    yiaddr: [u8; 4],
    opts: &[(u8, Vec<u8>)],
) -> Vec<u8> {
    let mut p = vec![0u8; 236];
    p[0] = op;
    p[1] = 1;
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[16..20].copy_from_slice(&yiaddr);
    p[28..34].copy_from_slice(&mac);
    p.extend_from_slice(&[99, 130, 83, 99, 53, 1, kind]);
    for (c, v) in opts {
        p.push(*c);
        p.push(v.len() as u8);
        p.extend_from_slice(v);
    }
    p.push(255);
    p
}

fn tftp_rrq(file: &str) -> Vec<u8> {
    let mut p = vec![0, 1];
    for part in [file, "octet"] {
        p.extend_from_slice(part.as_bytes());
        p.push(0);
    }
    p
}

/// Two Cisco phones booting: DHCP with and without option 150, TFTP
/// downloads that work, a file the server does not have, and a server that
/// does not answer.
pub fn scenario_phone_boot(s: &mut Synth) {
    let base = 120_000;
    let srv = "10.50.0.5";
    // Phone A: DHCP gives option 150, its file downloads (two blocks).
    let a_mac = [0x00, 0x1b, 0x54, 0xaa, 0xbb, 0xcc];
    let ask = vec![1, 3, 6, 15, 66, 150];
    s.udp(
        base,
        "0.0.0.0:68",
        "255.255.255.255:67",
        &dhcp_msg(1, 1, 0x1001, a_mac, [0; 4], &[(55, ask.clone())]),
    );
    let o150 = vec![(150, vec![10, 50, 0, 5]), (54, vec![10, 50, 0, 1])];
    s.udp(
        base + 5,
        "10.50.0.1:67",
        "255.255.255.255:68",
        &dhcp_msg(2, 2, 0x1001, a_mac, [10, 50, 0, 20], &o150),
    );
    s.udp(
        base + 10,
        "0.0.0.0:68",
        "255.255.255.255:67",
        &dhcp_msg(1, 3, 0x1001, a_mac, [0; 4], &[(55, ask.clone())]),
    );
    s.udp(
        base + 15,
        "10.50.0.1:67",
        "255.255.255.255:68",
        &dhcp_msg(2, 5, 0x1001, a_mac, [10, 50, 0, 20], &o150),
    );
    let pa = "10.50.0.20:50001";
    s.udp(
        base + 300,
        pa,
        &format!("{srv}:69"),
        &tftp_rrq("CTLSEP001B54AABBCC.tlv"),
    );
    let mut e = vec![0, 5, 0, 1];
    e.extend_from_slice(b"File not found\0");
    s.udp(base + 302, &format!("{srv}:40001"), pa, &e);
    let pa2 = "10.50.0.20:50002";
    s.udp(
        base + 400,
        pa2,
        &format!("{srv}:69"),
        &tftp_rrq("SEP001B54AABBCC.cnf.xml"),
    );
    let mut d1 = vec![0, 3, 0, 1];
    d1.extend(std::iter::repeat_n(b'x', 512));
    s.udp(base + 402, &format!("{srv}:40002"), pa2, &d1);
    s.udp(base + 403, pa2, &format!("{srv}:40002"), &[0, 4, 0, 1]);
    let mut d2 = vec![0, 3, 0, 2];
    d2.extend(std::iter::repeat_n(b'y', 100));
    s.udp(base + 405, &format!("{srv}:40002"), pa2, &d2);
    s.udp(base + 406, pa2, &format!("{srv}:40002"), &[0, 4, 0, 2]);
    // Phone B: the DHCP scope has no option 150 or 66.
    let b_mac = [0x00, 0x1b, 0x54, 0xdd, 0xee, 0xff];
    s.udp(
        base + 1000,
        "0.0.0.0:68",
        "255.255.255.255:67",
        &dhcp_msg(1, 3, 0x2002, b_mac, [0; 4], &[(55, ask)]),
    );
    s.udp(
        base + 1005,
        "10.50.0.1:67",
        "255.255.255.255:68",
        &dhcp_msg(
            2,
            5,
            0x2002,
            b_mac,
            [10, 50, 0, 21],
            &[(54, vec![10, 50, 0, 1])],
        ),
    );
    // Set by hand, the server has no file for it, and an old server is gone.
    let pb = "10.50.0.21:50010";
    s.udp(
        base + 1300,
        pb,
        &format!("{srv}:69"),
        &tftp_rrq("SEP001B54DDEEFF.cnf.xml"),
    );
    s.udp(base + 1302, &format!("{srv}:40003"), pb, &e);
    let pb2 = "10.50.0.21:50011";
    for t in [1500, 2500, 4500] {
        s.udp(
            base + t,
            pb2,
            "10.50.0.9:69",
            &tftp_rrq("SEP001B54DDEEFF.cnf.xml"),
        );
    }
}

/// SRTP offered, plain RTP answered.
pub fn scenario_srtp_mismatch(s: &mut Synth) {
    let a = "10.40.0.2:5060";
    let b = "10.40.0.3:5060";
    let cid = "srtp-1@10.40.0.2";
    let from = "<sip:5001@lab>;tag=s1";
    let to = "<sip:5002@lab>";
    let via = "SIP/2.0/UDP 10.40.0.2:5060;branch=z9hG4bKs1";
    let to_t = format!("{to};tag=s2");
    let base = 125_000;
    let offer = sdp_body(
        "10.40.0.2",
        44000,
        "RTP/SAVP",
        &[(0, "PCMU/8000"), (101, "telephone-event/8000")],
        &["a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"],
    );
    let answer = sdp_body("10.40.0.3", 54000, "RTP/AVP", &[(0, "PCMU/8000")], &[]);
    s.sip(
        base,
        a,
        b,
        &sip_text(
            "INVITE sip:5002@10.40.0.3 SIP/2.0",
            &hdrs(
                via,
                from,
                to,
                cid,
                "1 INVITE",
                &[("Contact", "<sip:5001@10.40.0.2>".into())],
            ),
            &offer,
        ),
    );
    s.sip(
        base + 8,
        b,
        a,
        &sip_text(
            "SIP/2.0 200 OK",
            &hdrs(
                via,
                from,
                &to_t,
                cid,
                "1 INVITE",
                &[("Contact", "<sip:5002@10.40.0.3>".into())],
            ),
            &answer,
        ),
    );
    s.sip(
        base + 12,
        a,
        b,
        &sip_text(
            "ACK sip:5002@10.40.0.3 SIP/2.0",
            &hdrs(
                "SIP/2.0/UDP 10.40.0.2:5060;branch=z9hG4bKs1a",
                from,
                &to_t,
                cid,
                "1 ACK",
                &[],
            ),
            "",
        ),
    );
    s.rtp(
        base + 30,
        "10.40.0.3:54000",
        "10.40.0.2:44000",
        0,
        0x6666_0001,
        150,
        &|_| false,
        1,
        &[],
    );
    s.sip(
        base + 3200,
        a,
        b,
        &sip_text(
            "BYE sip:5002@10.40.0.3 SIP/2.0",
            &hdrs(
                "SIP/2.0/UDP 10.40.0.2:5060;branch=z9hG4bKs1b",
                from,
                &to_t,
                cid,
                "2 BYE",
                &[],
            ),
            "",
        ),
    );
    s.sip(
        base + 3204,
        b,
        a,
        &sip_text(
            "SIP/2.0 200 OK",
            &hdrs(
                "SIP/2.0/UDP 10.40.0.2:5060;branch=z9hG4bKs1b",
                from,
                &to_t,
                cid,
                "2 BYE",
                &[],
            ),
            "",
        ),
    );
}

fn report_block((ssrc, fraction, jitter, lsr, dlsr): (u32, u8, u32, u32, u32)) -> Vec<u8> {
    let mut b = ssrc.to_be_bytes().to_vec();
    let cum = (fraction as u32) * 2;
    b.extend_from_slice(&[fraction, (cum >> 16) as u8, (cum >> 8) as u8, cum as u8]);
    b.extend_from_slice(&1000u32.to_be_bytes());
    b.extend_from_slice(&jitter.to_be_bytes());
    b.extend_from_slice(&lsr.to_be_bytes());
    b.extend_from_slice(&dlsr.to_be_bytes());
    b
}

/// A call through an SBC: the phone leg and the carrier leg (X-CID names the
/// first), RTCP with round trip and loss reported by the carrier, and carrier
/// audio that flows but is silent.
pub fn scenario_sbc_legs(s: &mut Synth) {
    let phone = "10.40.1.10:5060";
    let sbc_in = "10.40.1.1:5060";
    let sbc_out = "192.0.2.1:5060";
    let carrier = "198.51.100.7:5060";
    let base = 150_000;
    let call = |s: &mut Synth,
                t: i64,
                a: &str,
                b: &str,
                cid: &str,
                from: &str,
                to: &str,
                ruri: &str,
                ip_a: &str,
                port_a: u16,
                ip_b: &str,
                port_b: u16,
                extra: &[(&str, String)],
                tag: &str| {
        let via = format!("SIP/2.0/UDP {a};branch=z9hG4bK{tag}");
        let to_t = format!("{to};tag={tag}b");
        let mut h: Vec<(&str, String)> = vec![("Contact", format!("<sip:x@{a}>"))];
        h.extend(extra.iter().cloned());
        s.sip(
            t,
            a,
            b,
            &sip_text(
                &format!("INVITE {ruri} SIP/2.0"),
                &hdrs(&via, from, to, cid, "1 INVITE", &h),
                &sdp_body(
                    ip_a,
                    port_a,
                    "RTP/AVP",
                    &[(0, "PCMU/8000"), (101, "telephone-event/8000")],
                    &[],
                ),
            ),
        );
        s.sip(
            t + 3,
            b,
            a,
            &sip_text(
                "SIP/2.0 100 Trying",
                &hdrs(&via, from, to, cid, "1 INVITE", &[]),
                "",
            ),
        );
        s.sip(
            t + 900,
            b,
            a,
            &sip_text(
                "SIP/2.0 180 Ringing",
                &hdrs(&via, from, &to_t, cid, "1 INVITE", &[]),
                "",
            ),
        );
        s.sip(
            t + 2500,
            b,
            a,
            &sip_text(
                "SIP/2.0 200 OK",
                &hdrs(
                    &via,
                    from,
                    &to_t,
                    cid,
                    "1 INVITE",
                    &[("Contact", format!("<sip:y@{b}>"))],
                ),
                &sdp_body(
                    ip_b,
                    port_b,
                    "RTP/AVP",
                    &[(0, "PCMU/8000"), (101, "telephone-event/8000")],
                    &[],
                ),
            ),
        );
        let via2 = format!("SIP/2.0/UDP {a};branch=z9hG4bK{tag}ack");
        s.sip(
            t + 2510,
            a,
            b,
            &sip_text(
                &format!("ACK {ruri} SIP/2.0"),
                &hdrs(&via2, from, &to_t, cid, "1 ACK", &[]),
                "",
            ),
        );
        let via3 = format!("SIP/2.0/UDP {a};branch=z9hG4bK{tag}bye");
        s.sip(
            t + 14500,
            a,
            b,
            &sip_text(
                &format!("BYE {ruri} SIP/2.0"),
                &hdrs(&via3, from, &to_t, cid, "2 BYE", &[]),
                "",
            ),
        );
        s.sip(
            t + 14510,
            b,
            a,
            &sip_text(
                "SIP/2.0 200 OK",
                &hdrs(&via3, from, &to_t, cid, "2 BYE", &[]),
                "",
            ),
        );
    };
    let from = "\"Desk 7001\" <sip:7001@corp.example>;tag=pa";
    call(
        s,
        base,
        phone,
        sbc_in,
        "leg-a-7001@10.40.1.10",
        from,
        "<sip:+5511987654321@corp.example>",
        "sip:+5511987654321@corp.example",
        "10.40.1.10",
        30000,
        "10.40.1.1",
        40000,
        &[("User-Agent", "DeskPhone 5.1".into())],
        "la",
    );
    call(
        s,
        base + 40,
        sbc_out,
        carrier,
        "b2b-91f3c2@192.0.2.1",
        "<sip:+551130001234@192.0.2.1>;tag=pb",
        "<sip:+5511987654321@carrier.example>",
        "sip:+5511987654321@carrier.example",
        "192.0.2.1",
        50000,
        "198.51.100.7",
        60000,
        &[
            ("X-CID", "leg-a-7001@10.40.1.10".into()),
            ("User-Agent", "EdgeSBC 9.1".into()),
        ],
        "lb",
    );
    // Media: the phone talks, the carrier's audio arrives as digital silence.
    s.silent.push(0x5000_0004);
    let t = base + 2520;
    s.rtp(
        t,
        "10.40.1.10:30000",
        "10.40.1.1:40000",
        0,
        0x5000_0001,
        600,
        &|_| false,
        1,
        &[],
    );
    s.rtp(
        t,
        "10.40.1.1:40000",
        "10.40.1.10:30000",
        0,
        0x5000_0002,
        600,
        &|_| false,
        1,
        &[],
    );
    s.rtp(
        t,
        "192.0.2.1:50000",
        "198.51.100.7:60000",
        0,
        0x5000_0003,
        600,
        &|_| false,
        2,
        &[],
    );
    s.rtp(
        t,
        "198.51.100.7:60000",
        "192.0.2.1:50000",
        0,
        0x5000_0004,
        600,
        &|_| false,
        2,
        &[],
    );
    // RTCP every 5 s: the SBC sends SRs; the carrier reports 8% loss and 9 ms
    // jitter on the SBC's stream; round trip SBC <-> carrier about 180 ms.
    for k in 1..=2i64 {
        let ts = t + k * 5000;
        let ntp = 0x1000_0000u32 + k as u32 * 0x0005_0000;
        s.rtcp_sr(
            ts,
            "192.0.2.1:50001",
            "198.51.100.7:60001",
            0x5000_0003,
            ntp,
            250 * k as u32,
            None,
        );
        s.rtcp_rr(
            ts + 200,
            "198.51.100.7:60001",
            "192.0.2.1:50001",
            0x5000_0004,
            (0x5000_0003, 20, 72, ntp, 1311),
        );
        s.rtcp_sr(
            ts + 10,
            "10.40.1.10:30001",
            "10.40.1.1:40001",
            0x5000_0001,
            ntp + 7,
            250 * k as u32,
            Some((0x5000_0002, 0, 8, 0, 0)),
        );
    }
}

pub const SCENARIOS: &[(&str, &str)] = &[
    (
        "sbc-legs",
        "Call through an SBC: two legs linked by X-CID, RTCP with round trip and loss, silent carrier audio",
    ),
    (
        "good-call",
        "Registration with digest auth and a clean call with RFC 4733 DTMF",
    ),
    (
        "nat-one-way",
        "Remote phone behind NAT: private SDP, missing ACK, one-way audio, drop at 32 s",
    ),
    ("codec-488", "Carrier rejects a G.729-only offer with 488"),
    (
        "bad-quality",
        "Answered call with packet loss, jitter and a dropout",
    ),
    (
        "register-timeout",
        "REGISTER retransmitted to a registrar that never answers",
    ),
    ("srtp-mismatch", "SRTP offered, plain RTP answered"),
    (
        "phone-boot",
        "Cisco phones booting: DHCP option 150, TFTP downloads, a missing SEP file and a dead server",
    ),
    ("demo", "All scenarios in one capture"),
];

/// Generates a scenario capture as pcapng bytes.
pub fn generate(name: &str) -> Option<Vec<u8>> {
    let mut s = Synth::new(0);
    match name {
        "good-call" => scenario_good_call(&mut s),
        "nat-one-way" => scenario_nat_one_way(&mut s),
        "codec-488" => scenario_codec_488(&mut s),
        "bad-quality" => scenario_bad_quality(&mut s),
        "register-timeout" => scenario_register_timeout(&mut s),
        "srtp-mismatch" => scenario_srtp_mismatch(&mut s),
        "sbc-legs" => scenario_sbc_legs(&mut s),
        "phone-boot" => scenario_phone_boot(&mut s),
        "demo" => {
            scenario_good_call(&mut s);
            scenario_nat_one_way(&mut s);
            scenario_codec_488(&mut s);
            scenario_bad_quality(&mut s);
            scenario_register_timeout(&mut s);
            scenario_srtp_mismatch(&mut s);
            scenario_sbc_legs(&mut s);
            scenario_phone_boot(&mut s);
        }
        _ => return None,
    }
    Some(s.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{analyze_bytes, CallState};

    fn rules_of(name: &str) -> Vec<String> {
        let r = analyze_bytes(&generate(name).unwrap()).unwrap();
        r.findings.iter().map(|f| f.rule.clone()).collect()
    }

    #[test]
    fn good_call_is_clean() {
        let r = analyze_bytes(&generate("good-call").unwrap()).unwrap();
        assert_eq!(r.calls.len(), 2);
        let c = &r.calls[1];
        assert_eq!(c.state, CallState::Answered);
        assert_eq!(c.streams.len(), 2);
        assert_eq!(r.summary.errors, 0, "{:#?}", r.findings);
        let s = &r.streams[c.streams[0]];
        assert_eq!(s.loss_pct, 0.0);
        let dtmf: Vec<String> = r
            .streams
            .iter()
            .flat_map(|s| s.dtmf_events.clone())
            .collect();
        assert_eq!(dtmf.join(""), "123#");
        assert!((c.pdd_ms.unwrap() - 900.0).abs() < 1.0);
    }

    #[test]
    fn nat_scenario_detects_root_causes() {
        let rules = rules_of("nat-one-way");
        for want in [
            "sip.200_retransmitted",
            "sip.no_ack",
            "sip.drop_32s",
            "sdp.private_ip",
            "sip.contact_private",
            "rtp.one_way",
            "rtp.asymmetric",
        ] {
            assert!(
                rules.iter().any(|r| r == want),
                "missing {want} in {rules:?}"
            );
        }
    }

    #[test]
    fn sbc_legs_are_linked_with_rtcp_and_silence() {
        let r = crate::analysis::analyze_bytes(&generate("sbc-legs").unwrap()).unwrap();
        let invites: Vec<_> = r.calls.iter().filter(|c| c.kind == "INVITE").collect();
        assert_eq!(invites.len(), 2);
        assert_eq!(
            invites[0].related,
            vec![invites[1].index],
            "X-CID links the legs"
        );
        let out = r.streams.iter().find(|s| s.ssrc == "0x50000003").unwrap();
        assert_eq!(out.remote_loss_pct, Some(7.81));
        let rtt = out.rtt_ms.unwrap();
        assert!((rtt - 180.0).abs() < 2.0, "rtt {rtt}");
        assert!(
            out.series.len() >= 11 && out.series[3][1] >= 49.0,
            "{:?}",
            &out.series[..4]
        );
        let silent = r.streams.iter().find(|s| s.ssrc == "0x50000004").unwrap();
        assert!(silent.silence_pct.unwrap() > 99.0);
        let rules = rules_of("sbc-legs");
        for want in ["rtp.silent", "rtcp.loss"] {
            assert!(rules.iter().any(|x| x == want), "{want} in {rules:?}");
        }
    }

    #[test]
    fn other_scenarios() {
        assert!(rules_of("codec-488").iter().any(|r| r == "sip.call_failed"));
        let q = rules_of("bad-quality");
        assert!(q.iter().any(|r| r == "rtp.loss"), "{q:?}");
        assert!(q.iter().any(|r| r == "rtp.jitter"), "{q:?}");
        assert!(q.iter().any(|r| r == "rtp.gap"), "{q:?}");
        assert!(rules_of("register-timeout")
            .iter()
            .any(|r| r == "sip.no_response"));
        assert!(rules_of("srtp-mismatch")
            .iter()
            .any(|r| r == "sdp.srtp_mismatch"));
    }

    #[test]
    fn export_roundtrip_with_redaction() {
        use crate::export::{export_pcapng, ExportOptions};
        let r = analyze_bytes(&generate("nat-one-way").unwrap()).unwrap();
        let out = export_pcapng(
            &r,
            &ExportOptions {
                annotate: true,
                redact: Some(Default::default()),
                call: Some(0),
                sip_only: false,
            },
        );
        let r2 = analyze_bytes(&out).unwrap();
        assert_eq!(r2.calls.len(), 1);
        assert!(r2.messages.iter().all(|m| !m.raw.contains("198.51.100.20")));
        assert!(r2.capture.packets.iter().any(|p| p.comment.is_some()));
        assert_eq!(r2.streams.len(), 1);
    }
}

/// One SIP message seen by a client that has no packet access (browser web phone).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LogEntry {
    /// Unix epoch milliseconds (fractional allowed).
    pub t_ms: f64,
    /// True when sent by the client.
    pub out: bool,
    pub text: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SipLog {
    /// Client address to show in the capture (the browser has none; any placeholder works).
    pub local: String,
    /// Server address, e.g. the WebSocket host:port.
    pub remote: String,
    /// Note added as packet comment, e.g. "SIP over WebSocket wss://pbx/ws".
    #[serde(default)]
    pub note: Option<String>,
    pub entries: Vec<LogEntry>,
}

/// Turns a SIP message log into a pcapng (UDP framing) so it can be analyzed and opened in Wireshark.
pub fn capture_from_log(log: &SipLog) -> Result<Vec<u8>, String> {
    let local: SocketAddr = log
        .local
        .parse()
        .map_err(|_| format!("bad local address {}", log.local))?;
    let remote: SocketAddr = log
        .remote
        .parse()
        .map_err(|_| format!("bad remote address {}", log.remote))?;
    let pkts: Vec<(i64, Vec<u8>)> = log
        .entries
        .iter()
        .map(|e| {
            let (s, d) = if e.out {
                (local, remote)
            } else {
                (remote, local)
            };
            (
                (e.t_ms * 1e6) as i64,
                build_udp_packet(s, d, e.text.as_bytes()),
            )
        })
        .collect();
    let out: Vec<OutPacket<'_>> = pkts
        .iter()
        .enumerate()
        .map(|(i, (t, d))| OutPacket {
            ts_ns: *t,
            linktype: LINKTYPE_RAW,
            data: d,
            orig_len: d.len() as u32,
            comment: if i == 0 { log.note.clone() } else { None },
        })
        .collect();
    Ok(write_pcapng(
        &out,
        &PcapngOptions {
            user_appl: Some("Sidetone web phone".into()),
            section_comment: log.note.clone(),
            ..Default::default()
        },
    ))
}

#[cfg(test)]
mod dtls_tests {
    use super::*;
    use crate::analysis::analyze_bytes;

    #[test]
    fn webrtc_dtls_offer_is_not_flagged_as_missing_crypto() {
        let mut s = Synth::new(0);
        let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\nm=audio 4000 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\na=fingerprint:sha-256 AA:BB\r\na=setup:actpass\r\na=rtcp-mux\r\n";
        let answer = "v=0\r\no=- 1 1 IN IP4 192.0.2.3\r\ns=-\r\nc=IN IP4 192.0.2.3\r\nt=0 0\r\nm=audio 5000 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\na=fingerprint:sha-256 CC:DD\r\na=setup:active\r\na=rtcp-mux\r\n";
        let h = |cseq: &str, to: &str| {
            hdrs(
                "SIP/2.0/WSS x.invalid;branch=z9hG4bKw1",
                "<sip:a@lab>;tag=1",
                to,
                "w1",
                cseq,
                &[("Contact", "<sip:a@x.invalid;transport=ws>".into())],
            )
        };
        s.sip(
            0,
            "192.0.2.10:50000",
            "192.0.2.20:443",
            &sip_text(
                "INVITE sip:b@lab SIP/2.0",
                &h("1 INVITE", "<sip:b@lab>"),
                offer,
            ),
        );
        s.sip(
            10,
            "192.0.2.20:443",
            "192.0.2.10:50000",
            &sip_text(
                "SIP/2.0 200 OK",
                &h("1 INVITE", "<sip:b@lab>;tag=2"),
                answer,
            ),
        );
        let r = analyze_bytes(&s.finish()).unwrap();
        assert!(
            !r.findings
                .iter()
                .any(|f| f.rule.starts_with("sdp.srtp") || f.rule.starts_with("sdp.dtls")),
            "{:#?}",
            r.findings
        );
    }
}

fn lin2ulaw(x: i16) -> u8 {
    let mut s = x as i32;
    let sign = if s < 0 {
        s = -s;
        0x80
    } else {
        0
    };
    s = (s + 0x84).min(32635 + 0x84);
    let exp = (31 - (s as u32).leading_zeros()).saturating_sub(7).min(7);
    let mant = (s >> (exp + 3)) & 0x0f;
    !(sign | (exp << 4) as i32 | mant) as u8
}

fn lin2alaw(x: i16) -> u8 {
    let mut s = x as i32;
    let sign = if s >= 0 {
        0x80
    } else {
        s = -s - 1;
        0
    };
    s = s.min(32767);
    let v = if s < 256 {
        s >> 4
    } else {
        let exp = (31 - (s as u32).leading_zeros()) - 7;
        ((exp as i32) << 4) | ((s >> (exp + 3)) & 0x0f)
    };
    ((sign | v) ^ 0x55) as u8
}

#[cfg(test)]
mod g711_tests {
    use super::{lin2alaw, lin2ulaw};
    use crate::audio::{alaw, ulaw};

    #[test]
    fn g711_round_trip() {
        for x in [-30000i16, -5000, -300, -20, 0, 20, 300, 5000, 30000] {
            let u = ulaw(lin2ulaw(x)) as i32;
            let a = alaw(lin2alaw(x)) as i32;
            let tol = (x as i32).abs() / 16 + 40;
            assert!((u - x as i32).abs() <= tol, "ulaw {x} -> {u}");
            assert!((a - x as i32).abs() <= tol, "alaw {x} -> {a}");
        }
    }

    #[test]
    fn phone_boot_dhcp_and_tftp() {
        let r = crate::analyze_bytes(&super::generate("phone-boot").unwrap()).unwrap();
        let p = &r.provisioning;
        let tftp: Vec<(&str, &str, u64)> = p
            .iter()
            .filter(|e| e.kind == "tftp")
            .map(|e| (e.file.as_deref().unwrap(), e.outcome.as_str(), e.bytes))
            .collect();
        assert_eq!(
            tftp,
            vec![
                ("CTLSEP001B54AABBCC.tlv", "error", 0),
                ("SEP001B54AABBCC.cnf.xml", "ok", 612),
                ("SEP001B54DDEEFF.cnf.xml", "error", 0),
                ("SEP001B54DDEEFF.cnf.xml", "no answer", 0),
            ]
        );
        let dhcp: Vec<_> = p.iter().filter(|e| e.kind == "dhcp").collect();
        assert_eq!(dhcp.len(), 2);
        assert_eq!(dhcp[0].option150, vec!["10.50.0.5"]);
        let rules: Vec<&str> = r.findings.iter().map(|f| f.rule.as_str()).collect();
        for want in [
            "dhcp.tftp",
            "dhcp.no_tftp",
            "tftp.ok",
            "tftp.optional_missing",
            "tftp.error",
            "tftp.no_answer",
        ] {
            assert!(rules.contains(&want), "{want} missing in {rules:?}");
        }
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "tftp.error" && f.detail.contains("MAC")));
    }
}
