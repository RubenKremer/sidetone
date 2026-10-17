//! Turns a capture into SIP messages, calls (dialogs grouped by Call-ID),
//! RTP streams and findings.

use crate::net::{self, Transport};
use crate::pcap::{read_capture, Capture, CaptureFormat, PcapError, RawPacket};
use crate::rtp::{self, RtpObs, RtpStream};
use crate::rules;
use crate::sdp::{self, Sdp};
use crate::sip::{self, SipMessage, Uri};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub call: Option<usize>,
    pub messages: Vec<usize>,
    pub stream: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub index: usize,
    /// 1-based frame number in the source capture (as Wireshark shows it).
    pub frame: usize,
    pub ts_ns: i64,
    pub rel_s: f64,
    pub src: String,
    pub dst: String,
    pub transport: Transport,
    pub summary: String,
    pub label: String,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub call_id: Option<String>,
    pub cseq: Option<String>,
    pub branch: Option<String>,
    pub raw: String,
    pub parse_notes: Vec<String>,
    pub call: Option<usize>,
    pub retransmission: bool,
    pub sdp: Option<Sdp>,
    #[serde(skip)]
    pub sip: SipMessage,
    #[serde(skip)]
    pub src_addr: SocketAddr,
    #[serde(skip)]
    pub dst_addr: SocketAddr,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallState {
    Answered,
    Failed,
    Cancelled,
    InProgress,
    NonInvite,
}

#[derive(Debug, Clone, Serialize)]
pub struct Call {
    pub index: usize,
    pub call_id: String,
    pub kind: String,
    pub from: String,
    pub to: String,
    pub request_uri: String,
    pub state: CallState,
    pub final_status: Option<u16>,
    pub final_reason: Option<String>,
    pub start_ns: i64,
    pub end_ns: i64,
    pub start_rel_s: f64,
    pub pdd_ms: Option<f64>,
    pub setup_ms: Option<f64>,
    pub talk_s: Option<f64>,
    pub ended_by: Option<String>,
    pub reason: Option<String>,
    pub user_agents: Vec<String>,
    pub offer_codecs: Vec<String>,
    pub answer_codecs: Vec<String>,
    pub messages: Vec<usize>,
    pub streams: Vec<usize>,
    pub caller: String,
    pub callee: String,
    pub errors: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Summary {
    pub format: Option<CaptureFormat>,
    pub packets: usize,
    pub sip_messages: usize,
    pub calls: usize,
    pub rtp_streams: usize,
    pub rtcp_packets: usize,
    pub tls_packets: usize,
    pub undecoded_packets: usize,
    pub start_ns: i64,
    pub end_ns: i64,
    pub duration_s: f64,
    pub tls_keylog_lines: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub summary: Summary,
    pub calls: Vec<Call>,
    pub messages: Vec<Message>,
    pub streams: Vec<RtpStream>,
    pub findings: Vec<Finding>,
    #[serde(skip)]
    pub capture: Capture,
}

/// Parses capture bytes and runs the full analysis.
pub fn analyze_bytes(bytes: &[u8]) -> Result<Report, PcapError> {
    let cap = read_capture(bytes)?;
    Ok(analyze_capture(cap))
}

type FlowKey = (SocketAddr, SocketAddr);

struct TcpFlow {
    buf: Vec<u8>,
    next_seq: Option<u32>,
}

pub fn analyze_capture(cap: Capture) -> Report {
    let mut summary = Summary {
        format: Some(cap.format),
        packets: cap.packets.len(),
        tls_keylog_lines: cap.tls_keylog.len(),
        ..Default::default()
    };
    let start_ns = cap.packets.iter().map(|p| p.ts_ns).min().unwrap_or(0);
    let end_ns = cap.packets.iter().map(|p| p.ts_ns).max().unwrap_or(0);
    summary.start_ns = start_ns;
    summary.end_ns = end_ns;
    summary.duration_s = (end_ns - start_ns) as f64 / 1e9;

    let mut messages: Vec<Message> = Vec::new();
    let mut rtp_flows: BTreeMap<(SocketAddr, SocketAddr, u32), Vec<RtpObs>> = BTreeMap::new();
    let mut tcp: HashMap<FlowKey, TcpFlow> = HashMap::new();

    for (i, p) in cap.packets.iter().enumerate() {
        let frame = i + 1;
        let Some(d) = net::decode(p.linktype, &p.data) else {
            summary.undecoded_packets += 1;
            continue;
        };
        match d.transport {
            Transport::Udp => {
                if sip::looks_like_sip(d.payload) {
                    if let Some(m) = sip::parse_datagram(d.payload) {
                        push_message(
                            &mut messages,
                            m,
                            frame,
                            p,
                            d.src,
                            d.dst,
                            Transport::Udp,
                            start_ns,
                        );
                    }
                } else if rtp::is_rtcp(d.payload) {
                    summary.rtcp_packets += 1;
                } else if let Some(h) = rtp::parse_rtp(d.payload) {
                    let mut head = [0u8; 4];
                    let pl = &d.payload[h.payload_offset..];
                    for (k, b) in pl.iter().take(4).enumerate() {
                        head[k] = *b;
                    }
                    rtp_flows
                        .entry((d.src, d.dst, h.ssrc))
                        .or_default()
                        .push(RtpObs {
                            frame,
                            arrival_ns: p.ts_ns,
                            hdr: h,
                            payload_len: pl.len(),
                            head,
                        });
                }
            }
            Transport::Tcp => {
                if d.payload.is_empty() {
                    continue;
                }
                if d.payload[0] == 0x16 || d.payload[0] == 0x17 || d.payload[0] == 0x15 {
                    // TLS record (handshake, application data, alert).
                    summary.tls_packets += 1;
                    continue;
                }
                let flow = tcp.entry((d.src, d.dst)).or_insert(TcpFlow {
                    buf: Vec::new(),
                    next_seq: None,
                });
                let mut payload = d.payload;
                if let Some(ns) = flow.next_seq {
                    let delta = d.tcp_seq.wrapping_sub(ns) as i32;
                    if delta < 0 {
                        // Retransmitted or overlapping segment: keep only new bytes.
                        let overlap = (-delta) as usize;
                        if overlap >= payload.len() {
                            continue;
                        }
                        payload = &payload[overlap..];
                    }
                }
                flow.next_seq = Some(d.tcp_seq.wrapping_add(d.payload.len() as u32));
                flow.buf.extend_from_slice(payload);
                if !sip::looks_like_sip(&flow.buf) {
                    // Not SIP (or mid-stream start): drop until a SIP start line appears.
                    if let Some(pos) = find_sip_start(&flow.buf) {
                        flow.buf.drain(..pos);
                    } else {
                        if flow.buf.len() > 65536 {
                            flow.buf.clear();
                        }
                        continue;
                    }
                }
                let (msgs, used) = sip::parse_stream(&flow.buf);
                flow.buf.drain(..used);
                for m in msgs {
                    push_message(
                        &mut messages,
                        m,
                        frame,
                        p,
                        d.src,
                        d.dst,
                        Transport::Tcp,
                        start_ns,
                    );
                }
            }
        }
    }
    summary.sip_messages = messages.len();

    mark_retransmissions(&mut messages);

    // Group into calls by Call-ID, in order of first appearance.
    let mut call_order: Vec<String> = Vec::new();
    let mut by_cid: HashMap<String, Vec<usize>> = HashMap::new();
    for m in &messages {
        if let Some(cid) = &m.call_id {
            if !by_cid.contains_key(cid) {
                call_order.push(cid.clone());
            }
            by_cid.entry(cid.clone()).or_default().push(m.index);
        }
    }
    let mut calls: Vec<Call> = Vec::new();
    for cid in &call_order {
        let idxs = &by_cid[cid];
        let ci = calls.len();
        for &mi in idxs {
            messages[mi].call = Some(ci);
        }
        calls.push(build_call(ci, cid, idxs, &messages, start_ns));
    }

    // RTP streams and association to calls through SDP endpoints.
    let mut streams: Vec<RtpStream> = Vec::new();
    let endpoint_map = sdp_endpoints(&calls, &messages);
    for ((src, dst, _ssrc), obs) in rtp_flows.iter() {
        let call = associate(*src, *dst, obs, &endpoint_map, &calls);
        // Unassociated flows must look convincingly like RTP to avoid false positives.
        if call.is_none() && !plausible_rtp(obs) {
            continue;
        }
        let media = call.and_then(|c| media_for(&calls[c], &messages, *src, *dst));
        let dtmf_pt = media.as_ref().and_then(|m| {
            m.codecs
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case("telephone-event"))
                .map(|c| c.pt)
        });
        let clock_of = |pt: u8| {
            media
                .as_ref()
                .map(|m| m.clock_rate(pt))
                .unwrap_or_else(|| sdp::static_codec(pt).map(|c| c.1).unwrap_or(8000))
        };
        let name_of = |pt: u8| {
            media.as_ref().map(|m| m.codec_name(pt)).unwrap_or_else(|| {
                sdp::static_codec(pt)
                    .map(|c| c.0.to_string())
                    .unwrap_or_else(|| format!("PT{pt}"))
            })
        };
        let mut s =
            rtp::compute_stream(streams.len(), *src, *dst, obs, &clock_of, &name_of, dtmf_pt);
        s.call = call;
        if let Some(c) = call {
            calls[c].streams.push(s.id);
        }
        streams.push(s);
    }
    summary.rtp_streams = streams.len();
    summary.calls = calls.len();

    let mut report = Report {
        tool: "sidetone".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        summary,
        calls,
        messages,
        streams,
        findings: Vec::new(),
        capture: cap,
    };
    let findings = rules::run_all(&report);
    report.findings = findings;
    for f in &report.findings {
        match f.severity {
            Severity::Error => report.summary.errors += 1,
            Severity::Warning => report.summary.warnings += 1,
            Severity::Info => report.summary.infos += 1,
        }
        if let Some(c) = f.call {
            match f.severity {
                Severity::Error => report.calls[c].errors += 1,
                Severity::Warning => report.calls[c].warnings += 1,
                Severity::Info => {}
            }
        }
    }
    report
}

fn find_sip_start(b: &[u8]) -> Option<usize> {
    (0..b.len()).find(|&i| (i == 0 || b[i - 1] == b'\n') && sip::looks_like_sip(&b[i..]))
}

#[allow(clippy::too_many_arguments)]
fn push_message(
    messages: &mut Vec<Message>,
    m: SipMessage,
    frame: usize,
    p: &RawPacket,
    src: SocketAddr,
    dst: SocketAddr,
    transport: Transport,
    start_ns: i64,
) {
    let sdp = if m.has_sdp() {
        sdp::parse(&m.body)
    } else {
        None
    };
    let cseq = m.cseq().map(|(n, me)| format!("{n} {me}"));
    messages.push(Message {
        index: messages.len(),
        frame,
        ts_ns: p.ts_ns,
        rel_s: (p.ts_ns - start_ns) as f64 / 1e9,
        src: src.to_string(),
        dst: dst.to_string(),
        transport,
        summary: m.summary(),
        label: m.label(),
        method: m.method().map(|s| s.to_string()),
        status: m.status(),
        call_id: m.call_id().map(|s| s.to_string()),
        cseq,
        branch: m.top_via().and_then(|v| v.branch),
        raw: m.raw.clone(),
        parse_notes: m.parse_notes.clone(),
        call: None,
        retransmission: false,
        sdp,
        sip: m,
        src_addr: src,
        dst_addr: dst,
    });
}

fn mark_retransmissions(messages: &mut [Message]) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for m in messages.iter_mut() {
        let key = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            m.src,
            m.dst,
            m.method.clone().unwrap_or_default(),
            m.status.map(|s| s.to_string()).unwrap_or_default(),
            m.cseq.clone().unwrap_or_default(),
            m.branch.clone().unwrap_or_default(),
            m.call_id.clone().unwrap_or_default()
        );
        let n = seen.entry(key).or_insert(0);
        if *n > 0 {
            m.retransmission = true;
        }
        *n += 1;
    }
}

fn uri_short(v: Option<&str>) -> String {
    v.and_then(Uri::from_header)
        .map(|u| u.short())
        .unwrap_or_default()
}

fn build_call(index: usize, cid: &str, idxs: &[usize], msgs: &[Message], cap_start: i64) -> Call {
    let first = &msgs[idxs[0]];
    let first_req = idxs.iter().map(|&i| &msgs[i]).find(|m| m.sip.is_request());
    let kind = first_req
        .and_then(|m| m.method.clone())
        .or_else(|| first.sip.cseq().map(|c| c.1))
        .unwrap_or_else(|| "UNKNOWN".into());
    let from = uri_short(first.sip.header("From"));
    let to = uri_short(first.sip.header("To"));
    let request_uri = first_req
        .and_then(|m| m.sip.request_uri())
        .unwrap_or("")
        .to_string();
    let start_ns = first.ts_ns;
    let end_ns = idxs
        .iter()
        .map(|&i| msgs[i].ts_ns)
        .max()
        .unwrap_or(start_ns);

    let mut user_agents: Vec<String> = Vec::new();
    for &i in idxs {
        for h in ["User-Agent", "Server"] {
            if let Some(v) = msgs[i].sip.header(h) {
                if !user_agents.iter().any(|u| u == v) {
                    user_agents.push(v.to_string());
                }
            }
        }
    }

    let caller = first_req.map(|m| m.src.clone()).unwrap_or_default();
    let callee = first_req.map(|m| m.dst.clone()).unwrap_or_default();

    let mut call = Call {
        index,
        call_id: cid.to_string(),
        kind: kind.clone(),
        from,
        to,
        request_uri,
        state: CallState::NonInvite,
        final_status: None,
        final_reason: None,
        start_ns,
        end_ns,
        start_rel_s: (start_ns - cap_start) as f64 / 1e9,
        pdd_ms: None,
        setup_ms: None,
        talk_s: None,
        ended_by: None,
        reason: None,
        user_agents,
        offer_codecs: Vec::new(),
        answer_codecs: Vec::new(),
        messages: idxs.to_vec(),
        streams: Vec::new(),
        caller: caller.clone(),
        callee,
        errors: 0,
        warnings: 0,
    };

    let ms: Vec<&Message> = idxs.iter().map(|&i| &msgs[i]).collect();
    if kind == "INVITE" {
        let first_invite = ms
            .iter()
            .find(|m| m.method.as_deref() == Some("INVITE") && m.sip.to_tag().is_none());
        // The last initial INVITE (after any auth challenge) decides the outcome.
        let initial_invites: Vec<&&Message> = ms
            .iter()
            .filter(|m| {
                m.method.as_deref() == Some("INVITE")
                    && m.sip.to_tag().is_none()
                    && !m.retransmission
            })
            .collect();
        let last_invite = initial_invites.last();
        let inv_cseqs: Vec<u32> = initial_invites
            .iter()
            .filter_map(|m| m.sip.cseq().map(|c| c.0))
            .collect();
        let finals: Vec<&&Message> = ms
            .iter()
            .filter(|m| {
                m.status.map(|s| s >= 200).unwrap_or(false)
                    && m.sip
                        .cseq()
                        .map(|c| c.1 == "INVITE" && inv_cseqs.contains(&c.0))
                        .unwrap_or(false)
            })
            .collect();
        let last_cseq = last_invite.and_then(|m| m.sip.cseq().map(|c| c.0));
        let final_for_last = finals.iter().find(|m| {
            m.sip
                .cseq()
                .map(|c| Some(c.0) == last_cseq)
                .unwrap_or(false)
        });
        let answered = finals
            .iter()
            .find(|m| m.status.map(|s| (200..300).contains(&s)).unwrap_or(false));
        if let Some(fi) = first_invite {
            if let Some(p) = ms.iter().find(|m| {
                m.status.map(|s| (180..200).contains(&s)).unwrap_or(false) && m.ts_ns >= fi.ts_ns
            }) {
                call.pdd_ms = Some((p.ts_ns - fi.ts_ns) as f64 / 1e6);
            }
            if let Some(a) = answered {
                call.setup_ms = Some((a.ts_ns - fi.ts_ns) as f64 / 1e6);
                if call.pdd_ms.is_none() {
                    call.pdd_ms = call.setup_ms;
                }
            }
        }
        if let Some(a) = answered {
            call.state = CallState::Answered;
            call.final_status = a.status;
            call.final_reason = reason_phrase(a);
            if let Some(bye) = ms.iter().find(|m| m.method.as_deref() == Some("BYE")) {
                call.talk_s = Some((bye.ts_ns - a.ts_ns) as f64 / 1e9);
                call.ended_by = Some(if bye.src == caller {
                    "caller".into()
                } else {
                    "callee".into()
                });
                call.reason = bye.sip.header("Reason").map(|s| s.to_string());
            }
        } else if let Some(f) = final_for_last.or(finals.last()) {
            call.final_status = f.status;
            call.final_reason = reason_phrase(f);
            let cancelled = ms.iter().any(|m| m.method.as_deref() == Some("CANCEL"));
            call.state = if f.status == Some(487) || cancelled {
                CallState::Cancelled
            } else {
                CallState::Failed
            };
            call.reason = f.sip.header("Reason").map(|s| s.to_string()).or_else(|| {
                ms.iter()
                    .find(|m| m.method.as_deref() == Some("CANCEL"))
                    .and_then(|m| m.sip.header("Reason").map(|s| s.to_string()))
            });
            if let Some(c) = ms.iter().find(|m| m.method.as_deref() == Some("CANCEL")) {
                call.ended_by = Some(if c.src == caller {
                    "caller".into()
                } else {
                    "callee".into()
                });
            }
        } else {
            call.state = CallState::InProgress;
        }
        // Offer/answer codecs from the first SDP pair.
        let sdps: Vec<&&Message> = ms
            .iter()
            .filter(|m| m.sdp.is_some() && !m.retransmission)
            .collect();
        if let Some(o) = sdps.first() {
            call.offer_codecs = audio_codecs(o.sdp.as_ref().unwrap());
            if let Some(a) = sdps.iter().skip(1).find(|m| m.src != o.src) {
                call.answer_codecs = audio_codecs(a.sdp.as_ref().unwrap());
            }
        }
    } else {
        let fin = ms
            .iter()
            .filter(|m| m.status.map(|s| s >= 200).unwrap_or(false))
            .last();
        if let Some(f) = fin {
            call.final_status = f.status;
            call.final_reason = reason_phrase(f);
        }
    }
    call
}

fn reason_phrase(m: &Message) -> Option<String> {
    match &m.sip.start {
        sip::StartLine::Response { reason, .. } => Some(reason.clone()),
        _ => None,
    }
}

fn audio_codecs(s: &Sdp) -> Vec<String> {
    s.media
        .iter()
        .filter(|m| m.kind == "audio")
        .flat_map(|m| m.codec_names())
        .collect()
}

/// Every (ip, port) announced in SDP, mapped to the calls announcing it.
fn sdp_endpoints(calls: &[Call], msgs: &[Message]) -> HashMap<SocketAddr, Vec<usize>> {
    let mut map: HashMap<SocketAddr, Vec<usize>> = HashMap::new();
    for c in calls {
        for &mi in &c.messages {
            if let Some(s) = &msgs[mi].sdp {
                for m in &s.media {
                    if m.port == 0 {
                        continue;
                    }
                    if let Some(ip) = m.address(s) {
                        let e = map.entry(SocketAddr::new(ip, m.port)).or_default();
                        if !e.contains(&c.index) {
                            e.push(c.index);
                        }
                    }
                }
            }
        }
    }
    map
}

fn associate(
    src: SocketAddr,
    dst: SocketAddr,
    obs: &[RtpObs],
    map: &HashMap<SocketAddr, Vec<usize>>,
    calls: &[Call],
) -> Option<usize> {
    let t0 = obs.first().map(|o| o.arrival_ns).unwrap_or(0);
    let mut cands: Vec<usize> = Vec::new();
    for k in [dst, src] {
        if let Some(v) = map.get(&k) {
            for c in v {
                if !cands.contains(c) {
                    cands.push(*c);
                }
            }
        }
    }
    if cands.is_empty() {
        // NAT case: match on port only when an announced port is unique.
        for (k, v) in map {
            if k.port() == dst.port() || k.port() == src.port() {
                for c in v {
                    if !cands.contains(c) {
                        cands.push(*c);
                    }
                }
            }
        }
        if cands.len() != 1 {
            return None;
        }
    }
    // Prefer the call whose lifetime contains the stream start; else the latest started before it.
    cands
        .iter()
        .copied()
        .filter(|&c| calls[c].start_ns <= t0 + 2_000_000_000)
        .max_by_key(|&c| calls[c].start_ns)
        .or_else(|| cands.first().copied())
}

fn plausible_rtp(obs: &[RtpObs]) -> bool {
    if obs.len() < 8 {
        return false;
    }
    // Most consecutive packets should have sequence +1 and a constant payload type.
    let mut good = 0;
    for w in obs.windows(2) {
        if w[1].hdr.seq.wrapping_sub(w[0].hdr.seq) == 1 {
            good += 1;
        }
    }
    good * 10 >= (obs.len() - 1) * 7
}

/// SDP media section describing the stream (receiver's view first).
fn media_for(
    call: &Call,
    msgs: &[Message],
    src: SocketAddr,
    dst: SocketAddr,
) -> Option<sdp::Media> {
    let mut fallback = None;
    for target in [dst, src] {
        for &mi in &call.messages {
            if let Some(s) = &msgs[mi].sdp {
                for m in &s.media {
                    if m.kind == "audio" && fallback.is_none() {
                        fallback = Some(m.clone());
                    }
                    if m.port == target.port() && m.address(s) == Some(target.ip()) {
                        return Some(m.clone());
                    }
                }
            }
        }
    }
    fallback
}

impl Report {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn call_findings(&self, call: usize) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.call == Some(call))
            .collect()
    }

    pub fn find_call(&self, key: &str) -> Option<usize> {
        if let Ok(n) = key.parse::<usize>() {
            if n < self.calls.len() {
                return Some(n);
            }
        }
        self.calls.iter().position(|c| c.call_id == key)
    }
}
