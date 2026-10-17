//! Deterministic diagnostics. Each rule turns observable facts into a
//! finding with an explanation; the AI layer only interprets these.

use crate::analysis::{CallState, Finding, Message, Report, Severity};
use crate::net::is_private;
use crate::sip::{self, q850_hint, status_hint, Uri};
use std::collections::HashSet;
use std::net::IpAddr;

struct Out(Vec<Finding>);

impl Out {
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        rule: &str,
        sev: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
        call: Option<usize>,
        msgs: Vec<usize>,
        stream: Option<usize>,
    ) {
        self.0.push(Finding {
            rule: rule.into(),
            severity: sev,
            title: title.into(),
            detail: detail.into(),
            call,
            messages: msgs,
            stream,
        });
    }
}

pub fn run_all(r: &Report) -> Vec<Finding> {
    let mut o = Out(Vec::new());
    capture_level(r, &mut o);
    message_level(r, &mut o);
    for c in 0..r.calls.len() {
        call_level(r, c, &mut o);
        media_level(r, c, &mut o);
    }
    for s in &r.streams {
        stream_level(r, s.id, &mut o);
    }
    let mut v = o.0;
    // Errors first, then warnings, then info; stable within a severity.
    v.sort_by(|a, b| b.severity.cmp(&a.severity));
    v
}

fn capture_level(r: &Report, o: &mut Out) {
    if r.summary.packets > 0 && r.messages.is_empty() {
        o.add("capture.no_sip", Severity::Info, "No SIP found in capture",
            "No SIP messages were decoded. If SIP runs over TLS (port 5061) or WebSocket, the capture needs the TLS keys or a capture taken at the endpoint.", None, vec![], None);
    }
    if r.summary.tls_packets > 0 {
        let detail = if r.summary.tls_keylog_lines > 0 {
            format!("{} TLS records seen. The file carries {} TLS key log lines; open it in Wireshark to see the decrypted SIP. Sidetone does not decrypt TLS itself.", r.summary.tls_packets, r.summary.tls_keylog_lines)
        } else {
            format!("{} TLS records seen without keys. Capture at the softphone (Sidetone exports keys automatically) or provide an SSLKEYLOGFILE to see the signaling.", r.summary.tls_packets)
        };
        o.add(
            "capture.tls",
            Severity::Info,
            "Encrypted signaling present",
            detail,
            None,
            vec![],
            None,
        );
    }
    let answered = r.calls.iter().any(|c| c.state == CallState::Answered);
    if answered && r.streams.is_empty() && r.summary.rtcp_packets == 0 {
        o.add("capture.no_rtp", Severity::Info, "Capture contains no RTP",
            "Calls were answered but no RTP was captured, so media could not be analyzed. The capture filter may be SIP-only, or media flows on another interface/host (media server, SBC).", None, vec![], None);
    }
    let unassoc: Vec<usize> = r
        .streams
        .iter()
        .filter(|s| s.call.is_none())
        .map(|s| s.id)
        .collect();
    if !unassoc.is_empty() && !r.calls.is_empty() {
        o.add("rtp.unassociated", Severity::Info, format!("{} RTP stream(s) not linked to any call", unassoc.len()),
            "These streams use addresses never announced in captured SDP. Typical causes: the call setup is outside the capture, NAT rewrote addresses, or a media server/SBC anchors media on other addresses.", None, vec![], unassoc.first().copied());
    }
}

const REQ_MANDATORY: &[&str] = &["Via", "From", "To", "Call-ID", "CSeq", "Max-Forwards"];
const RESP_MANDATORY: &[&str] = &["Via", "From", "To", "Call-ID", "CSeq"];

fn message_level(r: &Report, o: &mut Out) {
    for m in &r.messages {
        if m.retransmission {
            continue;
        }
        if !m.parse_notes.is_empty() {
            o.add(
                "sip.parse",
                Severity::Warning,
                format!("Malformed or unusual message: {}", m.summary),
                m.parse_notes.join("; "),
                m.call,
                vec![m.index],
                None,
            );
        }
        let list = if m.sip.is_request() {
            REQ_MANDATORY
        } else {
            RESP_MANDATORY
        };
        let missing: Vec<&str> = list
            .iter()
            .copied()
            .filter(|h| m.sip.header(h).is_none())
            .collect();
        if !missing.is_empty() {
            o.add("sip.missing_headers", Severity::Warning, format!("Missing mandatory header(s) in {}", m.summary),
                format!("RFC 3261 requires {}; strict elements answer 400 Bad Request or drop the message.", missing.join(", ")), m.call, vec![m.index], None);
        }
        if let Some(mf) = m
            .sip
            .header("Max-Forwards")
            .and_then(|v| v.trim().parse::<u32>().ok())
        {
            if mf <= 5 && m.sip.is_request() {
                o.add("sip.max_forwards_low", Severity::Warning, format!("Max-Forwards is {mf}"),
                    "The request has almost exhausted its hop budget. A routing loop between proxies/SBCs is likely; a 483 Too Many Hops will follow soon.", m.call, vec![m.index], None);
            }
        }
        let invite_2xx = m.status.map(|s| (200..300).contains(&s)).unwrap_or(false)
            && m.sip.cseq().map(|c| c.1 == "INVITE").unwrap_or(false);
        if m.sip.method() == Some("INVITE") || invite_2xx {
            check_contact(m, o);
        }
        if let Some(s) = &m.sdp {
            check_sdp_address(m, s, o);
        }
    }
}

fn check_contact(m: &Message, o: &mut Out) {
    let Some(contact) = m.sip.header("Contact") else {
        {
            o.add("sip.no_contact", Severity::Warning, format!("No Contact header in {}", m.summary),
                "Dialog-creating messages need a Contact; without it the peer cannot send ACK/BYE/re-INVITE directly.", m.call, vec![m.index], None);
        }
        return;
    };
    let Some(u) = Uri::from_header(contact) else {
        return;
    };
    let Ok(cip) = u.host.parse::<IpAddr>() else {
        return;
    };
    let src_ip = m.src_addr.ip();
    if is_private(&cip) && !is_private(&src_ip) {
        o.add("sip.contact_private", Severity::Warning, "Contact has a private address but the message came from a public one",
            format!("Contact {} was sent from {}. Unless a proxy/SBC fixes it (nat=yes, rport + received, contact rewriting), in-dialog requests such as ACK, BYE and re-INVITE will be sent to an unreachable address. Typical symptom: call drops after ~32 s or BYE never arrives.", u.host, src_ip),
            m.call, vec![m.index], None);
    }
}

fn check_sdp_address(m: &Message, s: &crate::sdp::Sdp, o: &mut Out) {
    for media in &s.media {
        if media.port == 0 {
            continue;
        }
        let Some(ip) = media.address(s) else { continue };
        if ip.is_unspecified() {
            o.add("sdp.hold_zero_ip", Severity::Info, format!("Hold signaled with 0.0.0.0 in {}", m.summary),
                "Old-style hold (RFC 2543). Some endpoints mute both directions; modern devices use a=sendonly/inactive.", m.call, vec![m.index], None);
            continue;
        }
        let src = m.src_addr.ip();
        if is_private(&ip) && !is_private(&src) {
            o.add("sdp.private_ip", Severity::Warning, format!("SDP announces private media address {ip}"),
                format!("The SDP in '{}' asks for RTP at {ip}:{} but the message arrived from public address {src}. Without media NAT handling (SBC media latching, rtpengine, STUN/ICE) the far end sends audio to an unreachable address: one-way or no audio.", m.summary, media.port),
                m.call, vec![m.index], None);
        }
        if media.direction == "sendonly" || media.direction == "inactive" {
            o.add("sdp.hold", Severity::Info, format!("Media direction {} in {}", media.direction, m.summary),
                "The sender is putting the call on hold or stopping media in one/both directions. Silence after this point is expected.", m.call, vec![m.index], None);
        }
    }
}

fn call_level(r: &Report, ci: usize, o: &mut Out) {
    let c = &r.calls[ci];
    let ms: Vec<&Message> = c.messages.iter().map(|&i| &r.messages[i]).collect();
    let cap_end = r.summary.end_ns;

    // Retransmissions.
    let retx: Vec<&&Message> = ms.iter().filter(|m| m.retransmission).collect();
    if !retx.is_empty() {
        let ok_retx: Vec<usize> = retx
            .iter()
            .filter(|m| {
                m.status.map(|s| (200..300).contains(&s)).unwrap_or(false)
                    && m.sip.cseq().map(|x| x.1 == "INVITE").unwrap_or(false)
            })
            .map(|m| m.index)
            .collect();
        let inv_retx: Vec<usize> = retx
            .iter()
            .filter(|m| m.method.as_deref() == Some("INVITE"))
            .map(|m| m.index)
            .collect();
        if !ok_retx.is_empty() {
            o.add("sip.200_retransmitted", Severity::Error, format!("200 OK to INVITE retransmitted {} time(s)", ok_retx.len()),
                "The callee keeps resending 200 OK because it is not receiving the ACK. The ACK is lost, sent to the wrong address (Contact/Record-Route behind NAT) or blocked. If it never arrives the callee hangs up after 32 s (64*T1).",
                Some(ci), ok_retx, None);
        }
        if !inv_retx.is_empty() {
            let first_resp = ms.iter().find(|m| {
                m.status.is_some() && m.sip.cseq().map(|x| x.1 == "INVITE").unwrap_or(false)
            });
            let detail = if first_resp.is_none() {
                "No response at all came back: the next hop is unreachable, the port/transport is wrong, a firewall drops the request, or responses are routed elsewhere (check Via/rport).".to_string()
            } else {
                "The 100 Trying arrived late or was lost; on UDP each retransmission means the previous copy was not acknowledged within T1 (500 ms) or its doubling.".to_string()
            };
            o.add(
                "sip.invite_retransmitted",
                Severity::Warning,
                format!("INVITE retransmitted {} time(s)", inv_retx.len()),
                detail,
                Some(ci),
                inv_retx,
                None,
            );
        }
        let other: Vec<usize> = retx
            .iter()
            .filter(|m| {
                m.method.as_deref() != Some("INVITE")
                    && !(m.status.map(|s| (200..300).contains(&s)).unwrap_or(false)
                        && m.sip.cseq().map(|x| x.1 == "INVITE").unwrap_or(false))
            })
            .map(|m| m.index)
            .collect();
        if !other.is_empty() {
            o.add("sip.retransmissions", Severity::Info, format!("{} other retransmission(s)", other.len()),
                "Other requests/responses were sent more than once; occasional retransmissions on UDP are normal, many indicate packet loss or a slow peer.", Some(ci), other, None);
        }
    }

    if c.kind == "INVITE" {
        invite_outcome(r, ci, &ms, cap_end, o);
    } else {
        let has_resp = ms.iter().any(|m| m.status.is_some());
        let reqs: Vec<usize> = ms
            .iter()
            .filter(|m| m.sip.is_request())
            .map(|m| m.index)
            .collect();
        if !has_resp && !reqs.is_empty() {
            let sev = if c.kind == "OPTIONS" || c.kind == "REGISTER" {
                Severity::Error
            } else {
                Severity::Warning
            };
            let extra = if c.kind == "OPTIONS" {
                " Unanswered OPTIONS keepalives usually mark the trunk/peer as down."
            } else {
                ""
            };
            let mut extra = extra.to_string();
            let first = &r.messages[reqs[0]];
            if let Some(via) = first.sip.top_via() {
                if let (Ok(local), dst) = (via.host.parse::<IpAddr>(), first.dst_addr.ip()) {
                    if let (IpAddr::V4(l), IpAddr::V4(d)) = (local, dst) {
                        let (lo, dov) = (l.octets(), d.octets());
                        if is_private(&local) && is_private(&dst) && lo[..3] != dov[..3] {
                            extra.push_str(&format!(" The client advertises {l} (Via) while the server is {d}, on a different subnet: check that the softphone is bound to the right network interface (virtual adapters from VMware/Hyper-V/VPN often win) and that the server has a route back."));
                        }
                    }
                }
            }
            o.add(
                "sip.no_response",
                sev,
                format!("{} got no response", c.kind),
                format!(
                    "No response was captured for {} to {}.{extra}",
                    c.kind, c.callee
                ),
                Some(ci),
                reqs,
                None,
            );
        }
        if c.kind == "REGISTER" {
            if let Some(ok) = ms
                .iter()
                .find(|m| m.status.map(|s| (200..300).contains(&s)).unwrap_or(false))
            {
                let exp = ok
                    .sip
                    .header("Contact")
                    .and_then(|v| sip::param(v, "expires"))
                    .or_else(|| ok.sip.header("Expires").map(|s| s.to_string()));
                o.add("sip.registered", Severity::Info, format!("Registration accepted{}", exp.map(|e| format!(", expires {e}s")).unwrap_or_default()),
                    "The registrar accepted the binding. Re-registration should happen before expiry (typically at half the interval).", Some(ci), vec![ok.index], None);
            }
        }
    }

    // Error responses anywhere in the dialog (except outcome of the initial INVITE and auth challenges).
    let initial_inv_cseqs: HashSet<u32> = ms
        .iter()
        .filter(|m| m.method.as_deref() == Some("INVITE") && m.sip.to_tag().is_none())
        .filter_map(|m| m.sip.cseq().map(|x| x.0))
        .collect();
    for m in ms.iter().filter(|m| !m.retransmission) {
        let Some(st) = m.status else { continue };
        if st < 400 || st == 401 || st == 407 || st == 487 {
            continue;
        }
        let (n, meth) = m.sip.cseq().unwrap_or((0, String::new()));
        if meth == "INVITE" && initial_inv_cseqs.contains(&n) {
            continue;
        }
        let sev = match st {
            481 | 500..=599 => Severity::Error,
            _ => Severity::Warning,
        };
        let what = if meth == "INVITE" {
            "re-INVITE".to_string()
        } else {
            meth.clone()
        };
        let mut detail = format!("{what} was rejected with {st}. {}", status_hint(st));
        if st == 481 {
            detail.push_str(" For in-dialog requests this usually means the other side already ended the dialog or an SBC/B2BUA changed the tags/Call-ID.");
        }
        if st == 491 {
            detail.push_str(" Both sides sent a re-INVITE at the same time (glare).");
        }
        o.add(
            "sip.error_response",
            sev,
            format!("{st} response to {what}"),
            detail,
            Some(ci),
            vec![m.index],
            None,
        );
    }

    // Authentication problems.
    let challenges: Vec<&&Message> = ms
        .iter()
        .filter(|m| matches!(m.status, Some(401) | Some(407)) && !m.retransmission)
        .collect();
    for ch in &challenges {
        let (n, meth) = ch.sip.cseq().unwrap_or((0, String::new()));
        // Was the challenged request already carrying credentials?
        let req = ms
            .iter()
            .find(|m| m.sip.is_request() && m.sip.cseq() == Some((n, meth.clone())));
        if let Some(req) = req {
            if req.sip.header("Authorization").is_some()
                || req.sip.header("Proxy-Authorization").is_some()
            {
                o.add("sip.auth_rejected", Severity::Error, format!("{meth} rejected again after sending credentials"),
                    "The request already carried credentials and was challenged again: wrong username/password, wrong auth user vs. From user, wrong realm, or a stale nonce handling issue.",
                    Some(ci), vec![req.index, ch.index], None);
            }
        }
        // Challenge never answered with a new request.
        let retried = ms.iter().any(|m| {
            m.sip.is_request()
                && m.method.as_deref() == Some(meth.as_str())
                && m.sip.cseq().map(|x| x.0 > n).unwrap_or(false)
        });
        if !retried && meth != "ACK" {
            o.add("sip.auth_unanswered", Severity::Warning, format!("{} challenge to {meth} was never answered", ch.status.unwrap_or(0)),
                "The client did not resend the request with credentials. Check that credentials are configured for this realm, or that the challenge is reaching the client.",
                Some(ci), vec![ch.index], None);
        }
    }

    // Reason headers with Q.850 causes.
    for m in ms.iter().filter(|m| !m.retransmission) {
        for rv in m.sip.header_values("Reason") {
            let cause = sip::param(&rv, "cause").and_then(|c| c.parse::<u16>().ok());
            if let Some(cause) = cause {
                let proto = rv.split(';').next().unwrap_or("").trim().to_string();
                let hint = if proto.eq_ignore_ascii_case("Q.850") {
                    q850_hint(cause)
                } else {
                    status_hint(cause)
                };
                let sev =
                    if proto.eq_ignore_ascii_case("Q.850") && !matches!(cause, 16 | 17 | 19 | 31) {
                        Severity::Warning
                    } else {
                        Severity::Info
                    };
                o.add(
                    "sip.reason",
                    sev,
                    format!("{} carries Reason {proto} cause {cause}", m.label),
                    format!(
                        "{}{}",
                        if hint.is_empty() {
                            "Cause value not in the built-in table."
                        } else {
                            hint
                        },
                        sip::param(&rv, "text")
                            .map(|t| format!(" (text: {t})"))
                            .unwrap_or_default()
                    ),
                    Some(ci),
                    vec![m.index],
                    None,
                );
            }
        }
    }
}

fn invite_outcome(r: &Report, ci: usize, ms: &[&Message], cap_end: i64, o: &mut Out) {
    let c = &r.calls[ci];
    let invites: Vec<usize> = ms
        .iter()
        .filter(|m| m.method.as_deref() == Some("INVITE") && m.sip.to_tag().is_none())
        .map(|m| m.index)
        .collect();
    match c.state {
        CallState::InProgress => {
            let any_resp = ms.iter().any(|m| {
                m.status.is_some() && m.sip.cseq().map(|x| x.1 == "INVITE").unwrap_or(false)
            });
            if !any_resp {
                o.add("sip.invite_no_response", Severity::Error, "INVITE never got any response",
                    format!("Nothing came back from {}. Check reachability, port and transport (UDP vs TCP/TLS), firewall/ACL, and whether responses are being sent to the Via address (rport) instead of the real source.", c.callee),
                    Some(ci), invites.clone(), None);
            } else {
                o.add("sip.call_in_setup", Severity::Info, "Call still in setup at end of capture",
                    "Only provisional responses were captured. Either the capture stopped early or the call timed out later (Timer B/C, 408).", Some(ci), invites.clone(), None);
            }
        }
        CallState::Failed => {
            let st = c.final_status.unwrap_or(0);
            let (sev, rule) = match st {
                486 | 600 | 603 => (Severity::Info, "sip.call_rejected_user"),
                404 | 410 | 484 | 604 => (Severity::Warning, "sip.call_failed"),
                _ => (Severity::Error, "sip.call_failed"),
            };
            let fin = ms
                .iter()
                .filter(|m| m.status == Some(st))
                .map(|m| m.index)
                .next();
            let mut detail = format!(
                "Final response {st} {}. {}",
                c.final_reason.clone().unwrap_or_default(),
                status_hint(st)
            );
            if st == 488 || st == 606 {
                let offer = c.offer_codecs.join(", ");
                detail.push_str(&format!(
                    " Offered audio codecs: {}.",
                    if offer.is_empty() {
                        "none".into()
                    } else {
                        offer
                    }
                ));
            }
            if st == 401 || st == 407 {
                detail = format!("Call ended with an unanswered {st} authentication challenge.");
            }
            o.add(
                rule,
                sev,
                format!("Call failed with {st}"),
                detail,
                Some(ci),
                fin.into_iter().collect(),
                None,
            );
        }
        CallState::Cancelled => {
            let who = c.ended_by.clone().unwrap_or_else(|| "caller".into());
            o.add(
                "sip.call_cancelled",
                Severity::Info,
                "Call cancelled before answer",
                format!("The {who} sent CANCEL; 487 Request Terminated is the expected response."),
                Some(ci),
                vec![],
                None,
            );
        }
        CallState::Answered => {
            let inv_cseq = ms
                .iter()
                .find(|m| {
                    m.status.map(|s| (200..300).contains(&s)).unwrap_or(false)
                        && m.sip.cseq().map(|x| x.1 == "INVITE").unwrap_or(false)
                })
                .and_then(|m| m.sip.cseq().map(|x| x.0));
            let ok = ms.iter().find(|m| {
                m.status.map(|s| (200..300).contains(&s)).unwrap_or(false)
                    && m.sip.cseq().map(|x| x.1 == "INVITE").unwrap_or(false)
            });
            let ack = ms.iter().any(|m| {
                m.method.as_deref() == Some("ACK")
                    && m.sip.cseq().map(|x| Some(x.0) == inv_cseq).unwrap_or(false)
            });
            if let Some(ok) = ok {
                if !ack && cap_end - ok.ts_ns > 1_000_000_000 {
                    o.add("sip.no_ack", Severity::Error, "No ACK for the 200 OK",
                        "The caller never sent (or the capture never saw) the ACK confirming the answer. The callee will retransmit 200 OK and drop the call after 32 s. Check the Contact/Record-Route in the 200 OK: the ACK goes there.",
                        Some(ci), vec![ok.index], None);
                }
                if let Some(t) = c.talk_s {
                    if (30.0..=34.5).contains(&t) {
                        let sev =
                            if !ack || ms.iter().any(|m| m.retransmission && m.status.is_some()) {
                                Severity::Error
                            } else {
                                Severity::Warning
                            };
                        o.add("sip.drop_32s", sev, format!("Call ended {:.1} s after answer", t),
                            "Ending at ~32 s is the signature of a missing ACK (Timer H/64*T1) or a session/refresh timer mis-setting. Compare the 200 OK Contact with the address the ACK was sent to.",
                            Some(ci), vec![ok.index], None);
                    }
                    let se = ms
                        .iter()
                        .filter_map(|m| m.sip.header("Session-Expires"))
                        .filter_map(|v| {
                            v.split(';')
                                .next()
                                .and_then(|n| n.trim().parse::<f64>().ok())
                        })
                        .next();
                    if let Some(se) = se {
                        let refreshed = ms.iter().any(|m| {
                            m.method.as_deref() == Some("UPDATE")
                                || (m.method.as_deref() == Some("INVITE")
                                    && m.sip.to_tag().is_some())
                        });
                        if se > 60.0 && (t - se).abs() < 3.0 && !refreshed {
                            o.add("sip.session_timer", Severity::Warning, "Call ended at the session timer boundary",
                                format!("Session-Expires is {se:.0}s and the call lasted {t:.1}s with no successful refresh (re-INVITE/UPDATE). Check which side is the refresher and whether the refresh was rejected."),
                                Some(ci), vec![], None);
                        }
                    }
                }
            }
            if c.talk_s.is_none() && ms.iter().all(|m| m.method.as_deref() != Some("BYE")) {
                o.add(
                    "sip.call_up",
                    Severity::Info,
                    "Call still up at end of capture",
                    "No BYE was captured after the answer.",
                    Some(ci),
                    vec![],
                    None,
                );
            }
            if let Some(p) = c.pdd_ms {
                if p > 5000.0 {
                    o.add("sip.pdd_high", Severity::Warning, format!("Post-dial delay {:.1} s", p / 1000.0),
                        "More than 5 s from INVITE to ringback/answer. Look at DNS/ENUM lookups, routing timeouts, failover attempts towards dead trunks, or LCR processing.", Some(ci), vec![], None);
                }
            }
        }
        CallState::NonInvite => {}
    }
    // First response latency on UDP.
    if let Some(&first_inv) = invites.first() {
        let fm = &r.messages[first_inv];
        if let Some(resp) = ms
            .iter()
            .find(|m| m.status.is_some() && m.sip.cseq().map(|x| x.1 == "INVITE").unwrap_or(false))
        {
            let dt = (resp.ts_ns - fm.ts_ns) as f64 / 1e6;
            if dt > 500.0 {
                o.add("sip.slow_first_response", Severity::Warning, format!("First response to INVITE took {dt:.0} ms"),
                    "Over T1 (500 ms) the caller starts retransmitting the INVITE. Proxies should answer 100 Trying immediately.", Some(ci), vec![first_inv, resp.index], None);
            }
        }
    }
}

fn media_level(r: &Report, ci: usize, o: &mut Out) {
    let c = &r.calls[ci];
    if c.kind != "INVITE" {
        return;
    }
    let ms: Vec<&Message> = c
        .messages
        .iter()
        .map(|&i| &r.messages[i])
        .filter(|m| !m.retransmission)
        .collect();
    let sdps: Vec<&&Message> = ms.iter().filter(|m| m.sdp.is_some()).collect();
    if let Some(offer) = sdps.first() {
        if let Some(answer) = sdps.iter().skip(1).find(|m| m.src != offer.src) {
            let os = offer.sdp.as_ref().unwrap();
            let asd = answer.sdp.as_ref().unwrap();
            for (i, om) in os.media.iter().enumerate() {
                let Some(am) = asd.media.get(i) else {
                    o.add("sdp.media_count", Severity::Error, "Answer has fewer m= lines than the offer",
                        "RFC 3264 requires the answer to contain the same number of m= lines (rejected streams use port 0).", Some(ci), vec![offer.index, answer.index], None);
                    break;
                };
                if am.port == 0 {
                    if om.kind == "audio" {
                        o.add("sdp.audio_rejected", Severity::Error, "Audio stream rejected in the answer (port 0)",
                            "The answerer refused the audio m= line, usually because no offered codec or transport is acceptable.", Some(ci), vec![answer.index], None);
                    }
                    continue;
                }
                let ignore = |n: &str| {
                    n.eq_ignore_ascii_case("telephone-event")
                        || n.eq_ignore_ascii_case("CN")
                        || n.eq_ignore_ascii_case("comfort-noise")
                };
                let on: Vec<String> = om
                    .codec_names()
                    .into_iter()
                    .filter(|n| !ignore(n))
                    .map(|s| s.to_ascii_uppercase())
                    .collect();
                let an: Vec<String> = am
                    .codec_names()
                    .into_iter()
                    .filter(|n| !ignore(n))
                    .map(|s| s.to_ascii_uppercase())
                    .collect();
                if om.kind == "audio" {
                    if !an.iter().any(|a| on.contains(a)) {
                        o.add(
                            "sdp.no_common_codec",
                            Severity::Error,
                            "No common audio codec between offer and answer",
                            format!(
                                "Offer: {}. Answer: {}. Media cannot flow; expect 488 or silence.",
                                on.join(", "),
                                an.join(", ")
                            ),
                            Some(ci),
                            vec![offer.index, answer.index],
                            None,
                        );
                    } else {
                        let extra: Vec<&String> = an.iter().filter(|a| !on.contains(a)).collect();
                        if !extra.is_empty() {
                            o.add("sdp.answer_extra_codec", Severity::Warning, "Answer contains codecs that were not offered",
                                format!("{} not in the offer. Violates RFC 3264 and confuses strict endpoints.", extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), Some(ci), vec![answer.index], None);
                        }
                    }
                    let ote = om
                        .codec_names()
                        .iter()
                        .any(|n| n.eq_ignore_ascii_case("telephone-event"));
                    let ate = am
                        .codec_names()
                        .iter()
                        .any(|n| n.eq_ignore_ascii_case("telephone-event"));
                    if ote && !ate {
                        o.add("sdp.dtmf_not_negotiated", Severity::Warning, "RFC 4733 DTMF (telephone-event) not accepted",
                            "The offer proposed telephone-event but the answer dropped it. DTMF will go in-band or via SIP INFO; IVRs and transcoders often miss digits in this case.", Some(ci), vec![offer.index, answer.index], None);
                    }
                    if let (Some(op), Some(ap)) = (om.ptime, am.ptime) {
                        if op != ap {
                            o.add("sdp.ptime_mismatch", Severity::Info, format!("ptime differs: offer {op} ms, answer {ap} ms"),
                                "Asymmetric packetization is allowed but some gateways/transcoders handle it badly.", Some(ci), vec![offer.index, answer.index], None);
                        }
                    }
                }
                if om.is_secure() != am.is_secure() {
                    o.add("sdp.srtp_mismatch", Severity::Error, "SRTP / RTP mismatch",
                        format!("Offer uses {} and answer uses {}. One side expects encrypted media; the call will have no audio or be rejected with 488.", om.proto, am.proto), Some(ci), vec![offer.index, answer.index], None);
                } else if om.is_secure()
                    && !om.proto.to_ascii_uppercase().contains("TLS")
                    && om.fingerprint.is_none()
                    && (om.crypto.is_empty() || am.crypto.is_empty())
                {
                    o.add("sdp.srtp_no_crypto", Severity::Error, "SRTP without a=crypto keys",
                        "RTP/SAVP requires SDES a=crypto lines in both offer and answer (or DTLS-SRTP with fingerprints).", Some(ci), vec![offer.index, answer.index], None);
                }
                if om.proto.to_ascii_uppercase().contains("TLS") || om.fingerprint.is_some() {
                    if om.fingerprint.is_none() || am.fingerprint.is_none() {
                        o.add(
                            "sdp.dtls_no_fingerprint",
                            Severity::Error,
                            "DTLS-SRTP without a=fingerprint",
                            "Both sides must provide a certificate fingerprint for DTLS-SRTP.",
                            Some(ci),
                            vec![offer.index, answer.index],
                            None,
                        );
                    }
                    if om.setup.as_deref() == Some("active")
                        && am.setup.as_deref() == Some("active")
                        || om.setup.as_deref() == Some("passive")
                            && am.setup.as_deref() == Some("passive")
                    {
                        o.add("sdp.dtls_setup_conflict", Severity::Error, "DTLS setup roles conflict",
                            "Both sides chose the same a=setup role; the DTLS handshake cannot start.", Some(ci), vec![offer.index, answer.index], None);
                    }
                }
                if !om.candidates.is_empty() && am.candidates.is_empty() && !asd.ice_lite {
                    o.add("sdp.ice_one_sided", Severity::Info, "ICE candidates only in the offer",
                        "The answerer does not do ICE. Media relies on the c= addresses; behind NAT this needs an SBC or media latching.", Some(ci), vec![answer.index], None);
                }
            }
        }
    }

    // RTP presence and direction.
    if c.state != CallState::Answered || r.streams.is_empty() {
        return;
    }
    let streams: Vec<&crate::rtp::RtpStream> = c.streams.iter().map(|&s| &r.streams[s]).collect();
    if streams.is_empty() {
        o.add("rtp.no_media", Severity::Error, "Answered call without any RTP in the capture",
            "Other RTP was captured, but none for this call's SDP addresses. Likely causes: SDP points to an unreachable/private address, a firewall blocks the RTP port range, or media is anchored elsewhere.",
            Some(ci), vec![], None);
        return;
    }
    // Directions: group by the side the packets come from.
    let caller_ip = c
        .caller
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| a.ip());
    let mut dirs: HashSet<(String, String)> = HashSet::new();
    for s in &streams {
        let a = s.src_addr.map(|x| x.ip().to_string()).unwrap_or_default();
        let b = s.dst_addr.map(|x| x.ip().to_string()).unwrap_or_default();
        dirs.insert((a, b));
    }
    let has_reverse = dirs
        .iter()
        .any(|(a, b)| dirs.contains(&(b.clone(), a.clone())));
    if !has_reverse && !(dirs.len() > 1) {
        let s = streams[0];
        let hold = ms.iter().any(|m| {
            m.sdp
                .as_ref()
                .map(|sd| sd.media.iter().any(|x| x.direction != "sendrecv"))
                .unwrap_or(false)
        });
        let side = match (caller_ip, s.src_addr) {
            (Some(ci_), Some(sa)) if ci_ == sa.ip() => "caller to callee",
            (Some(_), Some(_)) => "callee to caller",
            _ => "one direction",
        };
        o.add("rtp.one_way", if hold { Severity::Warning } else { Severity::Error }, "One-way audio: RTP seen in a single direction",
            format!("Only {} → {} carries RTP ({side}). The other side either sends to a wrong address (private IP in SDP, NAT), is blocked by a firewall, or the capture point only sees one leg.{}", s.src, s.dst, if hold { " The call was put on hold at some point, which can also explain it." } else { "" }),
            Some(ci), vec![], Some(s.id));
    }
    // Asymmetric RTP (source differs from the address the sender announced).
    let mut announced: HashSet<std::net::SocketAddr> = HashSet::new();
    for m in &ms {
        if let Some(sd) = &m.sdp {
            for md in &sd.media {
                if let Some(ip) = md.address(sd) {
                    announced.insert(std::net::SocketAddr::new(ip, md.port));
                }
            }
        }
    }
    for s in &streams {
        if let (Some(src), Some(dst)) = (s.src_addr, s.dst_addr) {
            if announced.contains(&dst) && !announced.contains(&src) {
                o.add("rtp.asymmetric", Severity::Info, format!("RTP source {} was never announced in SDP", s.src),
                    "Media comes from a different address/port than the sender's SDP. Common behind NAT; the far end must use symmetric RTP (latching) or audio in the reverse direction goes to the wrong place.",
                    Some(ci), vec![], Some(s.id));
            }
        }
    }
    // Several SSRCs on the same 5-tuple.
    let mut tuples: Vec<(String, String)> = Vec::new();
    for s in &streams {
        let t = (s.src.clone(), s.dst.clone());
        if tuples.contains(&t) {
            o.add("rtp.ssrc_change", Severity::Info, format!("SSRC changed on {} → {}", s.src, s.dst),
                "A new SSRC appeared on the same flow (re-INVITE, transfer, media server switch). Jitter buffers and SRTP contexts must reset; some devices go silent.", Some(ci), vec![], Some(s.id));
        } else {
            tuples.push(t);
        }
    }
    // Payload types outside the negotiated set.
    let mut allowed: HashSet<u8> = HashSet::new();
    for m in &ms {
        if let Some(sd) = &m.sdp {
            for md in sd.media.iter().filter(|x| x.kind == "audio") {
                allowed.extend(md.formats.iter().copied());
            }
        }
    }
    if !allowed.is_empty() {
        for s in &streams {
            let bad: Vec<u8> = s
                .payload_types
                .iter()
                .copied()
                .filter(|p| !allowed.contains(p) && *p != 13)
                .collect();
            if !bad.is_empty() {
                o.add("rtp.unexpected_pt", Severity::Warning, format!("Unnegotiated payload type(s) {:?} on {} → {}", bad, s.src, s.dst),
                    "The sender uses payload types that never appeared in SDP. The receiver will discard them (silence) or decode garbage.", Some(ci), vec![], Some(s.id));
            }
        }
    }
}

fn stream_level(r: &Report, si: usize, o: &mut Out) {
    let s = &r.streams[si];
    let call = s.call;
    if s.packets < 10 {
        return;
    }
    let name = format!("{} → {}", s.src, s.dst);
    if s.loss_pct >= 1.0 {
        let sev = if s.loss_pct >= 5.0 {
            Severity::Error
        } else {
            Severity::Warning
        };
        o.add("rtp.loss", sev, format!("Packet loss {:.2}% on {name}", s.loss_pct),
            format!("{} of {} expected packets missing. Above 1% G.711 starts to sound choppy; above 5% speech becomes hard to follow. Check link saturation, Wi-Fi, QoS/DSCP marking and shaping on the path.", s.lost.max(0), s.expected),
            call, vec![], Some(si));
    }
    if s.jitter_ms >= 30.0 || s.max_jitter_ms >= 50.0 {
        let sev = if s.max_jitter_ms >= 80.0 {
            Severity::Error
        } else {
            Severity::Warning
        };
        o.add("rtp.jitter", sev, format!("High jitter on {name}: {:.1} ms (max {:.1} ms)", s.jitter_ms, s.max_jitter_ms),
            "Interarrival jitter (RFC 3550) above ~30 ms forces large jitter buffers or causes late-packet discards. Typical causes: congestion without QoS, VPN/Wi-Fi, CPU-starved media servers.",
            call, vec![], Some(si));
    }
    let has_cn = s.payload_types.contains(&13);
    if s.max_gap_ms >= 1000.0 && !has_cn {
        o.add("rtp.gap", Severity::Warning, format!("{:.1} s gap in RTP on {name}", s.max_gap_ms / 1000.0),
            "The stream stopped for over a second without comfort noise. Unless the call was on hold, this is an audio dropout (path change, NAT rebinding, media server failover).",
            call, vec![], Some(si));
    }
    if s.duplicates > 0 && s.duplicates * 100 > s.packets {
        o.add("rtp.duplicates", Severity::Info, format!("{} duplicate RTP packets on {name}", s.duplicates),
            "Duplicates usually come from capture on a mirrored port seeing both directions, or a network loop/mirroring setup.", call, vec![], Some(si));
    }
    if s.seq_jumps > 0 {
        o.add("rtp.seq_jump", Severity::Info, format!("RTP sequence jumped {} time(s) on {name}", s.seq_jumps),
            "Large sequence discontinuities happen when a media source changes without changing SSRC (transfer, MoH, media server switch).", call, vec![], Some(si));
    }
    if let Some(mos) = s.mos {
        if mos < 3.6 {
            let sev = if mos < 3.1 {
                Severity::Error
            } else {
                Severity::Warning
            };
            o.add("rtp.mos_low", sev, format!("Estimated MOS {mos:.2} on {name}"),
                format!("E-model (G.107) estimate from loss {:.2}% and jitter {:.1} ms with codec {}. Network part only; delay is approximated.", s.loss_pct, s.jitter_ms, s.codec),
                call, vec![], Some(si));
        }
    }
    if !s.dtmf_events.is_empty() {
        o.add(
            "rtp.dtmf",
            Severity::Info,
            format!("DTMF via RFC 4733 on {name}: {}", s.dtmf_events.join("")),
            "Digits detected as telephone-event packets.",
            call,
            vec![],
            Some(si),
        );
    }
}
