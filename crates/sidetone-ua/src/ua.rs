//! Minimal SIP user agent over UDP for test calls: REGISTER with digest
//! auth, OPTIONS ping, outbound calls (INVITE/PRACK/ACK/BYE/CANCEL) and an
//! answering mode, all recorded by the tap.

use crate::media::{bind_udp, AudioSource, Codec, RtpSession};
use crate::profile::{DtmfMode, Profile};
use crate::sipmsg;
use crate::tap::Tap;
use md5::{Digest, Md5};
use sidetone_core::sdp;
use sidetone_core::sip::{self, SipMessage, Uri};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct UaError(pub String);

impl std::fmt::Display for UaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for UaError {}

impl From<std::io::Error> for UaError {
    fn from(e: std::io::Error) -> Self {
        UaError(e.to_string())
    }
}

type Result<T> = std::result::Result<T, UaError>;

pub(crate) fn rand_hex(n: usize) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0x2545F4914F6CDD1D);
    let mut x = CTR.fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
    let mut s = String::new();
    while s.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push_str(&format!("{:016x}", x));
    }
    s.truncate(n);
    s
}

/// Resolves "host[:port]" (A/AAAA only; DNS SRV/NAPTR are not used yet).
pub fn resolve(hostport: &str, default_port: u16) -> Result<SocketAddr> {
    let h = hostport
        .trim()
        .trim_start_matches("sip:")
        .trim_start_matches("sips:");
    let (host, port) = sip::split_host_port(h.split(';').next().unwrap_or(h));
    let port = port.unwrap_or(default_port);
    (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| UaError(format!("cannot resolve {host}: {e}")))?
        .next()
        .ok_or_else(|| UaError(format!("no address for {host}")))
}

/// Local IP the OS would use to reach `target` (route-based interface choice).
pub fn local_ip_for(target: SocketAddr) -> Result<IpAddr> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let s = UdpSocket::bind(bind)?;
    s.connect(target)?;
    Ok(s.local_addr()?.ip())
}

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Builds a Digest Authorization value (RFC 2617 / 8760 MD5).
pub fn digest_authorization(
    challenge: &str,
    method: &str,
    uri: &str,
    user: &str,
    pass: &str,
    nc: u32,
) -> String {
    let params_str = challenge
        .trim()
        .splitn(2, char::is_whitespace)
        .nth(1)
        .unwrap_or("");
    let mut realm = String::new();
    let mut nonce = String::new();
    let mut opaque = None;
    let mut qop = None;
    let mut algorithm = None;
    for p in sip::split_list(params_str) {
        let mut kv = p.splitn(2, '=');
        let k = kv.next().unwrap_or("").trim().to_ascii_lowercase();
        let v = kv.next().unwrap_or("").trim().trim_matches('"').to_string();
        match k.as_str() {
            "realm" => realm = v,
            "nonce" => nonce = v,
            "opaque" => opaque = Some(v),
            "qop" => qop = Some(v),
            "algorithm" => algorithm = Some(v),
            _ => {}
        }
    }
    let ha1 = md5_hex(&format!("{user}:{realm}:{pass}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let use_qop = qop
        .as_deref()
        .map(|q| q.split(',').any(|x| x.trim() == "auth"))
        .unwrap_or(false);
    let cnonce = rand_hex(16);
    let nc_s = format!("{nc:08x}");
    let response = if use_qop {
        md5_hex(&format!("{ha1}:{nonce}:{nc_s}:{cnonce}:auth:{ha2}"))
    } else {
        md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
    };
    let mut v = format!("Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\"");
    if let Some(a) = algorithm {
        v.push_str(&format!(", algorithm={a}"));
    }
    if use_qop {
        v.push_str(&format!(", qop=auth, nc={nc_s}, cnonce=\"{cnonce}\""));
    }
    if let Some(o) = opaque {
        v.push_str(&format!(", opaque=\"{o}\""));
    }
    v
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Event {
    pub t_ms: u64,
    pub text: String,
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct CallOutcome {
    pub target: String,
    pub final_status: Option<u16>,
    pub final_reason: Option<String>,
    pub answered: bool,
    pub setup_ms: Option<u64>,
    pub talk_s: Option<f64>,
    pub ended_by: Option<String>,
    pub codec: Option<String>,
    pub remote_media: Option<String>,
    pub rtp_sent: u64,
    pub rtp_received: u64,
    pub events: Vec<Event>,
    pub notes: Vec<String>,
    #[serde(skip)]
    pub wav: Option<Vec<u8>>,
}

/// Options for one outbound test call.
#[derive(Debug, Clone)]
pub struct CallOptions {
    pub target: String,
    pub duration: Duration,
    pub ring_timeout: Duration,
    pub audio: AudioSource,
    /// Digits to send one second after answer.
    pub dtmf: Option<String>,
}

struct Dialog {
    call_id: String,
    local_tag: String,
    remote_tag: String,
    local_uri: String,
    remote_uri: String,
    remote_target: String,
    route_set: Vec<String>,
    cseq: u32,
    dest: SocketAddr,
}

pub struct Ua {
    pub profile: Profile,
    sock: UdpSocket,
    pub local: SocketAddr,
    pub server: SocketAddr,
    pub tap: Tap,
    started: Instant,
    pub events: Vec<Event>,
    reg_call_id: String,
    reg_tag: String,
    reg_cseq: u32,
    instance: String,
    nc: u32,
}

impl Ua {
    pub fn new(profile: Profile, tap: Tap) -> Result<Ua> {
        let b = &profile.behavior;
        let server_str = profile
            .account
            .outbound_proxy
            .clone()
            .unwrap_or_else(|| profile.account.domain.clone());
        let server = resolve(&server_str, 5060)?;
        let ip = match &b.local_ip {
            Some(s) if !s.is_empty() => s
                .parse()
                .map_err(|_| UaError(format!("bad local_ip {s}")))?,
            _ => local_ip_for(server)?,
        };
        let sock = bind_udp(SocketAddr::new(ip, b.local_port), b.dscp_sip)?;
        let local = sock.local_addr()?;
        Ok(Ua {
            profile,
            sock,
            local,
            server,
            tap,
            started: Instant::now(),
            events: Vec::new(),
            reg_call_id: format!("{}@{}", rand_hex(20), ip),
            reg_tag: rand_hex(10),
            reg_cseq: 0,
            instance: format!(
                "{}-{}-4{}-a{}-{}",
                rand_hex(8),
                rand_hex(4),
                rand_hex(3),
                rand_hex(3),
                rand_hex(12)
            ),
            nc: 0,
        })
    }

    fn ev(&mut self, text: impl Into<String>) {
        let t_ms = self.started.elapsed().as_millis() as u64;
        self.events.push(Event {
            t_ms,
            text: text.into(),
        });
    }

    fn domain(&self) -> String {
        self.profile.account.domain.clone()
    }

    fn aor(&self) -> String {
        sipmsg::aor(&self.profile)
    }

    fn from_header(&self, tag: &str) -> String {
        sipmsg::from_header(&self.profile, tag)
    }

    fn contact(&self, register: bool) -> String {
        sipmsg::contact(&self.profile, self.local, &self.instance, register)
    }

    fn hn(&self, full: &'static str) -> &'static str {
        sipmsg::hn(&self.profile.behavior, full)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        &self,
        method: &str,
        ruri: &str,
        branch: &str,
        from: &str,
        to: &str,
        call_id: &str,
        cseq: u32,
        cseq_method: &str,
        routes: &[String],
        extra: &[(String, String)],
        body: Option<(&str, &str)>,
    ) -> String {
        sipmsg::build_request(
            &self.profile.behavior,
            self.local,
            method,
            ruri,
            branch,
            from,
            to,
            call_id,
            cseq,
            cseq_method,
            routes,
            extra,
            body,
        )
    }

    fn send(&self, text: &str, dest: SocketAddr) -> Result<()> {
        self.sock.send_to(text.as_bytes(), dest)?;
        self.tap.record(self.local, dest, text.as_bytes());
        Ok(())
    }

    /// Receives one SIP message (keepalives are skipped).
    fn recv(&self, timeout: Duration) -> Result<Option<(SipMessage, SocketAddr)>> {
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 65535];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            self.sock
                .set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))))?;
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    self.tap.record(from, self.local, &buf[..n]);
                    if self.profile.behavior.filter_registrar && from.ip() != self.server.ip() {
                        continue;
                    }
                    if let Some(m) = sip::parse_datagram(&buf[..n]) {
                        return Ok(Some((m, from)));
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(None)
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Replies to a request with a minimal response copying the dialog headers.
    #[allow(clippy::too_many_arguments)]
    fn reply(
        &self,
        req: &SipMessage,
        from: SocketAddr,
        code: u16,
        reason: &str,
        to_tag: Option<&str>,
        extra: &[(String, String)],
        body: Option<(&str, &str)>,
    ) -> Result<()> {
        let s = sipmsg::build_response(
            &self.profile,
            self.local,
            &self.instance,
            req,
            from,
            code,
            reason,
            to_tag,
            extra,
            body,
        );
        self.send(&s, from)
    }

    /// Handles requests that arrive outside the transaction being waited on.
    fn handle_stray(&mut self, m: &SipMessage, from: SocketAddr) -> Result<()> {
        match m.method() {
            Some("OPTIONS") | Some("NOTIFY") | Some("INFO") | Some("UPDATE") => {
                self.reply(m, from, 200, "OK", Some(&rand_hex(8)), &[], None)
            }
            Some("INVITE") => self.reply(m, from, 486, "Busy Here", Some(&rand_hex(8)), &[], None),
            Some("ACK") | None => Ok(()),
            Some(other) => {
                let o = other.to_string();
                self.ev(format!("unexpected {o} answered 481"));
                self.reply(
                    m,
                    from,
                    481,
                    "Call/Transaction Does Not Exist",
                    None,
                    &[],
                    None,
                )
            }
        }
    }

    /// Sends a request and waits for its final response, retransmitting per RFC 3261 timers.
    /// `on_provisional` is called for each 1xx (used for PRACK).
    fn transact(
        &mut self,
        text: &str,
        dest: SocketAddr,
        branch: &str,
        invite: bool,
        mut on_provisional: impl FnMut(&mut Self, &SipMessage) -> Result<()>,
    ) -> Result<Option<SipMessage>> {
        let t1 = Duration::from_millis(self.profile.behavior.t1_ms.max(1));
        let t2 = Duration::from_secs(4);
        let timeout = t1 * 64;
        let start = Instant::now();
        let mut interval = t1;
        let mut next = start + interval;
        let mut provisional = false;
        self.send(text, dest)?;
        loop {
            let now = Instant::now();
            if now >= start + timeout && !provisional {
                return Ok(None);
            }
            if invite && provisional && now >= start + Duration::from_secs(180) {
                return Ok(None);
            }
            let wait = if provisional && invite {
                Duration::from_millis(200)
            } else {
                next.saturating_duration_since(now)
                    .max(Duration::from_millis(1))
            };
            match self.recv(wait)? {
                Some((m, from)) => {
                    if m.is_request() {
                        self.handle_stray(&m, from)?;
                        continue;
                    }
                    if m.top_via().and_then(|v| v.branch).as_deref() != Some(branch) {
                        continue; // response to another transaction (e.g. PRACK 200)
                    }
                    let st = m.status().unwrap_or(0);
                    if st < 200 {
                        provisional = true;
                        on_provisional(self, &m)?;
                        if !invite {
                            interval = t2;
                        }
                        continue;
                    }
                    return Ok(Some(m));
                }
                None => {
                    if Instant::now() >= next && !(invite && provisional) {
                        self.send(text, dest)?;
                        interval = if invite {
                            interval * 2
                        } else {
                            (interval * 2).min(t2)
                        };
                        next = Instant::now() + interval;
                    }
                }
            }
        }
    }

    fn challenge_header(resp: &SipMessage) -> Option<(String, &'static str)> {
        match resp.status() {
            Some(401) => resp
                .header("WWW-Authenticate")
                .map(|c| (c.to_string(), "Authorization")),
            Some(407) => resp
                .header("Proxy-Authenticate")
                .map(|c| (c.to_string(), "Proxy-Authorization")),
            _ => None,
        }
    }

    fn auth_value(&mut self, challenge: &str, method: &str, uri: &str) -> Option<String> {
        let pass = self.profile.account.password.clone()?;
        let user = self
            .profile
            .account
            .auth_user
            .clone()
            .unwrap_or_else(|| self.profile.account.user.clone());
        self.nc += 1;
        Some(digest_authorization(
            challenge, method, uri, &user, &pass, self.nc,
        ))
    }

    /// REGISTER (or un-REGISTER with expires 0). Returns the final status.
    pub fn register(&mut self, expires: Option<u32>) -> Result<Option<u16>> {
        let expires = expires.unwrap_or(self.profile.account.expires);
        let ruri = format!("sip:{}", sip::split_host_port(&self.domain()).0);
        let aor = self.aor();
        let mut auth: Option<(String, String)> = None;
        for _attempt in 0..3 {
            self.reg_cseq += 1;
            let branch = format!("z9hG4bK{}", rand_hex(16));
            let mut extra = vec![
                ("Contact".to_string(), self.contact(true)),
                ("Expires".to_string(), expires.to_string()),
            ];
            let mut sup = vec!["path"];
            if self.profile.behavior.offer_gruu {
                sup.push("gruu");
            }
            if self.profile.behavior.long_contact {
                sup.push("outbound");
            }
            extra.push((self.hn("Supported").to_string(), sup.join(", ")));
            if let Some(a) = &auth {
                extra.push(a.clone());
            }
            let from = self.from_header(&self.reg_tag.clone());
            let text = self.build(
                "REGISTER",
                &ruri,
                &branch,
                &from,
                &format!("<{aor}>"),
                &self.reg_call_id.clone(),
                self.reg_cseq,
                "REGISTER",
                &[],
                &extra,
                None,
            );
            self.ev(format!("REGISTER expires={expires} -> {}", self.server));
            let resp = self.transact(&text, self.server, &branch, false, |_, _| Ok(()))?;
            let Some(resp) = resp else {
                self.ev("REGISTER timed out (no response)");
                return Ok(None);
            };
            let st = resp.status().unwrap_or(0);
            self.ev(format!("REGISTER <- {}", resp.summary()));
            if let Some((ch, hdr)) = Self::challenge_header(&resp) {
                if auth.is_some() {
                    return Ok(Some(st)); // credentials rejected
                }
                match self.auth_value(&ch, "REGISTER", &ruri) {
                    Some(v) => {
                        auth = Some((hdr.to_string(), v));
                        continue;
                    }
                    None => {
                        self.ev("challenge received but no password configured");
                        return Ok(Some(st));
                    }
                }
            }
            return Ok(Some(st));
        }
        Ok(None)
    }

    /// OPTIONS ping; returns (status, round trip ms).
    pub fn options(&mut self, target: &str) -> Result<Option<(u16, u64)>> {
        let ruri = self.target_uri(target);
        let dest = self.dest_for_uri(&ruri)?;
        let branch = format!("z9hG4bK{}", rand_hex(16));
        let cid = format!("{}@{}", rand_hex(16), self.local.ip());
        let tag = rand_hex(10);
        let from = self.from_header(&tag);
        let text = self.build(
            "OPTIONS",
            &ruri,
            &branch,
            &from,
            &format!("<{ruri}>"),
            &cid,
            1,
            "OPTIONS",
            &[],
            &[("Accept".into(), "application/sdp".into())],
            None,
        );
        let t = Instant::now();
        let r = self.transact(&text, dest, &branch, false, |_, _| Ok(()))?;
        Ok(r.and_then(|m| m.status())
            .map(|s| (s, t.elapsed().as_millis() as u64)))
    }

    fn target_uri(&self, target: &str) -> String {
        sipmsg::target_uri(&self.profile, target)
    }

    fn dest_for_uri(&self, uri: &str) -> Result<SocketAddr> {
        if self.profile.account.outbound_proxy.is_some() {
            return Ok(self.server);
        }
        let u = Uri::parse(uri).ok_or_else(|| UaError(format!("bad URI {uri}")))?;
        let hp = match u.port {
            Some(p) => format!("{}:{p}", u.host),
            None => u.host.clone(),
        };
        resolve(&hp, 5060)
    }

    fn sdp_offer(&self, rtp: SocketAddr, codecs: &[Codec], dtmf_pt: Option<u8>) -> String {
        let b = &self.profile.behavior;
        let ip = b
            .sdp_ip_override
            .clone()
            .unwrap_or_else(|| rtp.ip().to_string());
        let fam = if ip.contains(':') { "IP6" } else { "IP4" };
        let sess = rand_hex(8)
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>();
        let sess = if sess.is_empty() { "1".into() } else { sess };
        let mut pts: Vec<String> = codecs.iter().map(|c| c.pt().to_string()).collect();
        if let Some(p) = dtmf_pt {
            pts.push(p.to_string());
        }
        let mut s = format!("v=0\r\no=sidetone {sess} {sess} IN {fam} {ip}\r\ns=Sidetone\r\nc=IN {fam} {ip}\r\nt=0 0\r\nm=audio {} RTP/AVP {}\r\n", rtp.port(), pts.join(" "));
        for c in codecs {
            s.push_str(&format!("a=rtpmap:{} {}\r\n", c.pt(), c.rtpmap()));
        }
        if let Some(p) = dtmf_pt {
            s.push_str(&format!(
                "a=rtpmap:{p} telephone-event/8000\r\na=fmtp:{p} 0-16\r\n"
            ));
        }
        s.push_str(&format!(
            "a=ptime:{}\r\na={}\r\n",
            b.ptime_ms, b.sdp_direction
        ));
        if !b.rtcp {
            s.push_str(&format!("a=rtcp:{}\r\n", rtp.port() + 1));
        }
        s
    }

    fn profile_codecs(&self) -> Vec<Codec> {
        crate::sipmsg::profile_codecs(&self.profile.behavior)
    }

    fn dialog_request(
        &self,
        d: &mut Dialog,
        method: &str,
        extra: &[(String, String)],
        body: Option<(&str, &str)>,
        new_cseq: bool,
    ) -> (String, String) {
        if new_cseq {
            d.cseq += 1;
        }
        let branch = format!("z9hG4bK{}", rand_hex(16));
        let from = format!("<{}>;tag={}", d.local_uri, d.local_tag);
        let to = format!("<{}>;tag={}", d.remote_uri, d.remote_tag);
        let cseq_method = method;
        let text = self.build(
            method,
            &d.remote_target,
            &branch,
            &from,
            &to,
            &d.call_id,
            d.cseq,
            cseq_method,
            &d.route_set,
            extra,
            body,
        );
        (text, branch)
    }

    /// Places an outbound test call and returns its outcome.
    pub fn call(&mut self, opts: &CallOptions) -> Result<CallOutcome> {
        let mark = self.events.len();
        let mut out = self.call_inner(opts)?;
        out.events = self.events[mark..].to_vec();
        Ok(out)
    }

    fn call_inner(&mut self, opts: &CallOptions) -> Result<CallOutcome> {
        let mut out = CallOutcome {
            target: opts.target.clone(),
            ..Default::default()
        };
        out.notes.extend(self.profile.unsupported());
        let ruri = self.target_uri(&opts.target);
        let dest = self.dest_for_uri(&ruri)?;
        let b = self.profile.behavior.clone();
        let mut rtp = RtpSession::bind(
            self.local.ip(),
            b.rtp_port_start,
            b.rtp_port_end,
            b.dscp_rtp,
        )?;
        let codecs = self.profile_codecs();
        let dtmf_pt = if b.dtmf_mode == DtmfMode::Rfc4733 {
            Some(b.dtmf_payload_type)
        } else {
            None
        };
        let offer = self.sdp_offer(rtp.local, &codecs, dtmf_pt);
        let call_id = format!("{}@{}", rand_hex(20), self.local.ip());
        let ltag = rand_hex(10);
        let from = self.from_header(&ltag);
        let mut cseq = 1u32;
        let mut auth: Option<(String, String)> = None;
        let t_start = Instant::now();
        let mut supported = vec!["replaces", "100rel"];
        if b.session_timer > 0 {
            supported.push("timer");
        }
        if b.offer_gruu {
            supported.push("gruu");
        }

        let final_resp: SipMessage;
        let mut invite_branch;
        let mut last_invite_text;
        loop {
            invite_branch = format!("z9hG4bK{}", rand_hex(16));
            let mut extra = vec![
                ("Contact".to_string(), self.contact(false)),
                (
                    "Allow".to_string(),
                    "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, NOTIFY".to_string(),
                ),
                (self.hn("Supported").to_string(), supported.join(", ")),
            ];
            if b.require_prack {
                extra.push(("Require".into(), "100rel".into()));
            }
            if b.session_timer > 0 {
                extra.push((
                    "Session-Expires".into(),
                    format!("{};refresher=uac", b.session_timer),
                ));
                extra.push(("Min-SE".into(), "90".into()));
            }
            if let Some(a) = &auth {
                extra.push(a.clone());
            }
            last_invite_text = self.build(
                "INVITE",
                &ruri,
                &invite_branch,
                &from,
                &format!("<{ruri}>"),
                &call_id,
                cseq,
                "INVITE",
                &[],
                &extra,
                Some(("application/sdp", &offer)),
            );
            self.ev(format!("INVITE {ruri} -> {dest}"));
            let ruri_c = ruri.clone();
            let cid_c = call_id.clone();
            let ltag_c = ltag.clone();
            let ring_deadline = t_start + opts.ring_timeout;
            let resp = self.transact(
                &last_invite_text,
                dest,
                &invite_branch.clone(),
                true,
                |ua, m| {
                    ua.ev(format!("<- {}", m.summary()));
                    // PRACK for reliable provisionals.
                    let reliable = m
                        .header("Require")
                        .map(|r| r.contains("100rel"))
                        .unwrap_or(false);
                    if let (true, Some(rseq)) = (reliable, m.header("RSeq")) {
                        let rt = m.header("Contact").and_then(Uri::from_header).map(|u| {
                            let port = u.port.map(|p| format!(":{p}")).unwrap_or_default();
                            format!(
                                "sip:{}{}@{}{}",
                                u.user.clone().unwrap_or_default(),
                                "",
                                u.host,
                                port
                            )
                        });
                        let mut d = Dialog {
                            call_id: cid_c.clone(),
                            local_tag: ltag_c.clone(),
                            remote_tag: m.to_tag().unwrap_or_default(),
                            local_uri: ua.aor(),
                            remote_uri: ruri_c.clone(),
                            remote_target: rt.unwrap_or_else(|| ruri_c.clone()),
                            route_set: m.header_values("Record-Route").into_iter().rev().collect(),
                            cseq: cseq,
                            dest,
                        };
                        let rack = format!("{} {} INVITE", rseq.trim(), cseq);
                        let (text, _) = ua.dialog_request(
                            &mut d,
                            "PRACK",
                            &[("RAck".into(), rack)],
                            None,
                            true,
                        );
                        ua.send(&text, d.dest)?;
                        ua.ev("PRACK sent");
                    }
                    if Instant::now() > ring_deadline {
                        return Err(UaError("ring timeout".into()));
                    }
                    Ok(())
                },
            );
            let resp = match resp {
                Ok(r) => r,
                Err(UaError(e)) if e == "ring timeout" => {
                    // CANCEL uses the INVITE branch and CSeq number.
                    let cancel = self.build(
                        "CANCEL",
                        &ruri,
                        &invite_branch,
                        &from,
                        &format!("<{ruri}>"),
                        &call_id,
                        cseq,
                        "CANCEL",
                        &[],
                        &[],
                        None,
                    );
                    self.ev("ring timeout, CANCEL");
                    self.send(&cancel, dest)?;
                    let end = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < end {
                        if let Some((m, from_addr)) = self.recv(Duration::from_millis(300))? {
                            if m.status().map(|s| s >= 300).unwrap_or(false)
                                && m.cseq().map(|c| c.1 == "INVITE").unwrap_or(false)
                            {
                                self.send_ack_non2xx(
                                    &m,
                                    &ruri,
                                    &invite_branch,
                                    &from,
                                    &call_id,
                                    cseq,
                                    dest,
                                )?;
                                out.final_status = m.status();
                                let _ = from_addr;
                                break;
                            }
                        }
                    }
                    out.ended_by = Some("local (cancel)".into());
                    return Ok(out);
                }
                Err(e) => return Err(e),
            };
            let Some(resp) = resp else {
                self.ev("INVITE timed out (Timer B)");
                out.notes.push("no final response within 64*T1".into());
                return Ok(out);
            };
            self.ev(format!("<- {}", resp.summary()));
            let st = resp.status().unwrap_or(0);
            if st >= 300 {
                self.send_ack_non2xx(&resp, &ruri, &invite_branch, &from, &call_id, cseq, dest)?;
            }
            if let Some((ch, hdr)) = Self::challenge_header(&resp) {
                if auth.is_none() {
                    if let Some(v) = self.auth_value(&ch, "INVITE", &ruri) {
                        auth = Some((hdr.to_string(), v));
                        cseq += 1;
                        continue;
                    }
                }
            }
            final_resp = resp;
            break;
        }
        let st = final_resp.status().unwrap_or(0);
        out.final_status = Some(st);
        if let sip::StartLine::Response { reason, .. } = &final_resp.start {
            out.final_reason = Some(reason.clone());
        }
        if !(200..300).contains(&st) {
            return Ok(out);
        }
        out.answered = true;
        out.setup_ms = Some(t_start.elapsed().as_millis() as u64);

        // Dialog from the 2xx.
        let remote_target = final_resp
            .header("Contact")
            .and_then(Uri::from_header)
            .map(|u| {
                let port = u.port.map(|p| format!(":{p}")).unwrap_or_default();
                let user = u.user.map(|x| format!("{x}@")).unwrap_or_default();
                format!("sip:{user}{}{port}", u.host)
            })
            .unwrap_or_else(|| ruri.clone());
        let route_set: Vec<String> = final_resp
            .header_values("Record-Route")
            .into_iter()
            .rev()
            .collect();
        let in_dialog_dest = if self.profile.account.outbound_proxy.is_some() {
            self.server
        } else if let Some(first) = route_set.first() {
            let u = Uri::from_header(first).ok_or_else(|| UaError("bad Record-Route".into()))?;
            resolve(
                &format!(
                    "{}{}",
                    u.host,
                    u.port.map(|p| format!(":{p}")).unwrap_or_default()
                ),
                5060,
            )?
        } else {
            self.dest_for_uri(&remote_target)?
        };
        let mut d = Dialog {
            call_id: call_id.clone(),
            local_tag: ltag.clone(),
            remote_tag: final_resp.to_tag().unwrap_or_default(),
            local_uri: self.aor(),
            remote_uri: ruri.clone(),
            remote_target,
            route_set,
            cseq,
            dest: in_dialog_dest,
        };
        let (ack, _) = self.dialog_request(&mut d, "ACK", &[], None, false);
        let ack = ack.replace(
            &format!("CSeq: {} ACK", d.cseq),
            &format!("CSeq: {cseq} ACK"),
        );
        if b.skip_ack {
            self.ev("ACK deliberately skipped (profile.skip_ack)");
        } else {
            self.send(&ack, d.dest)?;
        }

        // Media from the answer.
        let answer = if final_resp.has_sdp() {
            sdp::parse(&final_resp.body)
        } else {
            None
        };
        let Some(answer) = answer else {
            out.notes
                .push("2xx without SDP answer; no media started".into());
            self.hangup(&mut d, &mut out)?;
            return Ok(out);
        };
        let media = answer
            .media
            .iter()
            .find(|m| m.kind == "audio" && m.port != 0);
        let Some(media) = media else {
            out.notes.push("answer has no active audio stream".into());
            self.hangup(&mut d, &mut out)?;
            return Ok(out);
        };
        let codec = media
            .formats
            .iter()
            .find_map(|pt| Codec::from_media(&media, *pt))
            .unwrap_or(codecs[0]);
        let remote_dtmf = media
            .codecs
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case("telephone-event"))
            .map(|c| c.pt);
        let remote_ip = media.address(&answer).unwrap_or(dest.ip());
        let remote = SocketAddr::new(remote_ip, media.port);
        out.codec = Some(codec.name().into());
        out.remote_media = Some(remote.to_string());
        rtp.start(
            remote,
            codec,
            b.ptime_ms,
            opts.audio.clone(),
            if b.dtmf_mode == DtmfMode::Rfc4733 {
                remote_dtmf
            } else {
                None
            },
            b.symmetric_rtp,
            self.tap.clone(),
        );
        self.ev(format!("media {} -> {remote} {}", rtp.local, codec.name()));
        let answered_at = Instant::now();
        let mut dtmf_sent = false;
        let mut refreshed_at = Instant::now();
        let mut ended_remote = false;
        while answered_at.elapsed() < opts.duration {
            if !dtmf_sent && answered_at.elapsed() > Duration::from_secs(1) {
                if let Some(digits) = &opts.dtmf {
                    match b.dtmf_mode {
                        DtmfMode::Rfc4733 => rtp.queue_dtmf(digits),
                        DtmfMode::Info => {
                            for dg in digits.chars() {
                                let body = format!("Signal={dg}\r\nDuration=160\r\n");
                                let (text, br) = self.dialog_request(
                                    &mut d,
                                    "INFO",
                                    &[],
                                    Some(("application/dtmf-relay", &body)),
                                    true,
                                );
                                let r = self.transact(&text, d.dest, &br, false, |_, _| Ok(()))?;
                                self.ev(format!(
                                    "INFO {dg} -> {}",
                                    r.map(|m| m.summary()).unwrap_or_else(|| "timeout".into())
                                ));
                            }
                        }
                        DtmfMode::Inband => rtp.ctl.inband.lock().unwrap().extend(digits.chars()),
                    }
                    self.ev(format!("DTMF {digits} via {:?}", b.dtmf_mode));
                }
                dtmf_sent = true;
            }
            if b.session_timer > 0
                && refreshed_at.elapsed() > Duration::from_secs((b.session_timer / 2) as u64)
            {
                let (text, br) = self.dialog_request(
                    &mut d,
                    "UPDATE",
                    &[(
                        "Session-Expires".into(),
                        format!("{};refresher=uac", b.session_timer),
                    )],
                    None,
                    true,
                );
                let r = self.transact(&text, d.dest, &br, false, |_, _| Ok(()))?;
                self.ev(format!(
                    "session refresh UPDATE -> {}",
                    r.map(|m| m.summary()).unwrap_or_else(|| "timeout".into())
                ));
                refreshed_at = Instant::now();
            }
            if let Some((m, from_addr)) = self.recv(Duration::from_millis(200))? {
                if m.is_request() {
                    match m.method() {
                        Some("BYE") => {
                            self.reply(&m, from_addr, 200, "OK", None, &[], None)?;
                            self.ev("<- BYE (remote hangup)");
                            ended_remote = true;
                            break;
                        }
                        Some("INVITE") => {
                            let body = self.sdp_offer(rtp.local, &[codec], remote_dtmf);
                            self.reply(
                                &m,
                                from_addr,
                                200,
                                "OK",
                                None,
                                &[],
                                Some(("application/sdp", &body)),
                            )?;
                            self.ev("<- re-INVITE answered 200");
                        }
                        _ => self.handle_stray(&m, from_addr)?,
                    }
                } else if m.status().map(|s| (200..300).contains(&s)).unwrap_or(false)
                    && m.cseq().map(|c| c.1 == "INVITE").unwrap_or(false)
                {
                    if !b.skip_ack {
                        self.send(&ack, d.dest)?;
                        self.ev("200 OK retransmission: ACK resent");
                    }
                }
            }
        }
        rtp.stop();
        out.talk_s = Some(answered_at.elapsed().as_secs_f64());
        {
            let st = rtp.stats.lock().unwrap();
            out.rtp_sent = st.sent_packets;
            out.rtp_received = st.received_packets;
        }
        if out.rtp_received == 0 {
            out.notes.push("no RTP received from the far end".into());
        }
        out.wav = Some(rtp.wav());
        if ended_remote {
            out.ended_by = Some("remote".into());
        } else {
            self.hangup(&mut d, &mut out)?;
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_ack_non2xx(
        &mut self,
        resp: &SipMessage,
        ruri: &str,
        branch: &str,
        from: &str,
        call_id: &str,
        cseq: u32,
        dest: SocketAddr,
    ) -> Result<()> {
        let to = resp.header("To").unwrap_or("").to_string();
        let ack = self.build(
            "ACK",
            ruri,
            branch,
            from,
            &to,
            call_id,
            cseq,
            "ACK",
            &[],
            &[],
            None,
        );
        self.send(&ack, dest)
    }

    fn hangup(&mut self, d: &mut Dialog, out: &mut CallOutcome) -> Result<()> {
        let (bye, br) = self.dialog_request(
            d,
            "BYE",
            &[(
                "Reason".into(),
                "Q.850;cause=16;text=\"Normal call clearing\"".into(),
            )],
            None,
            true,
        );
        let r = self.transact(&bye, d.dest, &br, false, |_, _| Ok(()))?;
        self.ev(format!(
            "BYE -> {}",
            r.as_ref()
                .map(|m| m.summary())
                .unwrap_or_else(|| "timeout".into())
        ));
        out.ended_by = Some("local".into());
        Ok(())
    }

    /// Waits for incoming calls and answers them (tone or echo), up to `max_calls`.
    pub fn answer(
        &mut self,
        max_calls: usize,
        wait: Duration,
        talk: Duration,
        audio: AudioSource,
    ) -> Result<Vec<CallOutcome>> {
        let mut results = Vec::new();
        let deadline = Instant::now() + wait;
        let b = self.profile.behavior.clone();
        while results.len() < max_calls && Instant::now() < deadline {
            let Some((m, from)) = self.recv(Duration::from_millis(500))? else {
                continue;
            };
            if m.method() != Some("INVITE") || m.to_tag().is_some() {
                if m.is_request() {
                    self.handle_stray(&m, from)?;
                }
                continue;
            }
            let mut out = CallOutcome {
                target: m.header("From").unwrap_or("").to_string(),
                ..Default::default()
            };
            let tag = rand_hex(10);
            self.ev(format!("<- INVITE from {from}"));
            self.reply(&m, from, 100, "Trying", None, &[], None)?;
            self.reply(&m, from, 180, "Ringing", Some(&tag), &[], None)?;
            let offer = if m.has_sdp() {
                sdp::parse(&m.body)
            } else {
                None
            };
            let Some(offer) = offer else {
                self.reply(&m, from, 488, "Not Acceptable Here", Some(&tag), &[], None)?;
                out.notes
                    .push("INVITE without SDP (late offer) not supported in answer mode".into());
                results.push(out);
                continue;
            };
            let media = offer
                .media
                .iter()
                .find(|x| x.kind == "audio" && x.port != 0)
                .cloned();
            let mine = self.profile_codecs();
            let codec = media.as_ref().and_then(|md| {
                md.formats
                    .iter()
                    .filter_map(|p| Codec::from_media(md, *p))
                    .find(|c| mine.contains(c))
            });
            let (Some(media), Some(codec)) = (media, codec) else {
                self.reply(
                    &m,
                    from,
                    488,
                    "Not Acceptable Here",
                    Some(&tag),
                    &[("Warning".into(), "304 sidetone \"No common codec\"".into())],
                    None,
                )?;
                out.final_status = Some(488);
                results.push(out);
                continue;
            };
            let remote_dtmf = media
                .codecs
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case("telephone-event"))
                .map(|c| c.pt);
            let mut rtp = RtpSession::bind(
                self.local.ip(),
                b.rtp_port_start,
                b.rtp_port_end,
                b.dscp_rtp,
            )?;
            let answer = self.sdp_offer(rtp.local, &[codec], remote_dtmf);
            self.reply(
                &m,
                from,
                200,
                "OK",
                Some(&tag),
                &[],
                Some(("application/sdp", &answer)),
            )?;
            let remote = SocketAddr::new(media.address(&offer).unwrap_or(from.ip()), media.port);
            rtp.start(
                remote,
                codec,
                b.ptime_ms,
                audio.clone(),
                remote_dtmf,
                b.symmetric_rtp,
                self.tap.clone(),
            );
            out.answered = true;
            out.final_status = Some(200);
            out.codec = Some(codec.name().into());
            out.remote_media = Some(remote.to_string());
            let t = Instant::now();
            let mut got_ack = false;
            let mut ended = false;
            let mut last_200 = Instant::now();
            let mut interval = Duration::from_millis(b.t1_ms);
            while t.elapsed() < talk {
                if !got_ack && last_200.elapsed() >= interval {
                    self.reply(
                        &m,
                        from,
                        200,
                        "OK",
                        Some(&tag),
                        &[],
                        Some(("application/sdp", &answer)),
                    )?;
                    last_200 = Instant::now();
                    interval = (interval * 2).min(Duration::from_secs(4));
                    if t.elapsed() > Duration::from_millis(b.t1_ms * 64) {
                        out.notes
                            .push("ACK never received; ending call (Timer H)".into());
                        break;
                    }
                }
                if let Some((r, rfrom)) = self.recv(Duration::from_millis(100))? {
                    match r.method() {
                        Some("ACK") => got_ack = true,
                        Some("BYE") => {
                            self.reply(&r, rfrom, 200, "OK", None, &[], None)?;
                            out.ended_by = Some("remote".into());
                            ended = true;
                            break;
                        }
                        Some(_) => self.handle_stray(&r, rfrom)?,
                        None => {}
                    }
                }
            }
            rtp.stop();
            out.talk_s = Some(t.elapsed().as_secs_f64());
            {
                let st = rtp.stats.lock().unwrap();
                out.rtp_sent = st.sent_packets;
                out.rtp_received = st.received_packets;
            }
            out.wav = Some(rtp.wav());
            if !ended {
                // We hang up: BYE towards the caller's Contact.
                let contact = m.header("Contact").and_then(Uri::from_header);
                let target = contact
                    .map(|u| {
                        format!(
                            "sip:{}{}{}",
                            u.user.map(|x| format!("{x}@")).unwrap_or_default(),
                            u.host,
                            u.port.map(|p| format!(":{p}")).unwrap_or_default()
                        )
                    })
                    .unwrap_or_else(|| format!("sip:{from}"));
                let mut d = Dialog {
                    call_id: m.call_id().unwrap_or("").to_string(),
                    local_tag: tag.clone(),
                    remote_tag: m.from_tag().unwrap_or_default(),
                    local_uri: m
                        .header("To")
                        .and_then(Uri::from_header)
                        .map(|u| format!("sip:{}@{}", u.user.unwrap_or_default(), u.host))
                        .unwrap_or_else(|| self.aor()),
                    remote_uri: m
                        .header("From")
                        .and_then(Uri::from_header)
                        .map(|u| format!("sip:{}@{}", u.user.unwrap_or_default(), u.host))
                        .unwrap_or_default(),
                    remote_target: target.clone(),
                    route_set: m.header_values("Record-Route"),
                    cseq: 100,
                    dest: from,
                };
                self.hangup(&mut d, &mut out)?;
            }
            out.events = self.events.clone();
            results.push(out);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_rfc2617_example() {
        // RFC 2617 section 3.5 example values (with qop the cnonce is random, so test without qop).
        let ch =
            "Digest realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
        let v = digest_authorization(ch, "GET", "/dir/index.html", "Mufasa", "Circle Of Life", 1);
        let ha1 = md5_hex("Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = md5_hex("GET:/dir/index.html");
        let expected = md5_hex(&format!("{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:{ha2}"));
        assert!(v.contains(&format!("response=\"{expected}\"")));
    }
}
