//! Ladder (sequence) diagram rendering as standalone SVG and as plain text.

use crate::analysis::{Report, Severity};
use std::fmt::Write;

#[derive(Debug, Clone)]
pub struct LadderOptions {
    /// Restrict to one call; `None` draws every SIP message.
    pub call: Option<usize>,
    /// Several calls in one diagram (call legs side by side); when not
    /// empty it takes precedence over `call`.
    pub calls: Vec<usize>,
    /// Columns per IP instead of per IP:port. `None` picks automatically.
    pub group_by_ip: Option<bool>,
    pub include_rtp: bool,
    /// RTP streams in a block after the SIP instead of at the moment they start.
    pub rtp_at_end: bool,
}

impl Default for LadderOptions {
    fn default() -> Self {
        LadderOptions {
            call: None,
            calls: Vec::new(),
            group_by_ip: None,
            include_rtp: true,
            rtp_at_end: false,
        }
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn host_of(addr: &str) -> String {
    match addr.rfind(':') {
        Some(i) if addr.starts_with('[') => addr[1..i.saturating_sub(1)].to_string(),
        Some(i) => addr[..i].to_string(),
        None => addr.to_string(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
    }
}

/// Message indices drawn by the ladder for the given options.
pub fn ladder_messages(r: &Report, call: Option<usize>) -> Vec<usize> {
    match call {
        Some(c) => r
            .calls
            .get(c)
            .map(|c| c.messages.clone())
            .unwrap_or_default(),
        None => (0..r.messages.len()).collect(),
    }
}

fn columns(r: &Report, msgs: &[usize], streams: &[usize], by_ip: bool) -> Vec<String> {
    let key = |a: &str| if by_ip { host_of(a) } else { a.to_string() };
    let mut cols: Vec<String> = Vec::new();
    for &i in msgs {
        let m = &r.messages[i];
        for a in [&m.src, &m.dst] {
            let k = key(a);
            if !cols.contains(&k) {
                cols.push(k);
            }
        }
    }
    for &s in streams {
        let st = &r.streams[s];
        for a in [&st.src, &st.dst] {
            let k = key(a);
            if !cols.contains(&k) {
                cols.push(k);
            }
        }
    }
    cols
}

fn decide_by_ip(r: &Report, msgs: &[usize], opt: Option<bool>) -> bool {
    opt.unwrap_or_else(|| {
        !msgs
            .iter()
            .any(|&i| host_of(&r.messages[i].src) == host_of(&r.messages[i].dst))
    })
}

fn color_for(method: Option<&str>, status: Option<u16>) -> &'static str {
    match (method, status) {
        (_, Some(s)) if s < 200 => "st-prov",
        (_, Some(s)) if s < 300 => "st-ok",
        (_, Some(s)) if s < 400 => "st-redir",
        (_, Some(_)) => "st-err",
        (Some("BYE" | "CANCEL"), _) => "st-end",
        _ => "st-req",
    }
}

/// Messages of several calls, in capture order.
pub fn ladder_messages_of(r: &Report, calls: &[usize]) -> Vec<usize> {
    let mut v: Vec<usize> = calls
        .iter()
        .filter_map(|c| r.calls.get(*c))
        .flat_map(|c| c.messages.iter().copied())
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

pub fn render_svg(r: &Report, opt: &LadderOptions) -> String {
    if !opt.calls.is_empty() {
        let mut streams: Vec<usize> = if opt.include_rtp {
            opt.calls
                .iter()
                .filter_map(|c| r.calls.get(*c))
                .flat_map(|c| c.streams.iter().copied())
                .collect()
        } else {
            vec![]
        };
        streams.sort_unstable();
        streams.dedup();
        return render_with(r, ladder_messages_of(r, &opt.calls), streams, opt);
    }
    let msgs = ladder_messages(r, opt.call);
    let streams: Vec<usize> = if opt.include_rtp {
        match opt.call {
            Some(c) => r
                .calls
                .get(c)
                .map(|c| c.streams.clone())
                .unwrap_or_default(),
            None => (0..r.streams.len()).collect(),
        }
    } else {
        vec![]
    };
    render_with(r, msgs, streams, opt)
}

fn render_with(r: &Report, msgs: Vec<usize>, streams: Vec<usize>, opt: &LadderOptions) -> String {
    let by_ip = decide_by_ip(r, &msgs, opt.group_by_ip);
    let cols = columns(r, &msgs, &streams, by_ip);
    let col_w = 210.0;
    let left = 96.0;
    let top = 64.0;
    let row_h = 30.0;
    // Rows in drawing order: by default each RTP stream sits where it starts
    // among the SIP messages (after the 200 OK/ACK, before the BYE); optionally
    // all streams go in a block after the signaling.
    enum Row {
        Msg(usize),
        Stream(usize),
        RtpHeader,
    }
    let mut rows: Vec<Row> = Vec::new();
    if opt.rtp_at_end || streams.is_empty() {
        rows.extend(msgs.iter().map(|&m| Row::Msg(m)));
        if !streams.is_empty() {
            rows.push(Row::RtpHeader);
            rows.extend(streams.iter().map(|&st| Row::Stream(st)));
        }
    } else {
        let mut ss: Vec<usize> = streams.clone();
        ss.sort_by_key(|&i| r.streams[i].start_ns);
        let mut k = 0;
        for &m in &msgs {
            while k < ss.len() && r.streams[ss[k]].start_ns < r.messages[m].ts_ns {
                rows.push(Row::Stream(ss[k]));
                k += 1;
            }
            rows.push(Row::Msg(m));
        }
        rows.extend(ss[k..].iter().map(|&st| Row::Stream(st)));
    }
    let n_rows = rows.len();
    let width = left + col_w * cols.len().max(1) as f64 + 20.0;
    let height = top + row_h * n_rows as f64 + 30.0;
    let x_of = |addr: &str| -> f64 {
        let k = if by_ip {
            host_of(addr)
        } else {
            addr.to_string()
        };
        let i = cols.iter().position(|c| *c == k).unwrap_or(0);
        left + col_w * i as f64 + col_w / 2.0
    };

    // Worst finding severity per message, for markers.
    let mut sev: std::collections::HashMap<usize, (Severity, String)> =
        std::collections::HashMap::new();
    for f in &r.findings {
        for &m in &f.messages {
            let e = sev.entry(m).or_insert((f.severity, f.title.clone()));
            if f.severity > e.0 {
                *e = (f.severity, f.title.clone());
            }
        }
    }

    let mut s = String::new();
    let _ = write!(
        s,
        r#"<svg xmlns="http://www.w3.org/2000/svg" class="st-ladder" viewBox="0 0 {width:.0} {height:.0}" width="{width:.0}" height="{height:.0}" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="12">"#
    );
    s.push_str(
        r#"<style>
.st-ladder{--fg:#1f2937;--muted:#6b7280;--grid:#cbd5e1;--bg:#ffffff;--req:#2563eb;--prov:#6b7280;--ok:#16a34a;--redir:#d97706;--err:#dc2626;--end:#7c3aed;--rtp:#0891b2;--warn:#d97706;--info:#2563eb}
@media (prefers-color-scheme: dark){.st-ladder{--fg:#e5e7eb;--muted:#9ca3af;--grid:#374151;--bg:#111827;--req:#60a5fa;--prov:#9ca3af;--ok:#4ade80;--redir:#fbbf24;--err:#f87171;--end:#a78bfa;--rtp:#22d3ee;--warn:#fbbf24;--info:#60a5fa}}
:root[data-theme="dark"] .st-ladder{--fg:#e5e7eb;--muted:#9ca3af;--grid:#374151;--bg:#111827;--req:#60a5fa;--prov:#9ca3af;--ok:#4ade80;--redir:#fbbf24;--err:#f87171;--end:#a78bfa;--rtp:#22d3ee}
:root[data-theme="light"] .st-ladder{--fg:#1f2937;--muted:#6b7280;--grid:#cbd5e1;--bg:#ffffff;--req:#2563eb;--prov:#6b7280;--ok:#16a34a;--redir:#d97706;--err:#dc2626;--end:#7c3aed;--rtp:#0891b2}
.st-ladder text{fill:var(--fg)}
.st-ladder .t{fill:var(--muted)}
.st-ladder .life{stroke:var(--grid);stroke-width:1.5}
.st-ladder .st-req{stroke:var(--req);fill:var(--req);color:var(--req)}
.st-ladder .st-prov{stroke:var(--prov);fill:var(--prov);color:var(--prov)}
.st-ladder .st-ok{stroke:var(--ok);fill:var(--ok);color:var(--ok)}
.st-ladder .st-redir{stroke:var(--redir);fill:var(--redir);color:var(--redir)}
.st-ladder .st-err{stroke:var(--err);fill:var(--err);color:var(--err)}
.st-ladder .st-end{stroke:var(--end);fill:var(--end);color:var(--end)}
.st-ladder .st-rtp{stroke:var(--rtp);fill:var(--rtp);color:var(--rtp)}
.st-ladder .lbl{stroke:none;font-weight:600}
.st-ladder .retx line{stroke-dasharray:5 4;opacity:.6}
.st-ladder .retx text{opacity:.7}
.st-ladder .msg,.st-ladder .stream{cursor:pointer}
.st-ladder .msg:hover .hit,.st-ladder .stream:hover .hit{fill:var(--grid);fill-opacity:.35}
.st-ladder .hit{fill:transparent}
.st-ladder .sev-error{fill:var(--err)}
.st-ladder .sev-warning{fill:var(--warn)}
.st-ladder .sev-info{fill:var(--info)}
.st-ladder .sel .hit{fill:var(--grid);fill-opacity:.6}
</style>"#,
    );
    s.push_str(r#"<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="context-stroke"/></marker><marker id="ahr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="11" markerHeight="11" markerUnits="userSpaceOnUse" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="context-stroke"/></marker></defs>"#);

    // Column headers and lifelines.
    for (i, c) in cols.iter().enumerate() {
        let x = left + col_w * i as f64 + col_w / 2.0;
        let _ = write!(
            s,
            r#"<text x="{x:.1}" y="22" text-anchor="middle" font-weight="700">{}</text>"#,
            esc(&truncate(c, 28))
        );
        let ua = ua_for(r, &msgs, c, by_ip);
        if let Some(ua) = ua {
            let _ = write!(
                s,
                r#"<text class="t" x="{x:.1}" y="38" text-anchor="middle" font-size="10">{}</text>"#,
                esc(&truncate(&ua, 32))
            );
        }
        let _ = write!(
            s,
            r#"<line class="life" x1="{x:.1}" y1="46" x2="{x:.1}" y2="{:.1}"/>"#,
            height - 10.0
        );
    }

    let t0 = msgs
        .first()
        .map(|&i| r.messages[i].ts_ns)
        .unwrap_or(r.summary.start_ns);
    for (row, item) in rows.iter().enumerate() {
        let y = top + row_h * row as f64 + 14.0;
        let mi = match item {
            Row::Msg(mi) => *mi,
            Row::RtpHeader => {
                let _ = write!(
                    s,
                    r#"<text class="t" x="8" y="{:.1}" font-size="11">RTP</text>"#,
                    y + 4.0
                );
                continue;
            }
            Row::Stream(si) => {
                stream_row(&mut s, r, *si, y, row_h, width, t0, &x_of);
                continue;
            }
        };
        let m = &r.messages[mi];
        let x1 = x_of(&m.src);
        let x2 = x_of(&m.dst);
        let cls = color_for(m.method.as_deref(), m.status);
        let retx = if m.retransmission { " retx" } else { "" };
        let tooltip = format!(
            "#{} frame {} {} → {}\n{}",
            m.index, m.frame, m.src, m.dst, m.summary
        );
        let _ = write!(
            s,
            r#"<g class="msg{retx}" data-msg="{mi}"><title>{}</title>"#,
            esc(&tooltip)
        );
        let _ = write!(
            s,
            r#"<rect class="hit" x="0" y="{:.1}" width="{width:.0}" height="{row_h:.0}"/>"#,
            y - 18.0
        );
        let rel = (m.ts_ns - t0) as f64 / 1e9;
        let _ = write!(
            s,
            r#"<text class="t" x="8" y="{:.1}" font-size="11">+{rel:.3}s</text>"#,
            y + 4.0
        );
        if let Some((sv, title)) = sev.get(&mi) {
            let c = match sv {
                Severity::Error => "sev-error",
                Severity::Warning => "sev-warning",
                Severity::Info => "sev-info",
            };
            let _ = write!(
                s,
                r#"<circle class="{c}" cx="84" cy="{:.1}" r="5"><title>{}</title></circle>"#,
                y,
                esc(title)
            );
        }
        let label = format!(
            "{}{}",
            truncate(&m.label, 30),
            if m.retransmission { " ↻" } else { "" }
        );
        if (x1 - x2).abs() < 1.0 {
            // Self message: small loop.
            let _ = write!(
                s,
                r#"<g class="{cls}"><path d="M{x1:.1},{:.1} h28 v10 h-26" fill="none" stroke-width="1.6" marker-end="url(#ah)"/><text class="lbl {cls}" x="{:.1}" y="{:.1}">{}</text></g>"#,
                y - 4.0,
                x1 + 34.0,
                y + 2.0,
                esc(&label)
            );
        } else {
            let mid = (x1 + x2) / 2.0;
            let _ = write!(
                s,
                r#"<g class="{cls}"><line x1="{x1:.1}" y1="{y:.1}" x2="{:.1}" y2="{y:.1}" stroke-width="1.6" marker-end="url(#ah)"/><text class="lbl {cls}" x="{mid:.1}" y="{:.1}" text-anchor="middle">{}</text></g>"#,
                if x2 > x1 { x2 - 2.0 } else { x2 + 2.0 },
                y - 5.0,
                esc(&label)
            );
        }
        s.push_str("</g>");
    }

    s.push_str("</svg>");
    s
}

/// One RTP stream as a dashed arrow with its quality summary.
#[allow(clippy::too_many_arguments)]
fn stream_row(
    s: &mut String,
    r: &Report,
    si: usize,
    y: f64,
    row_h: f64,
    width: f64,
    t0: i64,
    x_of: &dyn Fn(&str) -> f64,
) {
    let st = &r.streams[si];
    let x1 = x_of(&st.src);
    let x2 = x_of(&st.dst);
    let mos = st.mos.map(|m| format!(" MOS {m:.1}")).unwrap_or_default();
    let label = format!(
        "{} {} pkts loss {:.1}% jit {:.0}ms{mos}",
        st.codec, st.packets, st.loss_pct, st.jitter_ms
    );
    let rel = (st.start_ns - t0) as f64 / 1e9;
    let _ = write!(
        s,
        r#"<g class="stream" data-stream="{si}"><title>RTP {} → {} SSRC {}</title><rect class="hit" x="0" y="{:.1}" width="{width:.0}" height="{row_h:.0}"/><text class="t" x="8" y="{:.1}" font-size="11">+{rel:.3}s</text>"#,
        esc(&st.src),
        esc(&st.dst),
        esc(&st.ssrc),
        y - 18.0,
        y + 4.0
    );
    if (x1 - x2).abs() < 1.0 {
        let _ = write!(
            s,
            r#"<g class="st-rtp"><text class="lbl st-rtp" x="{:.1}" y="{y:.1}">⟲ {}</text></g>"#,
            x1 + 6.0,
            esc(&label)
        );
    } else {
        let mid = (x1 + x2) / 2.0;
        let _ = write!(
            s,
            r#"<g class="st-rtp"><line x1="{x1:.1}" y1="{y:.1}" x2="{:.1}" y2="{y:.1}" stroke-width="3" stroke-dasharray="10 5" marker-end="url(#ahr)"/><text class="lbl st-rtp" x="{mid:.1}" y="{:.1}" text-anchor="middle" font-size="11">{}</text></g>"#,
            if x2 > x1 { x2 - 2.0 } else { x2 + 2.0 },
            y - 5.0,
            esc(&label)
        );
    }
    s.push_str("</g>");
}

fn ua_for(r: &Report, msgs: &[usize], col: &str, by_ip: bool) -> Option<String> {
    for &i in msgs {
        let m = &r.messages[i];
        let src = if by_ip {
            host_of(&m.src)
        } else {
            m.src.clone()
        };
        if src == col {
            if let Some(ua) = m
                .sip
                .header("User-Agent")
                .or_else(|| m.sip.header("Server"))
            {
                return Some(ua.to_string());
            }
        }
    }
    None
}

/// Plain-text ladder for terminals and AI prompts.
pub fn render_text(r: &Report, call: Option<usize>) -> String {
    let msgs = ladder_messages(r, call);
    let t0 = msgs.first().map(|&i| r.messages[i].ts_ns).unwrap_or(0);
    let mut out = String::new();
    for &i in &msgs {
        let m = &r.messages[i];
        let _ = writeln!(
            out,
            "#{:<4} +{:>8.3}s  {:>22} -> {:<22} {}{}",
            m.index,
            (m.ts_ns - t0) as f64 / 1e9,
            m.src,
            m.dst,
            m.label,
            if m.retransmission {
                "  [retransmission]"
            } else {
                ""
            }
        );
    }
    if let Some(c) = call {
        for &si in &r.calls[c].streams {
            let s = &r.streams[si];
            let _ = writeln!(
                out,
                "RTP   {:>22} -> {:<22} {} pkts={} loss={:.2}% jitter={:.1}ms max_gap={:.0}ms mos={}",
                s.src,
                s.dst,
                s.codec,
                s.packets,
                s.loss_pct,
                s.jitter_ms,
                s.max_gap_ms,
                s.mos.map(|m| format!("{m:.2}")).unwrap_or_else(|| "n/a".into())
            );
        }
    }
    out
}
