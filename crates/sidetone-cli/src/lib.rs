//! Library side of the CLI: shared by the `sidetone` binary and the desktop app.

pub mod aihttp;
pub mod mcp;
pub mod phone;
pub mod provision;
pub mod serve;
pub mod testrun;

use sidetone_core::ladder::render_text;
use sidetone_core::{Report, Severity};

fn sev_tag(s: Severity) -> &'static str {
    match s {
        Severity::Error => "ERROR",
        Severity::Warning => "WARN ",
        Severity::Info => "info ",
    }
}

pub fn report_text(r: &Report, call: Option<usize>, ladder: bool) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let s = &r.summary;
    let _ =
        writeln!(o,
        "{} packets, {} SIP messages, {} calls, {} RTP streams, {:.1} s  |  {} errors, {} warnings",
        s.packets, s.sip_messages, s.calls, s.rtp_streams, s.duration_s, s.errors, s.warnings
    );
    let _ = writeln!(o);
    for c in &r.calls {
        if call.is_some() && call != Some(c.index) {
            continue;
        }
        let fin = c
            .final_status
            .map(|f| format!("{f} {}", c.final_reason.clone().unwrap_or_default()))
            .unwrap_or_else(|| "-".into());
        let _ = writeln!(
            o,
            "[{}] {:<9} {} -> {}  {:?}  final={}  pdd={}  talk={}  streams={}  E{} W{}",
            c.index,
            c.kind,
            c.from,
            c.to,
            c.state,
            fin,
            c.pdd_ms
                .map(|v| format!("{v:.0}ms"))
                .unwrap_or_else(|| "-".into()),
            c.talk_s
                .map(|v| format!("{v:.1}s"))
                .unwrap_or_else(|| "-".into()),
            c.streams.len(),
            c.errors,
            c.warnings
        );
        if ladder {
            let _ = writeln!(o, "{}", render_text(r, Some(c.index)));
        }
    }
    if !r.streams.is_empty() {
        let _ = writeln!(o, "\nRTP streams:");
        for st in &r.streams {
            if call.is_some() && st.call != call {
                continue;
            }
            let _ = writeln!(o,
                "  #{} {} -> {} {} pkts={} loss={:.2}% jitter={:.1}ms max_gap={:.0}ms mos={} call={}",
                st.id,
                st.src,
                st.dst,
                st.codec,
                st.packets,
                st.loss_pct,
                st.jitter_ms,
                st.max_gap_ms,
                st.mos.map(|m| format!("{m:.2}")).unwrap_or_else(|| "n/a".into()),
                st.call.map(|c| c.to_string()).unwrap_or_else(|| "-".into())
            );
        }
    }
    let _ = writeln!(o, "\nFindings:");
    for f in &r.findings {
        if call.is_some() && f.call.is_some() && f.call != call {
            continue;
        }
        let c = f.call.map(|c| format!("[{c}] ")).unwrap_or_default();
        let _ = writeln!(o, "  {} {c}{}", sev_tag(f.severity), f.title);
        let _ = writeln!(o, "        {}", f.detail);
    }
    o
}
