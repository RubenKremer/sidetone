//! Phone engine against the Asterisk lab (lab/run-asterisk.sh).
//! Run with: cargo test -p sidetone-ua --test engine_lab -- --ignored --nocapture

use sidetone_ua::engine::{AccountCfg, CallRequest, Cmd, Engine, PhoneSettings};
use sidetone_ua::{DtmfMode, Profile};
use std::time::{Duration, Instant};

fn acc(id: &str, user: &str, pass: &str, dtmf: DtmfMode) -> AccountCfg {
    let mut p = Profile::default();
    p.account.user = user.into();
    p.account.password = Some(pass.into());
    p.account.domain =
        std::env::var("SIDETONE_LAB_SERVER").unwrap_or_else(|_| "127.0.0.1:5070".into());
    p.account.expires = 60;
    p.behavior.dtmf_mode = dtmf;
    AccountCfg {
        id: id.into(),
        label: user.into(),
        profile: p,
        ..Default::default()
    }
}

fn wait_for(e: &Engine, what: &str, secs: u64, f: impl Fn(&Engine) -> bool) {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f(e) {
            println!("ok: {what} ({} ms)", t.elapsed().as_millis());
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    for ev in e.events_since(0) {
        println!(
            "  event {:>5} {:<9} line={:?} {}",
            ev.seq, ev.kind, ev.line, ev.text
        );
    }
    panic!("timed out waiting for: {what}\nstate: {:#?}", e.state());
}

fn line_state(e: &Engine, line: u32) -> String {
    e.state()
        .calls
        .iter()
        .find(|c| c.line == line)
        .map(|c| c.state.clone())
        .unwrap_or_else(|| "gone".into())
}

fn incoming_line(e: &Engine, account: &str) -> Option<u32> {
    e.state()
        .calls
        .iter()
        .find(|c| c.account == account && c.direction == "in" && c.state == "incoming")
        .map(|c| c.line)
}

#[test]
#[ignore]
fn engine_against_asterisk() {
    // Both accounts live in one engine here, so do not auto-hold across them.
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        auto_hold: false,
        ..Default::default()
    };
    let e = Engine::start(
        settings,
        vec![
            acc("a", "2001", "secret2001", DtmfMode::Rfc4733),
            acc("b", "3001", "secret3001", DtmfMode::Info),
        ],
        None,
    );
    wait_for(&e, "both accounts registered", 10, |e| {
        e.state().accounts.iter().all(|a| a.state == "registered")
    });

    // Echo test with hold, resume, DTMF and mute.
    let l1 = e.call(CallRequest {
        account: Some("a".into()),
        target: "600".into(),
        ..Default::default()
    });
    wait_for(&e, "600 connected", 10, |e| {
        line_state(e, l1) == "connected"
    });
    wait_for(&e, "echo audio comes back", 5, |e| {
        e.state()
            .calls
            .iter()
            .any(|c| c.line == l1 && c.rtp_received > 50)
    });
    e.cmd(Cmd::Dtmf(l1, "123".into()));
    e.cmd(Cmd::Hold(l1, true));
    wait_for(&e, "hold confirmed", 5, |e| {
        e.events_since(0)
            .iter()
            .any(|v| v.line == Some(l1) && v.text == "hold confirmed")
    });
    e.cmd(Cmd::Hold(l1, false));
    wait_for(&e, "resume confirmed", 5, |e| {
        e.events_since(0)
            .iter()
            .any(|v| v.line == Some(l1) && v.text == "resume confirmed")
    });
    e.cmd(Cmd::Hangup(l1));
    wait_for(&e, "600 ended", 5, |e| {
        e.history()
            .iter()
            .any(|h| h.answered && h.remote.starts_with("600"))
    });

    // Busy and not found.
    let l2 = e.call(CallRequest {
        account: Some("a".into()),
        target: "602".into(),
        ..Default::default()
    });
    wait_for(&e, "602 busy", 10, |e| {
        e.state()
            .calls
            .iter()
            .any(|c| c.line == l2 && c.final_code == Some(486))
    });

    // a calls 700, which rings b; b answers; then a blind-transfers to 600.
    let l3 = e.call(CallRequest {
        account: Some("a".into()),
        target: "700".into(),
        ..Default::default()
    });
    wait_for(&e, "b rings", 10, |e| incoming_line(e, "b").is_some());
    let ib = incoming_line(&e, "b").unwrap();
    e.cmd(Cmd::Answer(ib));
    wait_for(&e, "a-b connected", 10, |e| {
        line_state(e, l3) == "connected" && line_state(e, ib) == "connected"
    });
    wait_for(&e, "audio a<-b", 5, |e| {
        e.state()
            .calls
            .iter()
            .any(|c| c.line == l3 && c.rtp_received > 20)
    });
    e.cmd(Cmd::Dtmf(ib, "9".into()));
    e.cmd(Cmd::BlindTransfer(l3, "600".into()));
    wait_for(&e, "blind transfer completed and a released", 10, |e| {
        line_state(e, l3) == "ended" || line_state(e, l3) == "gone"
    });
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(line_state(&e, ib), "connected", "b should now talk to 600");
    e.cmd(Cmd::Hangup(ib));
    wait_for(&e, "b released", 5, |e| line_state(e, ib) != "connected");

    // Attended: a calls 700 (b answers), a calls 600 (first line goes on hold), then joins them.
    let la = e.call(CallRequest {
        account: Some("a".into()),
        target: "700".into(),
        ..Default::default()
    });
    wait_for(&e, "b rings again", 10, |e| incoming_line(e, "b").is_some());
    let ib2 = incoming_line(&e, "b").unwrap();
    e.cmd(Cmd::Answer(ib2));
    wait_for(&e, "a-b connected again", 10, |e| {
        line_state(e, la) == "connected"
    });
    e.cmd(Cmd::Hold(la, true));
    let lb = e.call(CallRequest {
        account: Some("a".into()),
        target: "600".into(),
        ..Default::default()
    });
    wait_for(&e, "consultation call up and first line held", 10, |e| {
        line_state(e, lb) == "connected" && e.state().calls.iter().any(|c| c.line == la && c.held)
    });
    e.cmd(Cmd::AttendedTransfer(la, lb));
    wait_for(&e, "attended transfer releases both lines of a", 15, |e| {
        let s = |l| line_state(e, l);
        (s(la) == "ended" || s(la) == "gone") && (s(lb) == "ended" || s(lb) == "gone")
    });
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(line_state(&e, ib2), "connected", "b should now talk to 600");
    e.cmd(Cmd::HangupAll);

    // OPTIONS ping.
    let r = e.options(Some("a".into()), String::new());
    println!("OPTIONS: {r:?}");
    assert!(r.is_some());

    // DND rejects, auto answer answers.
    e.cmd(Cmd::SetSettings(PhoneSettings {
        dnd: true,
        audio_source: "tone".into(),
        auto_hold: false,
        ..Default::default()
    }));
    let l5 = e.call(CallRequest {
        account: Some("a".into()),
        target: "700".into(),
        ..Default::default()
    });
    wait_for(&e, "DND makes the call fail", 10, |e| {
        line_state(e, l5) == "ended"
    });
    e.cmd(Cmd::SetSettings(PhoneSettings {
        auto_answer: true,
        auto_answer_delay_ms: 200,
        audio_source: "tone".into(),
        auto_hold: false,
        ..Default::default()
    }));
    let l6 = e.call(CallRequest {
        account: Some("a".into()),
        target: "700".into(),
        ..Default::default()
    });
    wait_for(&e, "auto answer connects", 10, |e| {
        line_state(e, l6) == "connected"
    });
    e.cmd(Cmd::HangupAll);
    wait_for(&e, "all idle", 10, |e| {
        e.state().calls.iter().all(|c| c.state == "ended")
    });
    let pcap = e.capture();
    assert!(pcap.len() > 10_000, "capture has data");
    let trace = e.trace_since(0, 100000);
    println!(
        "trace items: {}, capture bytes: {}",
        trace.len(),
        pcap.len()
    );
    std::fs::write(std::env::temp_dir().join("engine_lab.pcapng"), pcap).unwrap();
    for ev in e.events_since(0) {
        println!(
            "  {:<9} line={:?} acc={:?} {}",
            ev.kind, ev.line, ev.account, ev.text
        );
    }
}
