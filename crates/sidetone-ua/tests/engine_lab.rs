//! Phone engine against the Asterisk lab (lab/run-asterisk.sh).
//! Run with: cargo test -p sidetone-ua --test engine_lab -- --ignored --nocapture --test-threads=1

use sidetone_ua::engine::{AccountCfg, CallRequest, Cmd, Engine, PhoneSettings};
use sidetone_ua::{DtmfMode, Profile, SrtpMode};
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
        let st = e.state();
        st.accounts.len() == 2 && st.accounts.iter().all(|a| a.state == "registered")
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
    // A direct client (no domain, no registration) dials a SIP URI anonymously.
    let mut d = AccountCfg {
        id: "direct".into(),
        register: false,
        ..Default::default()
    };
    d.profile.account.user = String::new();
    d.profile.account.domain = String::new();
    let mut all = vec![
        acc("a", "2001", "secret2001", DtmfMode::Rfc4733),
        acc("b", "3001", "secret3001", DtmfMode::Info),
    ];
    all.push(d);
    e.cmd(Cmd::SetAccounts(all));
    std::thread::sleep(Duration::from_millis(500));
    let server = std::env::var("SIDETONE_LAB_SERVER").unwrap_or_else(|_| "127.0.0.1:5070".into());
    let l7 = e.call(CallRequest {
        account: Some("direct".into()),
        target: format!("sip:600@{server}"),
        ..Default::default()
    });
    wait_for(&e, "anonymous call to a SIP URI connects", 10, |e| {
        line_state(e, l7) == "connected"
    });
    e.cmd(Cmd::HangupAll);
    wait_for(&e, "idle again", 10, |e| {
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

fn transport(mut a: AccountCfg, kind: &str, port: u16) -> AccountCfg {
    a.profile.behavior.transport = kind.into();
    a.profile.behavior.tls_verify = false;
    let host = a
        .profile
        .account
        .domain
        .split(':')
        .next()
        .unwrap_or("127.0.0.1")
        .to_string();
    a.profile.account.domain = format!("{host}:{port}");
    a
}

#[test]
#[ignore]
fn transports_srtp_blf_conference() {
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        auto_hold: false,
        ..Default::default()
    };
    let mut a = acc("a", "2001", "secret2001", DtmfMode::Rfc4733);
    a.blf = vec!["3001".into()];
    let b = transport(
        acc("b", "3001", "secret3001", DtmfMode::Rfc4733),
        "tcp",
        5070,
    );
    let mut s = transport(
        acc("s", "5001", "secret5001", DtmfMode::Rfc4733),
        "tls",
        5071,
    );
    s.profile.behavior.srtp = SrtpMode::Mandatory;
    let e = Engine::start(settings, vec![a, b, s], None);
    wait_for(&e, "UDP, TCP and TLS accounts registered", 15, |e| {
        let st = e.state();
        st.accounts.len() == 3 && st.accounts.iter().all(|a| a.state == "registered")
    });
    let st = e.state();
    let tr = |id: &str| {
        st.accounts
            .iter()
            .find(|a| a.id == id)
            .unwrap()
            .transport
            .clone()
    };
    assert_eq!(tr("b").to_lowercase(), "tcp");
    assert_eq!(tr("s").to_lowercase(), "tls");

    // SRTP over TLS to the echo test.
    let ls = e.call(CallRequest {
        account: Some("s".into()),
        target: "600".into(),
        ..Default::default()
    });
    wait_for(&e, "SRTP echo connected and audio decrypts", 10, |e| {
        e.state()
            .calls
            .iter()
            .any(|c| c.line == ls && c.state == "connected" && c.srtp && c.rtp_received > 50)
    });
    let c = e.state().calls.into_iter().find(|c| c.line == ls).unwrap();
    assert_eq!(c.srtp_failed, 0, "no SRTP authentication failures");
    e.cmd(Cmd::Hangup(ls));

    // BLF on 3001 follows idle, ringing and busy while a calls b (over TCP).
    let blf = |e: &Engine| {
        e.state()
            .accounts
            .iter()
            .find(|a| a.id == "a")
            .and_then(|a| a.blf.first().map(|b| b.state.clone()))
            .unwrap_or_default()
    };
    wait_for(&e, "BLF idle", 10, |e| blf(e) == "idle");

    // Presence (Event: presence, PIDF) next to the lamp, driven from the PBX.
    let pres = |e: &Engine| {
        e.state()
            .accounts
            .iter()
            .find(|a| a.id == "a")
            .and_then(|a| a.blf.first().map(|b| (b.presence.clone(), b.note.clone())))
            .unwrap_or_default()
    };
    wait_for(&e, "presence of 3001 known", 10, |e| pres(e).0.is_some());
    println!("presence of 3001: {:?}", pres(&e));
    // Own presence: Asterisk does not take PUBLISH from phones, so expect a clean refusal.
    e.cmd(Cmd::SetPresence(
        "a".into(),
        "away".into(),
        "testing".into(),
    ));
    wait_for(&e, "PUBLISH answered", 10, |e| {
        e.state()
            .accounts
            .iter()
            .any(|a| a.id == "a" && a.presence_error.is_some())
            || e.events_since(0)
                .iter()
                .any(|v| v.text.starts_with("presence published"))
    });
    println!(
        "PUBLISH: {:?}",
        e.state()
            .accounts
            .iter()
            .find(|a| a.id == "a")
            .unwrap()
            .presence_error
    );
    let l1 = e.call(CallRequest {
        account: Some("a".into()),
        target: "700".into(),
        ..Default::default()
    });
    wait_for(&e, "b rings over TCP", 10, |e| {
        incoming_line(e, "b").is_some()
    });
    wait_for(&e, "BLF ringing", 5, |e| blf(e) == "ringing");
    let ib = incoming_line(&e, "b").unwrap();
    e.cmd(Cmd::Answer(ib));
    wait_for(&e, "a-b connected", 10, |e| {
        line_state(e, l1) == "connected"
    });
    wait_for(&e, "BLF busy", 5, |e| blf(e) == "busy");
    wait_for(&e, "presence follows the call", 5, |e| {
        pres(e).0.as_deref() == Some("busy")
    });
    println!("presence of 3001 in a call: {:?}", pres(&e));

    // Three-way conference: a joins b and the echo test.
    let l2 = e.call(CallRequest {
        account: Some("a".into()),
        target: "600".into(),
        ..Default::default()
    });
    wait_for(&e, "second line connected", 10, |e| {
        line_state(e, l2) == "connected"
    });
    e.cmd(Cmd::Conference(l1, l2, true));
    wait_for(&e, "conference joined", 5, |e| {
        let calls = e.state().calls;
        let conf = |l| {
            calls
                .iter()
                .find(|c| c.line == l)
                .and_then(|c| c.conference)
        };
        conf(l1) == Some(l2) && conf(l2) == Some(l1)
    });
    std::thread::sleep(Duration::from_millis(1000));
    e.cmd(Cmd::Conference(l1, l2, false));
    wait_for(&e, "conference split", 5, |e| {
        e.state().calls.iter().all(|c| c.conference.is_none())
    });
    e.cmd(Cmd::HangupAll);
    wait_for(&e, "BLF idle again", 10, |e| blf(e) == "idle");
    wait_for(&e, "presence available again", 10, |e| {
        pres(e).0.as_deref() == Some("available")
    });

    // The capture keeps SIP over TCP as TCP and SIP over TLS as decrypted PDUs.
    let pcap = e.capture();
    std::fs::write(std::env::temp_dir().join("engine_lab_tls.pcapng"), &pcap).unwrap();
    let r = sidetone_core::analysis::analyze_bytes(&pcap).expect("capture parses");
    use sidetone_core::net::Transport;
    let count = |t: Transport| r.messages.iter().filter(|m| m.transport == t).count();
    println!(
        "capture: {} UDP, {} TCP, {} TLS messages",
        count(Transport::Udp),
        count(Transport::Tcp),
        count(Transport::Tls)
    );
    assert!(count(Transport::Tcp) > 5, "SIP over TCP in the capture");
    assert!(count(Transport::Tls) > 5, "SIP over TLS in the capture");
    assert!(
        r.messages
            .iter()
            .any(|m| m.transport == Transport::Tls && m.method.as_deref() == Some("INVITE")),
        "the INVITE sent over TLS is readable"
    );
    let trace = e.trace_since(0, 100000);
    assert!(trace.iter().any(|t| t.transport == "TLS"));
    assert!(trace.iter().any(|t| t.transport == "TCP"));
}

#[test]
#[ignore]
fn opus_echo() {
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        auto_hold: false,
        ..Default::default()
    };
    let mut a = acc("a", "2001", "secret2001", DtmfMode::Rfc4733);
    a.profile.behavior.codecs = vec!["opus".into(), "PCMU".into()];
    let b = acc("b", "3001", "secret3001", DtmfMode::Rfc4733);
    let e = Engine::start(settings, vec![a, b], None);
    wait_for(&e, "registered", 10, |e| {
        let st = e.state();
        st.accounts.len() == 2 && st.accounts.iter().all(|a| a.state == "registered")
    });
    let l = e.call(CallRequest {
        account: Some("a".into()),
        target: "600".into(),
        ..Default::default()
    });
    wait_for(&e, "Opus echo connected", 10, |e| {
        line_state(e, l) == "connected"
    });
    let c = e.state().calls.into_iter().find(|c| c.line == l).unwrap();
    assert_eq!(c.codec.as_deref(), Some("opus"));
    wait_for(&e, "Opus audio decodes with level", 5, |e| {
        e.state()
            .calls
            .iter()
            .any(|c| c.line == l && c.rtp_received > 50 && c.rx_level > 2000)
    });
    e.cmd(Cmd::Dtmf(l, "1".into()));
    std::thread::sleep(Duration::from_millis(500));
    e.cmd(Cmd::HangupAll);
    wait_for(&e, "ended", 5, |e| line_state(e, l) != "connected");

    // Opus to a G.711-only phone: Asterisk transcodes both ways.
    let l2 = e.call(CallRequest {
        account: Some("a".into()),
        target: "700".into(),
        ..Default::default()
    });
    wait_for(&e, "3001 rings", 10, |e| incoming_line(e, "b").is_some());
    let ib = incoming_line(&e, "b").unwrap();
    e.cmd(Cmd::Answer(ib));
    wait_for(&e, "audio both ways through the transcoder", 8, |e| {
        let calls = e.state().calls;
        let lvl = |l| {
            calls
                .iter()
                .find(|c| c.line == l)
                .map(|c| c.rx_level)
                .unwrap_or(0)
        };
        lvl(l2) > 2000 && lvl(ib) > 2000
    });
    let calls = e.state().calls;
    let codec = |l| {
        calls
            .iter()
            .find(|c| c.line == l)
            .and_then(|c| c.codec.clone())
    };
    assert_eq!(codec(l2).as_deref(), Some("opus"));
    assert_eq!(codec(ib).as_deref(), Some("PCMU"));
    e.cmd(Cmd::HangupAll);
}
