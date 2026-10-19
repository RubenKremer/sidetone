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
    // The decrypted export carries the tone in clear RTP; the wire one does not.
    assert!(e.state().capture_srtp);
    let share = |bytes: &[u8]| {
        let r = sidetone_core::analyze_bytes(bytes).unwrap();
        r.streams
            .iter()
            .filter(|s| s.codec.starts_with("PCM"))
            .filter_map(|s| sidetone_core::audio::stream_audio(bytes, s.id).ok())
            .map(|a| pcm_tone_share(&a.pcm, a.rate as f64, 440.0))
            .fold(0.0, f64::max)
    };
    let (dec, wire) = (share(&e.capture_decrypted()), share(&e.capture()));
    println!("440 Hz share: decrypted {dec:.2}, on the wire {wire:.2}");
    assert!(dec > 0.5 && wire < 0.3, "decrypted {dec}, wire {wire}");
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

    // Wideband: a 6 kHz tone survives the Opus echo and vanishes through G.711.
    let tone = |hz: f32| PhoneSettings {
        audio_source: "tone".into(),
        tone_hz: hz,
        auto_hold: false,
        ..Default::default()
    };
    e.cmd(Cmd::SetSettings(tone(6000.0)));
    let level_of = |e: &Engine, l: u32| {
        e.state()
            .calls
            .iter()
            .find(|c| c.line == l)
            .map(|c| c.rx_level)
            .unwrap_or(0)
    };
    let w = e.call(CallRequest {
        account: Some("a".into()),
        target: "600".into(),
        ..Default::default()
    });
    wait_for(&e, "6 kHz over Opus comes back", 8, |e| {
        level_of(e, w) > 3000
    });
    e.cmd(Cmd::HangupAll);
    wait_for(&e, "ended", 5, |e| line_state(e, w) != "connected");
    let n = e.call(CallRequest {
        account: Some("a".into()),
        target: "600".into(),
        overrides: Some(serde_json::json!({"codecs": ["PCMU"]})),
        ..Default::default()
    });
    wait_for(&e, "G.711 echo connected", 8, |e| {
        line_state(e, n) == "connected"
    });
    std::thread::sleep(Duration::from_millis(2000));
    let narrow = level_of(&e, n);
    println!("6 kHz tone: G.711 echo level {narrow}");
    assert!(narrow < 1500, "G.711 cannot carry 6 kHz ({narrow})");
    e.cmd(Cmd::HangupAll);
    wait_for(&e, "ended", 5, |e| line_state(e, n) != "connected");
    e.cmd(Cmd::SetSettings(tone(440.0)));

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

#[test]
#[ignore]
fn dtls_srtp() {
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        auto_hold: false,
        ..Default::default()
    };
    let mut d = acc("d", "6001", "secret6001", DtmfMode::Rfc4733);
    d.profile.behavior.srtp = SrtpMode::Mandatory;
    d.profile.behavior.srtp_keys = "dtls".into();
    let a = acc("a", "2001", "secret2001", DtmfMode::Rfc4733);
    let e = Engine::start(settings, vec![d, a], None);
    wait_for(&e, "registered", 10, |e| {
        let st = e.state();
        st.accounts.len() == 2 && st.accounts.iter().all(|a| a.state == "registered")
    });
    let call = |e: &Engine, l: u32| e.state().calls.into_iter().find(|c| c.line == l);
    // Outgoing: we offer actpass, Asterisk answers and picks its role.
    let l = e.call(CallRequest {
        account: Some("d".into()),
        target: "600".into(),
        ..Default::default()
    });
    wait_for(&e, "DTLS-SRTP echo: handshake, keys and audio", 10, |e| {
        call(e, l)
            .map(|c| {
                c.state == "connected"
                    && c.security
                        .as_deref()
                        .unwrap_or("")
                        .contains("fingerprint verified")
                    && c.rtp_received > 50
                    && c.rx_level > 2000
            })
            .unwrap_or(false)
    });
    let c = call(&e, l).unwrap();
    println!("outgoing: {:?}", c.security);
    assert_eq!(c.srtp_failed, 0);
    e.cmd(Cmd::Hangup(l));
    wait_for(&e, "ended", 5, |e| line_state(e, l) != "connected");

    // Incoming: Asterisk offers DTLS to 6001; we answer and take the role left to us.
    let lo = e.call(CallRequest {
        account: Some("a".into()),
        target: "900".into(),
        ..Default::default()
    });
    wait_for(&e, "6001 rings", 10, |e| incoming_line(e, "d").is_some());
    let li = incoming_line(&e, "d").unwrap();
    e.cmd(Cmd::Answer(li));
    wait_for(
        &e,
        "incoming DTLS-SRTP call carries audio both ways",
        10,
        |e| {
            let ok = |l| {
                call(e, l)
                    .map(|c| c.state == "connected" && c.rx_level > 2000)
                    .unwrap_or(false)
            };
            ok(lo)
                && ok(li)
                && call(e, li)
                    .and_then(|c| c.security)
                    .unwrap_or_default()
                    .contains("fingerprint verified")
        },
    );
    println!("incoming: {:?}", call(&e, li).unwrap().security);
    e.cmd(Cmd::HangupAll);
}

/// Share of the right channel (received audio) of a stereo recording that is
/// a tone at `hz`, by the Goertzel algorithm (1.0 = pure tone).
fn pcm_tone_share(pcm: &[i16], rate: f64, hz: f64) -> f64 {
    let x: Vec<f64> = pcm.iter().map(|v| *v as f64).collect();
    if x.is_empty() {
        return 0.0;
    }
    let w = 2.0 * std::f64::consts::PI * hz / rate;
    let (mut s1, mut s2) = (0.0f64, 0.0f64);
    for v in &x {
        let s0 = v + 2.0 * w.cos() * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    let p = s1 * s1 + s2 * s2 - 2.0 * w.cos() * s1 * s2;
    let e: f64 = x.iter().map(|v| v * v).sum();
    (2.0 * p / (e * x.len() as f64).max(1.0)).min(1.0)
}

fn tone_share(wav: &[u8], hz: f64) -> f64 {
    let rate = u32::from_le_bytes([wav[24], wav[25], wav[26], wav[27]]) as f64;
    let data = &wav[44..];
    let right: Vec<f64> = data
        .chunks_exact(4)
        .map(|f| i16::from_le_bytes([f[2], f[3]]) as f64)
        .collect();
    // Skip the start (ringing, jitter buffer filling) and the end.
    let n = right.len();
    let x = &right[n / 4..n * 3 / 4];
    if x.is_empty() {
        return 0.0;
    }
    let total: f64 = x.iter().map(|v| v * v).sum::<f64>();
    let w = 2.0 * std::f64::consts::PI * hz / rate;
    let (mut s1, mut s2) = (0.0, 0.0);
    for v in x {
        let s0 = v + 2.0 * w.cos() * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    let power = s1 * s1 + s2 * s2 - 2.0 * w.cos() * s1 * s2;
    // A pure sine of amplitude A over N samples: Goertzel power N²A²/4, energy N·A²/2.
    if total < 1.0 {
        return 0.0;
    }
    (2.0 * power / (x.len() as f64 * total)).min(1.0)
}

#[test]
#[ignore]
fn codecs_interop() {
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        tone_hz: 1000.0,
        auto_hold: false,
        auto_answer: true,
        auto_answer_delay_ms: 0,
        record_calls: true,
        ..Default::default()
    };
    let a = acc("a", "2001", "secret2001", DtmfMode::Rfc4733);
    let b = acc("b", "3001", "secret3001", DtmfMode::Rfc4733);
    let e = Engine::start(settings, vec![a, b], None);
    wait_for(&e, "registered", 10, |e| {
        let st = e.state();
        st.accounts.len() == 2 && st.accounts.iter().all(|a| a.state == "registered")
    });
    // Through 700 Asterisk transcodes between the codec and G.711 (3001), so both
    // our encoder and our decoder meet an independent implementation. G.729 and
    // iLBC have no transcoder in the lab, so they go through the echo (600).
    let cases: &[(&str, &str, &str)] = &[
        ("PCMA", "700", "PCMA"),
        ("G722", "700", "G722"),
        ("opus", "700", "opus"),
        ("GSM", "700", "GSM"),
        ("G726-32", "700", "G726-32"),
        ("AAL2-G726-32", "700", "AAL2-G726-32"),
        ("speex/8000", "700", "speex"),
        ("speex/16000", "700", "speex"),
        ("L16/8000", "700", "L16"),
        ("L16/16000", "700", "L16"),
        ("G729", "600", "G729"),
        ("iLBC", "600", "iLBC"),
    ];
    let mut bad = Vec::new();
    let only = std::env::var("SIDETONE_CODECS").unwrap_or_default();
    // A codec gets up to three tries: Asterisk may start its encoder before
    // the first RTP packet goes out, and Speex on a pure tone then diverges.
    let runs: Vec<&(&str, &str, &str)> = cases.iter().flat_map(|c| [c, c, c]).collect();
    let mut passed: Vec<&str> = Vec::new();
    for (codec, target, expect) in runs {
        if !only.is_empty() && !only.split(',').any(|c| c == *codec) {
            continue;
        }
        if passed.contains(codec) {
            continue;
        }
        let before: Vec<u32> = e.state().calls.iter().map(|c| c.line).collect();
        let l = e.call(CallRequest {
            account: Some("a".into()),
            target: (*target).into(),
            overrides: Some(serde_json::json!({ "codecs": [codec] })),
            ..Default::default()
        });
        wait_for(&e, &format!("{codec} connected"), 10, |e| {
            line_state(e, l) == "connected"
        });
        std::thread::sleep(Duration::from_millis(3500));
        let st = e.state();
        let me = st.calls.iter().find(|c| c.line == l).unwrap();
        let used = me.codec.clone().unwrap_or_default();
        println!(
            "  rtp sent {} received {} rx level {}",
            me.rtp_sent, me.rtp_received, me.rx_level
        );
        let other = st
            .calls
            .iter()
            .find(|c| c.line != l && !before.contains(&c.line) && c.direction == "in")
            .map(|c| c.line);
        e.cmd(Cmd::HangupAll);
        wait_for(&e, "ended", 8, |e| {
            e.state().calls.iter().all(|c| c.state == "ended")
        });
        std::thread::sleep(Duration::from_millis(500));
        let mine = e
            .recording(l)
            .map(|w| tone_share(&w, 1000.0))
            .unwrap_or(0.0);
        let theirs = other
            .and_then(|o| e.recording(o))
            .map(|w| tone_share(&w, 1000.0));
        println!(
            "codec {codec:>13}: negotiated {used:<13} decoded tone {mine:.2}{}",
            theirs
                .map(|t| format!(", G.711 side hears our encoder {t:.2}"))
                .unwrap_or_default()
        );
        if !used.eq_ignore_ascii_case(expect) || mine < 0.5 || theirs.is_some_and(|t| t < 0.5) {
            bad.push(format!("{codec}: {used} {mine:.2} {theirs:?}"));
        } else {
            passed.push(codec);
            bad.retain(|b| !b.starts_with(&format!("{codec}:")));
        }
        // Lines linger 40 s after the end; let the next call get fresh ones.
        std::thread::sleep(Duration::from_millis(300));
    }
    e.cmd(Cmd::HangupAll);
    if let Ok(p) = std::env::var("SIDETONE_CODECS_PCAP") {
        std::fs::write(p, e.capture()).ok();
    }
    assert!(bad.is_empty(), "codecs failing: {bad:?}");
}

#[test]
#[ignore]
fn rtcp_reports_with_asterisk() {
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        auto_hold: false,
        ..Default::default()
    };
    let a = acc("a", "2001", "secret2001", DtmfMode::Rfc4733);
    let e = Engine::start(settings, vec![a], None);
    wait_for(&e, "registered", 10, |e| {
        e.state().accounts.iter().all(|a| a.state == "registered")
    });
    let l = e.call(CallRequest {
        account: Some("a".into()),
        target: "600".into(),
        overrides: Some(serde_json::json!({ "codecs": ["PCMU"] })),
        ..Default::default()
    });
    wait_for(&e, "connected", 10, |e| line_state(e, l) == "connected");
    wait_for(&e, "RTCP both ways with a round trip", 20, |e| {
        e.state()
            .calls
            .iter()
            .any(|c| c.line == l && c.rtcp_sent >= 2 && c.rtcp_received >= 1 && c.rtt_ms.is_some())
    });
    let c = e.state().calls.into_iter().find(|c| c.line == l).unwrap();
    println!(
        "rtcp sent {} received {} rtt {:?} remote loss {:?} jitter {:?}, our rx loss {:?} jitter {:?}",
        c.rtcp_sent, c.rtcp_received, c.rtt_ms, c.remote_loss_pct, c.remote_jitter_ms, c.rx_loss_pct, c.rx_jitter_ms
    );
    assert!(c.rtt_ms.unwrap() < 50.0, "loopback round trip");
    // The capture holds the RTCP and the analysis puts it on the streams.
    let r = sidetone_core::analyze_bytes(&e.capture()).unwrap();
    assert!(r.summary.rtcp_packets >= 3);
    assert!(
        r.streams.iter().any(|s| !s.rtcp.is_empty()),
        "RTCP attached to a stream"
    );
    e.cmd(Cmd::HangupAll);
}

#[test]
#[ignore]
fn hep_copies_to_a_collector() {
    let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        hep_collector: rx.local_addr().unwrap().to_string(),
        hep_agent_id: 77,
        ..Default::default()
    };
    let a = acc("a", "2001", "secret2001", DtmfMode::Rfc4733);
    let e = Engine::start(settings, vec![a], None);
    wait_for(&e, "registered", 10, |e| {
        e.state().accounts.iter().all(|a| a.state == "registered")
    });
    // The HEP copies, unwrapped, make a capture the analysis reads like any other.
    let mut methods = Vec::new();
    let mut buf = [0u8; 65536];
    while let Ok(n) = rx.recv(&mut buf) {
        let d = sidetone_core::net::decode_hep(&buf[..n]).expect("HEPv3");
        let line = String::from_utf8_lossy(d.payload)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        methods.push(line);
        if methods.iter().any(|m| m.starts_with("SIP/2.0 200")) {
            break;
        }
    }
    println!("HEP: {methods:?}");
    assert!(methods.iter().any(|m| m.starts_with("REGISTER")));
    assert!(methods.iter().any(|m| m.starts_with("SIP/2.0 200")));
}

#[test]
#[ignore]
fn voicemail_lamp() {
    // The lab Asterisk polls mailbox 2001 every second; a message file
    // dropped into its spool turns the lamp on.
    let spool = std::env::var("SIDETONE_LAB_DIR").unwrap_or_else(|_| "/tmp/stlab".into());
    let inbox = std::path::Path::new(&spool).join("spool/voicemail/default/2001/INBOX");
    let _ = std::fs::remove_dir_all(&inbox);
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        ..Default::default()
    };
    let a = acc("a", "2001", "secret2001", DtmfMode::Rfc4733);
    let e = Engine::start(settings, vec![a], None);
    let mwi = |e: &Engine| e.state().accounts.first().and_then(|a| a.mwi.clone());
    wait_for(&e, "voicemail state known", 15, |e| mwi(e).is_some());
    assert!(!mwi(&e).unwrap().waiting);
    if std::fs::create_dir_all(&inbox).is_err() {
        println!(
            "no access to {}, skipping the new message part",
            inbox.display()
        );
        return;
    }
    std::fs::write(
        inbox.join("msg0000.txt"),
        "[message]\norigmailbox=2001\ncontext=test\nmacrocontext=\nexten=2001\ncallerid=\"Lab\" <3001>\norigdate=Mon Jan 1 00:00:00 AM UTC 2026\norigtime=1767225600\ncategory=\nflag=\nduration=3\n",
    )
    .unwrap();
    std::fs::write(inbox.join("msg0000.wav"), [0u8; 44]).unwrap();
    wait_for(&e, "voicemail lamp on", 15, |e| {
        mwi(e).is_some_and(|m| m.waiting && m.new == 1)
    });
    println!("mwi: {:?}", mwi(&e));
    let _ = std::fs::remove_dir_all(&inbox);
    wait_for(&e, "voicemail lamp off", 15, |e| {
        mwi(e).is_some_and(|m| !m.waiting)
    });
}

#[test]
#[ignore]
fn call_forwarding() {
    // 3001 forwards everything to the echo test; a call to it (700) ends up there.
    let fwd = Engine::start(
        PhoneSettings {
            audio_source: "tone".into(),
            forward_always: "600".into(),
            ..Default::default()
        },
        vec![acc("b", "3001", "secret3001", DtmfMode::Rfc4733)],
        None,
    );
    let caller = Engine::start(
        PhoneSettings {
            audio_source: "tone".into(),
            auto_hold: false,
            ..Default::default()
        },
        vec![acc("a", "2001", "secret2001", DtmfMode::Rfc4733)],
        None,
    );
    for e in [&fwd, &caller] {
        wait_for(e, "registered", 10, |e| {
            e.state().accounts.iter().all(|a| a.state == "registered")
        });
    }
    let l = caller.call(CallRequest {
        account: Some("a".into()),
        target: "700".into(),
        ..Default::default()
    });
    wait_for(&caller, "forwarded call connected to the echo", 15, |e| {
        e.state()
            .calls
            .iter()
            .any(|c| c.line == l && c.state == "connected" && c.rtp_received > 20)
    });
    assert!(fwd
        .events_since(0)
        .iter()
        .any(|ev| ev.text.contains("forwarded to 600")));
    caller.cmd(Cmd::Hangup(l));
}

#[test]
#[ignore]
fn sip_message_between_phones() {
    let settings = PhoneSettings {
        audio_source: "tone".into(),
        ..Default::default()
    };
    let a = acc("a", "2001", "secret2001", DtmfMode::Rfc4733);
    let b = acc("b", "3001", "secret3001", DtmfMode::Rfc4733);
    let e = Engine::start(settings, vec![a, b], None);
    wait_for(&e, "registered", 10, |e| {
        let st = e.state();
        st.accounts.len() == 2 && st.accounts.iter().all(|a| a.state == "registered")
    });
    e.cmd(Cmd::Message(
        Some("a".into()),
        "3001".into(),
        "hello from 2001".into(),
    ));
    wait_for(&e, "MESSAGE delivered and received", 10, |e| {
        let ev = e.events_since(0);
        ev.iter()
            .any(|x| x.kind == "message" && x.text.contains("delivered"))
            && ev.iter().any(|x| {
                x.kind == "message"
                    && x.account.as_deref() == Some("b")
                    && x.text.contains("hello from 2001")
            })
    });
}
