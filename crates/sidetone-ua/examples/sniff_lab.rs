//! Interface capture against the Asterisk lab: captures on the loopback
//! while the engine calls the echo test, then checks the capture.
//! Needs capture rights (CI runs it with sudo):
//!   cargo build -p sidetone-ua --example sniff_lab && sudo target/debug/examples/sniff_lab

use sidetone_ua::engine::{AccountCfg, CallRequest, Cmd, Engine, PhoneSettings};
use sidetone_ua::Profile;
use std::time::{Duration, Instant};

fn main() {
    let (ifs, version) = sidetone_ua::sniff::interfaces().expect("libpcap available");
    println!("{version}");
    let lo = ifs
        .iter()
        .find(|i| i.loopback)
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "lo".into());
    let mut s = sidetone_ua::sniff::Sniffer::default();
    s.start(&lo, "port 5070 or (udp and portrange 10000-60000)")
        .expect("capture starts");

    let mut p = Profile::default();
    p.account.user = "2001".into();
    p.account.password = Some("secret2001".into());
    p.account.domain = "127.0.0.1:5070".into();
    let e = Engine::start(
        PhoneSettings {
            audio_source: "tone".into(),
            ..Default::default()
        },
        vec![AccountCfg {
            id: "a".into(),
            profile: p,
            ..Default::default()
        }],
        None,
    );
    let t = Instant::now();
    while !e.state().accounts.iter().any(|a| a.state == "registered") {
        assert!(t.elapsed() < Duration::from_secs(10), "registration");
        std::thread::sleep(Duration::from_millis(100));
    }
    let l = e.call(CallRequest {
        account: Some("a".into()),
        target: "600".into(),
        ..Default::default()
    });
    std::thread::sleep(Duration::from_secs(3));
    e.cmd(Cmd::Hangup(l));
    std::thread::sleep(Duration::from_secs(1));
    s.stop_capture();
    let st = s.status();
    println!("{st:?}");
    assert!(st.error.is_none(), "capture error: {:?}", st.error);
    assert!(st.sip >= 6, "SIP seen on the wire");
    assert!(st.rtp > 100, "RTP seen on the wire");
    let r = sidetone_core::analysis::analyze_bytes(&s.to_pcapng()).expect("capture parses");
    let call = r
        .calls
        .iter()
        .find(|c| c.messages.len() >= 4)
        .expect("the call is in the capture");
    println!(
        "analysis: {} messages, call {}",
        r.messages.len(),
        call.call_id
    );
    println!("ok");
}
