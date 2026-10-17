//! Automated SIP test suites: steps with expectations, pcapng per case,
//! JUnit XML for CI, and optional AI generation/explanation.

use crate::aihttp;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sidetone_core::ai::AiConfig;
use sidetone_core::{analyze_bytes, Report, Severity};
use sidetone_ua::{AudioSource, CallOptions, Profile, Tap, Ua};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suite {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Base profile (same JSON as `sidetone profile`); cases deep-merge their own on top.
    #[serde(default)]
    pub profile: Value,
    pub cases: Vec<Case>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub name: String,
    #[serde(default)]
    pub profile: Value,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Register(RegisterStep),
    Unregister(RegisterStep),
    Options(OptionsStep),
    Call(CallStep),
    /// Pause between steps, in milliseconds.
    Wait(u64),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterStep {
    #[serde(default)]
    pub expect_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionsStep {
    pub target: String,
    #[serde(default)]
    pub expect_status: Option<u16>,
    #[serde(default)]
    pub max_rtt_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStep {
    pub target: String,
    #[serde(default = "default_duration")]
    pub duration: u64,
    #[serde(default)]
    pub dtmf: Option<String>,
    /// tone | silence | echo
    #[serde(default)]
    pub audio: Option<String>,
    #[serde(default)]
    pub ring_timeout: Option<u64>,
    #[serde(default)]
    pub expect: Expect,
}

fn default_duration() -> u64 {
    5
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Expect {
    /// Expected final status of the INVITE (default 200).
    #[serde(default)]
    pub status: Option<u16>,
    /// Maximum number of error findings in the analysis (default 0 when the call should succeed).
    #[serde(default)]
    pub max_errors: Option<usize>,
    #[serde(default)]
    pub max_warnings: Option<usize>,
    #[serde(default)]
    pub min_mos: Option<f64>,
    #[serde(default)]
    pub max_loss_pct: Option<f64>,
    #[serde(default)]
    pub max_jitter_ms: Option<f64>,
    #[serde(default)]
    pub max_pdd_ms: Option<f64>,
    #[serde(default)]
    pub min_talk_s: Option<f64>,
    /// RTP must be received from the far end.
    #[serde(default)]
    pub rtp_received: Option<bool>,
    #[serde(default)]
    pub codec: Option<String>,
    /// Rules that must appear in the analysis (e.g. "rtp.dtmf").
    #[serde(default)]
    pub rules_present: Vec<String>,
    /// Rules that must not appear (e.g. "rtp.one_way").
    #[serde(default)]
    pub rules_absent: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub step: String,
    pub what: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub name: String,
    pub passed: bool,
    pub seconds: f64,
    pub checks: Vec<Check>,
    pub error: Option<String>,
    pub pcap: Option<String>,
    pub ai_explanation: Option<String>,
}

/// Replaces ${VAR} with environment values in every string.
fn expand_env(v: &mut Value) {
    match v {
        Value::String(s) => {
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(i) = rest.find("${") {
                out.push_str(&rest[..i]);
                match rest[i + 2..].find('}') {
                    Some(j) => {
                        let name = &rest[i + 2..i + 2 + j];
                        out.push_str(&std::env::var(name).unwrap_or_default());
                        rest = &rest[i + 3 + j..];
                    }
                    None => {
                        out.push_str(&rest[i..]);
                        rest = "";
                    }
                }
            }
            out.push_str(rest);
            *s = out;
        }
        Value::Array(a) => a.iter_mut().for_each(expand_env),
        Value::Object(o) => o.values_mut().for_each(expand_env),
        _ => {}
    }
}

fn merge(base: &mut Value, over: &Value) {
    match (base, over) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                merge(b.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (b, o) if !o.is_null() => *b = o.clone(),
        _ => {}
    }
}

pub fn load_suite(path: &Path) -> Result<Suite> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_suite(&text)
}

pub fn parse_suite(text: &str) -> Result<Suite> {
    serde_json::from_str(text).map_err(|e| anyhow!("invalid suite: {e}"))
}

fn check(checks: &mut Vec<Check>, step: &str, what: &str, passed: bool, detail: String) {
    checks.push(Check {
        step: step.into(),
        what: what.into(),
        passed,
        detail,
    });
}

fn verify_call(
    checks: &mut Vec<Check>,
    step: &str,
    e: &Expect,
    out: &sidetone_ua::CallOutcome,
    r: &Report,
) {
    let want = e.status.unwrap_or(200);
    check(
        checks,
        step,
        "final status",
        out.final_status == Some(want),
        format!(
            "expected {want}, got {}",
            out.final_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "none".into())
        ),
    );
    let errors = r
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let max_err = e
        .max_errors
        .unwrap_or(if want < 300 { 0 } else { usize::MAX });
    if max_err != usize::MAX {
        let titles: Vec<String> = r
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .map(|f| f.title.clone())
            .collect();
        check(
            checks,
            step,
            "error findings",
            errors <= max_err,
            format!("{errors} (max {max_err}) {}", titles.join("; ")),
        );
    }
    if let Some(mw) = e.max_warnings {
        let w = r
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();
        check(
            checks,
            step,
            "warning findings",
            w <= mw,
            format!("{w} (max {mw})"),
        );
    }
    let streams = &r.streams;
    if let Some(m) = e.min_mos {
        let worst = streams
            .iter()
            .filter_map(|s| s.mos)
            .fold(f64::INFINITY, f64::min);
        let ok = worst.is_finite() && worst >= m;
        check(
            checks,
            step,
            "MOS",
            ok,
            format!(
                "worst {} (min {m})",
                if worst.is_finite() {
                    format!("{worst:.2}")
                } else {
                    "n/a".into()
                }
            ),
        );
    }
    if let Some(m) = e.max_loss_pct {
        let worst = streams.iter().map(|s| s.loss_pct).fold(0.0, f64::max);
        check(
            checks,
            step,
            "packet loss",
            worst <= m,
            format!("worst {worst:.2}% (max {m}%)"),
        );
    }
    if let Some(m) = e.max_jitter_ms {
        let worst = streams.iter().map(|s| s.jitter_ms).fold(0.0, f64::max);
        check(
            checks,
            step,
            "jitter",
            worst <= m,
            format!("worst {worst:.1} ms (max {m} ms)"),
        );
    }
    if let Some(m) = e.max_pdd_ms {
        let pdd = r
            .calls
            .iter()
            .find(|c| c.kind == "INVITE")
            .and_then(|c| c.pdd_ms);
        check(
            checks,
            step,
            "post-dial delay",
            pdd.map(|p| p <= m).unwrap_or(false),
            format!(
                "{} (max {m} ms)",
                pdd.map(|p| format!("{p:.0} ms"))
                    .unwrap_or_else(|| "n/a".into())
            ),
        );
    }
    if let Some(m) = e.min_talk_s {
        let t = out.talk_s.unwrap_or(0.0);
        check(
            checks,
            step,
            "talk time",
            t >= m,
            format!("{t:.1} s (min {m} s)"),
        );
    }
    if let Some(want) = e.rtp_received {
        check(
            checks,
            step,
            "RTP received",
            (out.rtp_received > 0) == want,
            format!("{} packets", out.rtp_received),
        );
    }
    if let Some(c) = &e.codec {
        check(
            checks,
            step,
            "codec",
            out.codec
                .as_deref()
                .map(|x| x.eq_ignore_ascii_case(c))
                .unwrap_or(false),
            format!(
                "expected {c}, got {}",
                out.codec.clone().unwrap_or_default()
            ),
        );
    }
    for rule in &e.rules_present {
        let ok = r.findings.iter().any(|f| &f.rule == rule);
        check(
            checks,
            step,
            &format!("rule {rule} present"),
            ok,
            String::new(),
        );
    }
    for rule in &e.rules_absent {
        let hit: Vec<String> = r
            .findings
            .iter()
            .filter(|f| &f.rule == rule)
            .map(|f| f.title.clone())
            .collect();
        check(
            checks,
            step,
            &format!("rule {rule} absent"),
            hit.is_empty(),
            hit.join("; "),
        );
    }
}

fn run_case(suite: &Suite, case: &Case, out_dir: &Path, ai: Option<&AiConfig>) -> CaseResult {
    let t0 = Instant::now();
    let mut checks = Vec::new();
    let mut base = if suite.profile.is_null() {
        serde_json::to_value(Profile::default()).unwrap()
    } else {
        suite.profile.clone()
    };
    if base.get("account").is_none() {
        let mut d = serde_json::to_value(Profile::default()).unwrap();
        merge(&mut d, &base);
        base = d;
    }
    merge(&mut base, &case.profile);
    expand_env(&mut base);
    let mut res = CaseResult {
        name: case.name.clone(),
        passed: false,
        seconds: 0.0,
        checks: vec![],
        error: None,
        pcap: None,
        ai_explanation: None,
    };
    let profile: Profile = match serde_json::from_value(base) {
        Ok(p) => p,
        Err(e) => {
            res.error = Some(format!("profile: {e}"));
            return res;
        }
    };
    let tap = Tap::new();
    let mut ua = match Ua::new(profile, tap.clone()) {
        Ok(u) => u,
        Err(e) => {
            res.error = Some(e.to_string());
            return res;
        }
    };
    let mut last_report: Option<Report> = None;
    for (i, step) in case.steps.iter().enumerate() {
        let label = format!("step {} ", i + 1);
        let r: Result<()> = (|| {
            match step {
                Step::Register(s) | Step::Unregister(s) => {
                    let unreg = matches!(step, Step::Unregister(_));
                    let st = ua
                        .register(if unreg { Some(0) } else { None })
                        .map_err(|e| anyhow!("{e}"))?;
                    let want = s.expect_status.unwrap_or(200);
                    let name = format!("{label}{}", if unreg { "unregister" } else { "register" });
                    check(
                        &mut checks,
                        &name,
                        "status",
                        st == Some(want),
                        format!(
                            "expected {want}, got {}",
                            st.map(|x| x.to_string())
                                .unwrap_or_else(|| "no response".into())
                        ),
                    );
                }
                Step::Options(s) => {
                    let r = ua.options(&s.target).map_err(|e| anyhow!("{e}"))?;
                    let name = format!("{label}options {}", s.target);
                    let want = s.expect_status.unwrap_or(200);
                    check(
                        &mut checks,
                        &name,
                        "status",
                        r.map(|x| x.0) == Some(want),
                        format!(
                            "expected {want}, got {}",
                            r.map(|x| x.0.to_string())
                                .unwrap_or_else(|| "no response".into())
                        ),
                    );
                    if let (Some(max), Some((_, ms))) = (s.max_rtt_ms, r) {
                        check(
                            &mut checks,
                            &name,
                            "round trip",
                            ms <= max,
                            format!("{ms} ms (max {max})"),
                        );
                    }
                }
                Step::Call(s) => {
                    let before = tap.len();
                    let audio = match s.audio.as_deref() {
                        Some("echo") => AudioSource::Echo,
                        Some("silence") => AudioSource::Silence,
                        _ => AudioSource::Tone(440.0),
                    };
                    let out = ua
                        .call(&CallOptions {
                            target: s.target.clone(),
                            duration: Duration::from_secs(s.duration),
                            ring_timeout: Duration::from_secs(s.ring_timeout.unwrap_or(30)),
                            audio,
                            dtmf: s.dtmf.clone(),
                        })
                        .map_err(|e| anyhow!("{e}"))?;
                    let _ = before;
                    let rep = analyze_bytes(&tap.to_pcapng()).map_err(|e| anyhow!("{e}"))?;
                    verify_call(
                        &mut checks,
                        &format!("{label}call {}", s.target),
                        &s.expect,
                        &out,
                        &rep,
                    );
                    last_report = Some(rep);
                }
                Step::Wait(ms) => std::thread::sleep(Duration::from_millis(*ms)),
            }
            Ok(())
        })();
        if let Err(e) = r {
            res.error = Some(format!("{label}: {e}"));
            break;
        }
    }
    let pcap = tap.to_pcapng();
    let safe: String = case
        .name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let p = out_dir.join(format!("{safe}.pcapng"));
    if std::fs::write(&p, &pcap).is_ok() {
        res.pcap = Some(p.display().to_string());
    }
    res.passed = res.error.is_none() && checks.iter().all(|c| c.passed);
    res.checks = checks;
    if !res.passed {
        if let Some(cfg) = ai {
            let rep = last_report.or_else(|| analyze_bytes(&pcap).ok());
            if let Some(rep) = rep {
                let failed: Vec<String> = res
                    .checks
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| format!("{} / {}: {}", c.step, c.what, c.detail))
                    .collect();
                let q = format!("This automated test case failed: {}. Failed checks: {}. Error: {}. Explain the most likely cause and what to change.", case.name, failed.join(" | "), res.error.clone().unwrap_or_default());
                let prompt =
                    sidetone_core::ai::build_prompt(&rep, None, cfg.redact.as_ref(), Some(&q));
                res.ai_explanation = Some(
                    aihttp::ask(cfg, &prompt).unwrap_or_else(|e| format!("AI request failed: {e}")),
                );
            }
        }
    }
    res.seconds = t0.elapsed().as_secs_f64();
    res
}

fn xml_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn junit(suite: &Suite, results: &[CaseResult]) -> String {
    let failures = results
        .iter()
        .filter(|r| !r.passed && r.error.is_none())
        .count();
    let errors = results.iter().filter(|r| r.error.is_some()).count();
    let time: f64 = results.iter().map(|r| r.seconds).sum();
    let mut x = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"{}\" tests=\"{}\" failures=\"{failures}\" errors=\"{errors}\" time=\"{time:.3}\">\n", xml_esc(&suite.name), results.len());
    for r in results {
        x.push_str(&format!(
            "  <testcase classname=\"sidetone\" name=\"{}\" time=\"{:.3}\">\n",
            xml_esc(&r.name),
            r.seconds
        ));
        if let Some(e) = &r.error {
            x.push_str(&format!("    <error message=\"{}\"/>\n", xml_esc(e)));
        } else if !r.passed {
            let msg: Vec<String> = r
                .checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| format!("{} {}: {}", c.step, c.what, c.detail))
                .collect();
            x.push_str(&format!(
                "    <failure message=\"{}\">{}</failure>\n",
                xml_esc(&msg.join("; ")),
                xml_esc(&r.ai_explanation.clone().unwrap_or_default())
            ));
        }
        if let Some(p) = &r.pcap {
            x.push_str(&format!(
                "    <system-out>capture: {}</system-out>\n",
                xml_esc(p)
            ));
        }
        x.push_str("  </testcase>\n");
    }
    x.push_str("</testsuite>\n");
    x
}

pub fn run_suite(
    path: &Path,
    out_dir: &Path,
    junit_out: Option<PathBuf>,
    filter: Option<&str>,
    ai: Option<&AiConfig>,
) -> Result<bool> {
    let suite = load_suite(path)?;
    std::fs::create_dir_all(out_dir)?;
    println!("Suite: {} ({} cases)", suite.name, suite.cases.len());
    let mut results = Vec::new();
    for case in &suite.cases {
        if let Some(f) = filter {
            if !case.name.contains(f) {
                continue;
            }
        }
        println!("\n▶ {}", case.name);
        let r = run_case(&suite, case, out_dir, ai);
        for c in &r.checks {
            println!(
                "  {} {} / {}  {}",
                if c.passed { "PASS" } else { "FAIL" },
                c.step,
                c.what,
                c.detail
            );
        }
        if let Some(e) = &r.error {
            println!("  ERROR {e}");
        }
        if let Some(p) = &r.pcap {
            println!("  capture: {p}");
        }
        if let Some(a) = &r.ai_explanation {
            println!(
                "  AI:\n{}",
                a.lines()
                    .map(|l| format!("    {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        println!(
            "  => {} ({:.1} s)",
            if r.passed { "PASSED" } else { "FAILED" },
            r.seconds
        );
        results.push(r);
    }
    let passed = results.iter().filter(|r| r.passed).count();
    println!("\n{passed}/{} cases passed", results.len());
    if let Some(j) = junit_out {
        std::fs::write(&j, junit(&suite, &results))?;
        println!("JUnit report: {}", j.display());
    }
    std::fs::write(
        out_dir.join("results.json"),
        serde_json::to_string_pretty(&results)?,
    )?;
    Ok(passed == results.len())
}

pub const SUITE_FORMAT: &str = r#"Sidetone test suite JSON format:
{
  "name": "string",
  "description": "string (optional)",
  "profile": { "account": {"user": "...", "auth_user": null, "password": "${SIP_PASSWORD}", "domain": "host[:port]", "display_name": "...", "outbound_proxy": null, "expires": 300},
               "behavior": {"t1_ms": 500, "codecs": ["PCMU","PCMA"], "ptime_ms": 20, "dtmf_mode": "rfc4733|info", "session_timer": 0, "user_phone": false,
                            "compact_headers": false, "require_prack": false, "long_contact": false, "symmetric_rtp": true, "skip_ack": false, "sdp_ip_override": null} },
  "cases": [
    { "name": "string", "profile": { ...same shape, deep-merged over the suite profile... },
      "steps": [
        {"register": {"expect_status": 200}},
        {"options": {"target": "user@host or number", "expect_status": 200, "max_rtt_ms": 300}},
        {"call": {"target": "number or user@host", "duration": 5, "dtmf": "123#", "audio": "tone|echo|silence", "ring_timeout": 30,
                  "expect": {"status": 200, "max_errors": 0, "max_warnings": null, "min_mos": 4.0, "max_loss_pct": 1.0, "max_jitter_ms": 30,
                             "max_pdd_ms": 3000, "min_talk_s": 4, "rtp_received": true, "codec": "PCMU",
                             "rules_present": ["rtp.dtmf"], "rules_absent": ["rtp.one_way"]}}},
        {"wait": 1000},
        {"unregister": {"expect_status": 200}}
      ] }
  ]
}
Known analysis rule ids: sip.invite_no_response, sip.call_failed, sip.call_rejected_user, sip.call_cancelled, sip.no_ack, sip.200_retransmitted, sip.invite_retransmitted,
sip.drop_32s, sip.session_timer, sip.auth_rejected, sip.auth_unanswered, sip.error_response, sip.no_response, sip.registered, sip.pdd_high, sip.slow_first_response,
sip.contact_private, sip.missing_headers, sip.reason, sdp.no_common_codec, sdp.private_ip, sdp.srtp_mismatch, sdp.dtmf_not_negotiated, sdp.hold, sdp.ptime_mismatch,
rtp.no_media, rtp.one_way, rtp.asymmetric, rtp.loss, rtp.jitter, rtp.gap, rtp.mos_low, rtp.dtmf, rtp.unexpected_pt, rtp.ssrc_change.
Use ${ENV_VAR} for secrets. Negative tests set expect.status to the failure code (e.g. 404, 488) and may set max_errors to null."#;

/// Asks the model to write a suite from a natural-language description; validates before returning.
pub fn generate_suite(cfg: &AiConfig, description: &str, context: Option<&str>) -> Result<String> {
    let mut prompt = format!(
        "Write a Sidetone SIP test suite for this request:\n\n{description}\n\n{SUITE_FORMAT}\n\nReply with the JSON only, no prose, no markdown fences."
    );
    if let Some(c) = context {
        prompt.push_str(&format!("\n\nEnvironment details:\n{c}"));
    }
    let mut cfg = cfg.clone();
    cfg.redact = None;
    cfg.max_tokens = cfg.max_tokens.max(4000);
    let mut last_err = String::new();
    for _ in 0..2 {
        let p = if last_err.is_empty() {
            prompt.clone()
        } else {
            format!("{prompt}\n\nYour previous answer was invalid: {last_err}. Fix it.")
        };
        let text = aihttp::ask_with_system(
            &cfg,
            "You write precise test definitions for SIP/VoIP systems. Output strictly valid JSON.",
            &p,
        )?;
        let json = extract_json(&text);
        match parse_suite(&json) {
            Ok(s) => return Ok(serde_json::to_string_pretty(&s)?),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(anyhow!("model did not produce a valid suite: {last_err}"))
}

fn extract_json(t: &str) -> String {
    let t = t.trim();
    let t = t
        .strip_prefix("```json")
        .or_else(|| t.strip_prefix("```"))
        .unwrap_or(t);
    let t = t.strip_suffix("```").unwrap_or(t);
    match (t.find('{'), t.rfind('}')) {
        (Some(a), Some(b)) if b > a => t[a..=b].to_string(),
        _ => t.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_and_merges_profiles() {
        let s = r#"{"name":"x","profile":{"account":{"domain":"127.0.0.1:5070","password":"${SIDETONE_TEST_PW}"}},
          "cases":[{"name":"a","profile":{"behavior":{"t1_ms":250}},"steps":[{"register":{}},{"call":{"target":"600","expect":{"min_mos":4.0}}},{"wait":10}]}]}"#;
        let suite = parse_suite(s).unwrap();
        std::env::set_var("SIDETONE_TEST_PW", "pw");
        let mut base = serde_json::to_value(Profile::default()).unwrap();
        merge(&mut base, &suite.profile);
        merge(&mut base, &suite.cases[0].profile);
        expand_env(&mut base);
        let p: Profile = serde_json::from_value(base).unwrap();
        assert_eq!(p.account.domain, "127.0.0.1:5070");
        assert_eq!(p.account.password.as_deref(), Some("pw"));
        assert_eq!(p.behavior.t1_ms, 250);
        assert_eq!(p.behavior.max_forwards, 70);
    }
}
