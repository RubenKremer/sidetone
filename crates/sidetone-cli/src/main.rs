//! `sidetone` command line.

use sidetone_cli::{aihttp, mcp, report_text, serve, testrun};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sidetone_core::ai::{AiConfig, Provider};
use sidetone_core::export::{export_pcapng, ExportOptions};
use sidetone_core::ladder::{render_svg, LadderOptions};
use sidetone_core::redact::RedactOptions;
use sidetone_core::{analyze_bytes, Report};
use sidetone_ua::{AudioSource, CallOptions, Profile, Tap, Ua};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "sidetone",
    version,
    about = "SIP softphone and call analyzer for troubleshooting"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Write the configuration (accounts, settings, codecs) as sidetone-config JSON.
    Export {
        /// Output file (standard output when left out).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Include account passwords.
        #[arg(long)]
        secrets: bool,
    },
    /// Load a sidetone-config JSON file exported by the app or by this command.
    Import {
        file: PathBuf,
        /// Add the accounts to the current ones instead of replacing everything.
        #[arg(long)]
        merge: bool,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// Export or import the phone configuration (the same file as Settings, Import and export).
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Analyze a pcap/pcapng capture: calls, ladder, RTP quality, findings.
    Analyze {
        file: PathBuf,
        /// Restrict output to one call (index or Call-ID).
        #[arg(long)]
        call: Option<String>,
        /// Print the full report as JSON.
        #[arg(long)]
        json: bool,
        /// Print the text ladder.
        #[arg(long)]
        ladder: bool,
        /// Write the ladder as SVG.
        #[arg(long)]
        svg: Option<PathBuf>,
    },
    /// Export pcapng with findings as packet comments, optional redaction and call filter.
    Export {
        file: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long)]
        call: Option<String>,
        /// Mask numbers, names, credentials and public IPv4 addresses.
        #[arg(long)]
        redact: bool,
        #[arg(long)]
        sip_only: bool,
        #[arg(long)]
        no_annotate: bool,
    },
    /// Ask an AI model to interpret the analysis.
    Ai {
        file: PathBuf,
        #[arg(long)]
        call: Option<String>,
        #[command(flatten)]
        ai: AiArgs,
        /// Extra question for the model.
        #[arg(long)]
        question: Option<String>,
        /// Print the prompt instead of calling the provider.
        #[arg(long)]
        dry_run: bool,
    },
    /// Write the built-in synthetic sample captures to a directory.
    Samples { dir: PathBuf },
    /// Print a default UA profile (JSON) to start from.
    Profile,
    /// Register with the account in the profile.
    Register {
        #[command(flatten)]
        ua: UaArgs,
        /// Unregister afterwards (expires 0).
        #[arg(long)]
        unregister: bool,
    },
    /// Send OPTIONS and report status and round trip.
    Options {
        target: String,
        #[command(flatten)]
        ua: UaArgs,
    },
    /// Place a test call and analyze it.
    Call {
        target: String,
        #[command(flatten)]
        ua: UaArgs,
        /// Seconds to stay connected.
        #[arg(long, default_value_t = 10)]
        duration: u64,
        #[arg(long, default_value_t = 60)]
        ring_timeout: u64,
        /// Audio to send.
        #[arg(long, value_enum, default_value_t = Audio::Tone)]
        audio: Audio,
        /// 8 kHz 16-bit WAV to send when --audio wav.
        #[arg(long)]
        wav_in: Option<PathBuf>,
        /// DTMF digits to send 1 s after answer.
        #[arg(long)]
        dtmf: Option<String>,
        /// Register before calling.
        #[arg(long)]
        register: bool,
        /// Write the stereo recording (left sent, right received).
        #[arg(long)]
        wav: Option<PathBuf>,
    },
    /// Wait for incoming calls and answer them.
    Answer {
        #[command(flatten)]
        ua: UaArgs,
        #[arg(long, default_value_t = 1)]
        calls: usize,
        /// Seconds to wait for calls.
        #[arg(long, default_value_t = 120)]
        wait: u64,
        #[arg(long, default_value_t = 30)]
        duration: u64,
        #[arg(long, value_enum, default_value_t = Audio::Echo)]
        audio: Audio,
        #[arg(long)]
        register: bool,
    },
    /// Run an automated test suite (JSON); writes a pcapng per case and optional JUnit XML.
    Test {
        suite: PathBuf,
        /// Directory for captures and results.json.
        #[arg(long, default_value = "sidetone-results")]
        out: PathBuf,
        #[arg(long)]
        junit: Option<PathBuf>,
        /// Only cases whose name contains this text.
        #[arg(long)]
        only: Option<String>,
        /// Ask the AI to explain failed cases.
        #[arg(long)]
        ai_explain: bool,
        #[command(flatten)]
        ai: AiArgs,
    },
    /// Let an AI model write a test suite from a plain-language description.
    TestGen {
        /// What to test, e.g. "register 1001 on 10.0.0.5 and call the echo test 600 with DTMF".
        description: String,
        #[arg(short, long)]
        out: PathBuf,
        /// Extra environment facts for the model (numbers, servers, expectations).
        #[arg(long)]
        context: Option<String>,
        #[command(flatten)]
        ai: AiArgs,
    },
    /// Print the test suite format reference.
    TestFormat,
    /// Run as an MCP server over stdio, exposing analysis and test tools to AI clients.
    Mcp,
    /// Serve the web UI and an HTTP API (analysis runs on this machine).
    Serve {
        #[arg(long, default_value = "127.0.0.1:8640")]
        listen: String,
        /// Directory with the web UI (index.html, app.js...).
        #[arg(long)]
        web: Option<PathBuf>,
        /// Disable the API access token (only on trusted networks).
        #[arg(long)]
        no_token: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Audio {
    Silence,
    Tone,
    Echo,
    Wav,
}

#[derive(Args, Clone)]
pub struct UaArgs {
    /// Profile JSON (see `sidetone profile`).
    #[arg(long)]
    profile: Option<PathBuf>,
    /// Domain / registrar host[:port] (overrides the profile).
    #[arg(long)]
    domain: Option<String>,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    auth_user: Option<String>,
    /// Password; also read from SIDETONE_PASSWORD.
    #[arg(long, env = "SIDETONE_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    #[arg(long)]
    outbound_proxy: Option<String>,
    #[arg(long)]
    local_port: Option<u16>,
    /// Write everything sent/received to this pcapng.
    #[arg(long)]
    pcap: Option<PathBuf>,
    /// Run the analyzer on the captured traffic and print findings.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    analyze: bool,
}

#[derive(Args, Clone)]
pub struct AiArgs {
    #[arg(long, value_enum, default_value_t = ProviderArg::Anthropic)]
    provider: ProviderArg,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    /// API key; defaults to ANTHROPIC_API_KEY / OPENAI_API_KEY.
    #[arg(long)]
    api_key: Option<String>,
    #[arg(long, default_value = "English")]
    lang: String,
    /// Send unredacted data to the provider.
    #[arg(long)]
    no_redact: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderArg {
    Anthropic,
    Openai,
    Ollama,
}

impl AiArgs {
    fn config(&self) -> Result<AiConfig> {
        let provider = match self.provider {
            ProviderArg::Anthropic => Provider::Anthropic,
            ProviderArg::Openai => Provider::Openai,
            ProviderArg::Ollama => Provider::Ollama,
        };
        let api_key = self.api_key.clone().or_else(|| match provider {
            Provider::Anthropic => std::env::var("ANTHROPIC_API_KEY").ok(),
            Provider::Openai => std::env::var("OPENAI_API_KEY").ok(),
            Provider::Ollama => None,
        });
        let model = match (&self.model, provider) {
            (Some(m), _) => m.clone(),
            (None, Provider::Anthropic) => sidetone_core::ai::DEFAULT_ANTHROPIC_MODEL.to_string(),
            (None, _) => bail!("--model is required for this provider"),
        };
        Ok(AiConfig {
            provider,
            base_url: self.base_url.clone(),
            model,
            api_key,
            language: self.lang.clone(),
            max_tokens: 2000,
            redact: if self.no_redact {
                None
            } else {
                Some(RedactOptions::default())
            },
        })
    }
}

fn load(file: &Path) -> Result<Report> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    analyze_bytes(&bytes).map_err(|e| anyhow!("{}: {e}", file.display()))
}

fn pick_call(r: &Report, key: &Option<String>) -> Result<Option<usize>> {
    match key {
        None => Ok(None),
        Some(k) => r
            .find_call(k)
            .map(Some)
            .ok_or_else(|| anyhow!("no call {k}")),
    }
}

fn build_ua(a: &UaArgs) -> Result<Ua> {
    let mut p = match &a.profile {
        Some(path) => Profile::from_json(&std::fs::read_to_string(path)?)
            .map_err(|e| anyhow!("profile: {e}"))?,
        None => Profile::default(),
    };
    if let Some(d) = &a.domain {
        p.account.domain = d.clone();
    }
    if let Some(u) = &a.user {
        p.account.user = u.clone();
    }
    if a.auth_user.is_some() {
        p.account.auth_user = a.auth_user.clone();
    }
    if a.password.is_some() {
        p.account.password = a.password.clone();
    }
    if a.outbound_proxy.is_some() {
        p.account.outbound_proxy = a.outbound_proxy.clone();
    }
    if let Some(lp) = a.local_port {
        p.behavior.local_port = lp;
    }
    let ua = Ua::new(p, Tap::new()).map_err(|e| anyhow!("{e}"))?;
    eprintln!("local SIP address {} -> server {}", ua.local, ua.server);
    Ok(ua)
}

fn finish_ua(ua: &Ua, a: &UaArgs) -> Result<()> {
    for e in &ua.events {
        eprintln!("  {:>6} ms  {}", e.t_ms, e.text);
    }
    let pcap = ua.tap.to_pcapng();
    if let Some(p) = &a.pcap {
        std::fs::write(p, &pcap)?;
        eprintln!(
            "capture written to {} ({} packets)",
            p.display(),
            ua.tap.len()
        );
    }
    if a.analyze {
        let r = analyze_bytes(&pcap).map_err(|e| anyhow!("{e}"))?;
        println!();
        print!("{}", report_text(&r, None, true));
    }
    Ok(())
}

fn audio_source(a: Audio, wav: &Option<PathBuf>) -> Result<AudioSource> {
    Ok(match a {
        Audio::Silence => AudioSource::Silence,
        Audio::Tone => AudioSource::Tone(440.0),
        Audio::Echo => AudioSource::Echo,
        Audio::Wav => {
            let p = wav
                .as_ref()
                .ok_or_else(|| anyhow!("--wav-in is required with --audio wav"))?;
            let s = sidetone_ua::media::read_wav_8k(&std::fs::read(p)?).map_err(|e| anyhow!(e))?;
            AudioSource::Samples(std::sync::Arc::new(s))
        }
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Analyze {
            file,
            call,
            json,
            ladder,
            svg,
        } => {
            let r = load(&file)?;
            let c = pick_call(&r, &call)?;
            if json {
                println!("{}", r.to_json_pretty());
            } else {
                print!("{}", report_text(&r, c, ladder));
            }
            if let Some(out) = svg {
                std::fs::write(
                    &out,
                    render_svg(
                        &r,
                        &LadderOptions {
                            call: c,
                            ..Default::default()
                        },
                    ),
                )?;
                eprintln!("ladder written to {}", out.display());
            }
        }
        Cmd::Export {
            file,
            out,
            call,
            redact,
            sip_only,
            no_annotate,
        } => {
            let r = load(&file)?;
            let c = pick_call(&r, &call)?;
            let bytes = export_pcapng(
                &r,
                &ExportOptions {
                    annotate: !no_annotate,
                    redact: if redact {
                        Some(RedactOptions::default())
                    } else {
                        None
                    },
                    call: c,
                    sip_only,
                },
            );
            std::fs::write(&out, bytes)?;
            eprintln!("written {}", out.display());
        }
        Cmd::Ai {
            file,
            call,
            ai,
            question,
            dry_run,
        } => {
            let r = load(&file)?;
            let c = pick_call(&r, &call)?;
            let cfg = ai.config()?;
            let prompt =
                sidetone_core::ai::build_prompt(&r, c, cfg.redact.as_ref(), question.as_deref());
            if dry_run {
                println!(
                    "{}\n\n{}",
                    sidetone_core::ai::system_prompt(&cfg.language),
                    prompt
                );
                return Ok(());
            }
            let text = aihttp::ask(&cfg, &prompt)?;
            println!("{text}");
        }
        Cmd::Config { action } => match action {
            ConfigCmd::Export { out, secrets } => {
                let v = sidetone_cli::phone::export_config(secrets)?;
                let text = serde_json::to_string_pretty(&v)?;
                match out {
                    Some(p) => {
                        std::fs::write(&p, text)?;
                        eprintln!("wrote {}", p.display());
                    }
                    None => println!("{text}"),
                }
            }
            ConfigCmd::Import { file, merge } => {
                let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&file)?)?;
                let n = sidetone_cli::phone::import_config(&v, merge)?;
                eprintln!(
                    "imported {n} account(s){}",
                    if merge { " (merged)" } else { "" }
                );
            }
        },
        Cmd::Samples { dir } => {
            std::fs::create_dir_all(&dir)?;
            for (name, desc) in sidetone_core::synth::SCENARIOS {
                let bytes = sidetone_core::synth::generate(name).unwrap();
                let p = dir.join(format!("{name}.pcapng"));
                std::fs::write(&p, bytes)?;
                println!("{:<40} {desc}", p.display());
            }
        }
        Cmd::Profile => println!("{}", serde_json::to_string_pretty(&Profile::default())?),
        Cmd::Register { ua, unregister } => {
            let mut u = build_ua(&ua)?;
            let st = u.register(None).map_err(|e| anyhow!("{e}"))?;
            println!(
                "REGISTER result: {}",
                st.map(|s| s.to_string())
                    .unwrap_or_else(|| "no response".into())
            );
            if unregister {
                let st = u.register(Some(0)).map_err(|e| anyhow!("{e}"))?;
                println!(
                    "un-REGISTER result: {}",
                    st.map(|s| s.to_string())
                        .unwrap_or_else(|| "no response".into())
                );
            }
            finish_ua(&u, &ua)?;
        }
        Cmd::Options { target, ua } => {
            let mut u = build_ua(&ua)?;
            match u.options(&target).map_err(|e| anyhow!("{e}"))? {
                Some((st, ms)) => println!("OPTIONS {target}: {st} in {ms} ms"),
                None => println!("OPTIONS {target}: no response"),
            }
            finish_ua(&u, &ua)?;
        }
        Cmd::Call {
            target,
            ua,
            duration,
            ring_timeout,
            audio,
            wav_in,
            dtmf,
            register,
            wav,
        } => {
            let mut u = build_ua(&ua)?;
            if register {
                let st = u.register(None).map_err(|e| anyhow!("{e}"))?;
                eprintln!(
                    "REGISTER: {}",
                    st.map(|s| s.to_string())
                        .unwrap_or_else(|| "no response".into())
                );
            }
            let opts = CallOptions {
                target,
                duration: Duration::from_secs(duration),
                ring_timeout: Duration::from_secs(ring_timeout),
                audio: audio_source(audio, &wav_in)?,
                dtmf,
            };
            let out = u.call(&opts).map_err(|e| anyhow!("{e}"))?;
            println!("{}", serde_json::to_string_pretty(&out)?);
            if let (Some(p), Some(w)) = (&wav, &out.wav) {
                std::fs::write(p, w)?;
                eprintln!(
                    "recording written to {} (left sent, right received)",
                    p.display()
                );
            }
            finish_ua(&u, &ua)?;
        }
        Cmd::Answer {
            ua,
            calls,
            wait,
            duration,
            audio,
            register,
        } => {
            let mut u = build_ua(&ua)?;
            if register {
                let st = u.register(None).map_err(|e| anyhow!("{e}"))?;
                eprintln!(
                    "REGISTER: {}",
                    st.map(|s| s.to_string())
                        .unwrap_or_else(|| "no response".into())
                );
            }
            eprintln!("waiting for calls on {}", u.local);
            let res = u
                .answer(
                    calls,
                    Duration::from_secs(wait),
                    Duration::from_secs(duration),
                    audio_source(audio, &None)?,
                )
                .map_err(|e| anyhow!("{e}"))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
            finish_ua(&u, &ua)?;
        }
        Cmd::Test {
            suite,
            out,
            junit,
            only,
            ai_explain,
            ai,
        } => {
            let cfg = if ai_explain { Some(ai.config()?) } else { None };
            let ok = testrun::run_suite(&suite, &out, junit, only.as_deref(), cfg.as_ref())?;
            if !ok {
                std::process::exit(1);
            }
        }
        Cmd::TestGen {
            description,
            out,
            context,
            ai,
        } => {
            let json = testrun::generate_suite(&ai.config()?, &description, context.as_deref())?;
            std::fs::write(&out, &json)?;
            println!(
                "{json}\n\nsuite written to {} (review it, then: sidetone test {})",
                out.display(),
                out.display()
            );
        }
        Cmd::TestFormat => println!("{}", testrun::SUITE_FORMAT),
        Cmd::Mcp => mcp::run()?,
        Cmd::Serve {
            listen,
            web,
            no_token,
        } => serve::run(&listen, web, !no_token)?,
    }
    Ok(())
}
