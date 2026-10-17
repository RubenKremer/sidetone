# Sidetone

SIP softphone and call analyzer for troubleshooting. It places and answers test calls, reads pcap/pcapng captures, draws the ladder, measures RTP quality, explains what went wrong with deterministic rules, and can hand the evidence to any AI model for a second opinion.

Sidetone runs as:

- a **desktop app** for Linux, Windows and macOS (Tauri),
- a **web app** that analyzes captures entirely in the browser (WebAssembly) and includes a WebRTC web phone, publishable on GitHub Pages,
- a **command line tool** with test automation, JUnit output and an **MCP server** so AI agents can analyze captures and run calls themselves.

## What it finds

Every capture goes through the same rule engine (Rust, no AI involved). Findings cite message numbers and are written as explanations, not codes. Examples:

| Area | Rules |
|---|---|
| Call outcome | no response to INVITE, failure codes with meaning, CANCEL/487, post-dial delay, slow first response |
| Dialog integrity | 200 OK retransmitted (ACK not arriving), missing ACK, drop at ~32 s, 481 to in-dialog requests, session timer expiry |
| NAT | private address in SDP or Contact behind a public source, asymmetric RTP, wrong interface on unanswered REGISTER |
| SDP | no common codec, answer with codecs that were not offered, SRTP vs RTP, missing crypto/fingerprint, DTLS role conflict, DTMF not negotiated, ptime mismatch, hold |
| Media | one-way audio, no RTP, loss, jitter (RFC 3550), gaps, SSRC changes, unnegotiated payload types, MOS estimate (ITU-T G.107 E-model), RFC 4733 digits |
| Hygiene | missing mandatory headers, Content-Length errors, Max-Forwards close to zero, Reason headers with Q.850 causes |

## Quick start

```bash
# Build
cargo build --release -p sidetone-cli

# Try the built-in captures (each has a known problem)
./target/release/sidetone samples ./samples
./target/release/sidetone analyze samples/nat-one-way.pcapng --ladder

# Web UI on this machine (analysis, test calls, AI proxy)
./target/release/sidetone serve
```

### Analyze and share

```bash
sidetone analyze trace.pcapng --call 3 --svg call3.svg
sidetone export trace.pcapng -o annotated.pcapng            # findings become Wireshark packet comments
sidetone export trace.pcapng -o share.pcapng --call 3 --redact  # numbers, names, credentials and public IPs masked
```

Exported pcapng files keep TLS key logs in a Decryption Secrets Block when the source had one, so Wireshark decrypts SIP over TLS on open. Redacted exports never carry keys.

### Test calls

```bash
sidetone profile > my.json                    # every behavior knob, edit as needed
sidetone call 600 --domain pbx.lab:5060 --user 2001 --password '...' --register \
  --dtmf 123# --pcap call.pcapng --wav call.wav
sidetone answer --domain pbx.lab --user 3001 --password '...' --register --audio echo
sidetone options pbx.lab
```

The local IP is chosen by the route to the server, so the softphone does not end up advertising a VPN or virtual adapter address. Every packet sent and received is recorded in-process (no capture driver or privileges) and analyzed when the call ends. The WAV is stereo: left is what was sent, right what was received.

Behavior profiles reproduce problem clients on purpose: T1 timer, Max-Forwards, session timers, `user=phone`, compact headers, PRACK required, GRUU, long Contact with `+sip.instance`, `rport`, codec order and ptime, DTMF as RFC 4733 or SIP INFO, symmetric RTP, DSCP marking, outbound proxy, extra headers, and deliberate faults such as skipping the ACK or advertising a fake SDP address.

### Test automation

```bash
sidetone test-format                                    # suite reference
SIP_PASSWORD=... sidetone test examples/asterisk-lab.suite.json --junit junit.xml
sidetone test suite.json --ai-explain                   # failed cases get an AI explanation
sidetone test-gen "register 2001 on pbx.lab and check echo 600 with DTMF and MOS above 4" -o new.suite.json
```

A suite is JSON: cases made of `register`, `options`, `call`, `wait` and `unregister` steps, each with expectations (final status, maximum errors, minimum MOS, loss, jitter, post-dial delay, talk time, codec, RTP received, rules that must or must not appear). Each case saves its pcapng. `test-gen` asks the model to write the suite and validates it before saving.

### AI

```bash
export ANTHROPIC_API_KEY=...
sidetone ai trace.pcapng --call 2 --lang "Portuguese (Brazil)"
sidetone ai trace.pcapng --provider ollama --model llama3.1
sidetone ai trace.pcapng --provider openai --model <model> --base-url https://your-gateway
sidetone ai trace.pcapng --dry-run                       # print exactly what would be sent
```

The model receives the deterministic findings, the ladder, RTP statistics and the relevant raw messages, with redaction on by default. It is asked to explain, not to detect, which keeps answers grounded and cheap.

### MCP server

```json
{
  "mcpServers": {
    "sidetone": { "command": "/path/to/sidetone", "args": ["mcp"] }
  }
}
```

Tools: `analyze_capture`, `get_ladder`, `get_message`, `get_call_context`, `export_pcapng`, `generate_sample`, `sip_options`, `test_call`, `get_test_suite_format`, `run_test_suite`.

## Web app and web phone

`web/` is one frontend for every mode. Built with the WASM analyzer (see `.github/workflows/pages.yml`) it runs fully in the browser, so captures never leave the machine. The **Web phone** registers over SIP WebSocket (RFC 7118) and calls with WebRTC audio; when a call ends its signaling is converted to pcapng and analyzed, and the browser's `getStats()` numbers (loss, jitter, RTT, ICE path) appear next to it. On an HTTPS page the server must offer `wss://` with a valid certificate.

AI from the browser goes straight to the provider with the key you type (kept only in that browser). Ollama needs `OLLAMA_ORIGINS` to include the page origin.

## Desktop app

`app/src-tauri` starts the same local server on a random loopback port, protected by a per-launch token, and opens it in a native window. Installers are produced by `.github/workflows/release.yml` for Linux (deb, rpm, AppImage), Windows (MSI, NSIS) and macOS (dmg, Apple silicon and Intel). Unsigned macOS builds must be allowed in System Settings on first run; signing secrets are optional workflow inputs.

## Lab

`lab/run-asterisk.sh` starts a throwaway Asterisk with UDP, WebSocket and WebRTC endpoints, echo/busy/unallocated extensions and ring groups. CI uses it to run `examples/asterisk-lab.suite.json` on every push.

## Layout

```
crates/sidetone-core   capture I/O, SIP/SDP/RTP parsing, rules, ladder, export, redaction, AI prompt (no I/O, compiles to WASM)
crates/sidetone-ua     test user agent: REGISTER/INVITE/PRACK/ACK/BYE/CANCEL/INFO/UPDATE, G.711, RFC 4733, digest auth
crates/sidetone-cli    sidetone binary: analyze, export, ai, test, mcp, serve, call/answer/options
crates/sidetone-wasm   browser bindings
web/                   UI and web phone
app/src-tauri          desktop shell
lab/, examples/        Asterisk lab and test suites
```

## Current limits

- The test UA speaks SIP over UDP with G.711; TCP/TLS transport, SRTP and Opus in the native UA are next.
- Passive capture of other hosts' traffic (libpcap/Npcap) is not wired yet; import captures from Wireshark/tcpdump/sngrep or use HEP-capable tools meanwhile.
- DNS SRV/NAPTR resolution is not used by the UA yet (A/AAAA only).
- MOS is an estimate from one capture point.

## License

MIT
