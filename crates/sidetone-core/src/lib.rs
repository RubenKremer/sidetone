//! Sidetone core: everything that does not touch the network or audio
//! devices, so it runs natively, inside the desktop app and in WASM.

pub mod ai;
pub mod analysis;
pub mod audio;
pub mod export;
pub mod ladder;
pub mod net;
pub mod pcap;
pub mod provision;
pub mod redact;
pub mod rtcp;
pub mod rtp;
pub mod rules;
pub mod sdp;
pub mod sip;
pub mod synth;

pub use analysis::{
    analyze_bytes, analyze_capture, Call, CallState, Finding, Message, Report, Severity,
};
