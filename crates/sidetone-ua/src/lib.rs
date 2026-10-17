//! Sidetone test user agent: places and answers SIP calls with a configurable
//! behavior profile while recording every packet for analysis.

pub mod audio;
pub mod dns;
pub mod engine;
pub mod media;
pub mod profile;
pub mod sipmsg;
pub mod srtp;
pub mod stun;
pub mod tap;
pub mod transport;
pub mod ua;

pub use media::AudioSource;
pub use profile::{Account, Behavior, DtmfMode, Profile, SrtpMode};
pub use tap::Tap;
pub use ua::{CallOptions, CallOutcome, Ua, UaError};
