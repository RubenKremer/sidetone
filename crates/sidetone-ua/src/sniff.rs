//! Passive capture of other hosts' traffic on a network interface.
//!
//! libpcap (Linux, macOS) or Npcap (Windows) is loaded at run time, so the
//! application starts and works without it; only this feature needs it.
//! Capturing usually needs privileges: root or CAP_NET_RAW on Linux, access
//! to /dev/bpf* on macOS (Wireshark's ChmodBPF), Npcap installed on Windows.

use libloading::Library;
use serde::Serialize;
use sidetone_core::net::{self, Transport};
use sidetone_core::pcap::{write_pcapng, OutPacket, PcapngOptions};
use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut PcapAddr,
    flags: c_uint,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *mut SockAddr,
    netmask: *mut SockAddr,
    broadaddr: *mut SockAddr,
    dstaddr: *mut SockAddr,
}

/// Enough of struct sockaddr to read IPv4 and IPv6 addresses. BSDs put a
/// length byte before a one-byte family; Linux and Windows use a u16 family.
#[repr(C)]
struct SockAddr {
    head: [u8; 2],
    data: [u8; 26],
}

#[repr(C)]
struct BpfProgram {
    len: c_uint,
    insns: *mut c_void,
}

/// struct pcap_pkthdr: a timeval, then caplen and len. `long` seconds and
/// microseconds that fit in 32 bits, padded to 8 bytes outside Windows.
#[repr(C)]
struct PktHdr {
    sec: c_long,
    usec: i32,
    #[cfg(not(windows))]
    _pad: i32,
    caplen: u32,
    len: u32,
}

type FindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type OpenLive =
    unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
type Datalink = unsafe extern "C" fn(*mut c_void) -> c_int;
type Compile =
    unsafe extern "C" fn(*mut c_void, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type SetFilter = unsafe extern "C" fn(*mut c_void, *mut BpfProgram) -> c_int;
type FreeCode = unsafe extern "C" fn(*mut BpfProgram);
type NextEx = unsafe extern "C" fn(*mut c_void, *mut *mut PktHdr, *mut *const u8) -> c_int;
type GetErr = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type Close = unsafe extern "C" fn(*mut c_void);
type LibVersion = unsafe extern "C" fn() -> *const c_char;

struct Pcap {
    _lib: Library,
    findalldevs: FindAllDevs,
    freealldevs: FreeAllDevs,
    open_live: OpenLive,
    datalink: Datalink,
    compile: Compile,
    setfilter: SetFilter,
    freecode: FreeCode,
    next_ex: NextEx,
    geterr: GetErr,
    close: Close,
    version: String,
}

// The function pointers are plain C entry points; libpcap handles are only
// used from the thread that owns them.
unsafe impl Send for Pcap {}
unsafe impl Sync for Pcap {}

fn candidates() -> Vec<String> {
    if cfg!(windows) {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        vec![
            format!("{sys}\\System32\\Npcap\\wpcap.dll"),
            "wpcap.dll".into(),
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            "/usr/lib/libpcap.A.dylib".into(),
            "libpcap.A.dylib".into(),
            "libpcap.dylib".into(),
        ]
    } else {
        vec![
            "libpcap.so.1".into(),
            "libpcap.so.0.8".into(),
            "libpcap.so".into(),
        ]
    }
}

fn open_library(path: &str) -> Result<Library, libloading::Error> {
    #[cfg(windows)]
    {
        // wpcap.dll finds Packet.dll next to it only with an altered search path.
        const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x8;
        unsafe {
            libloading::os::windows::Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH)
                .map(Library::from)
        }
    }
    #[cfg(not(windows))]
    unsafe {
        Library::new(path)
    }
}

fn load() -> Result<&'static Pcap, String> {
    static PCAP: OnceLock<Result<Pcap, String>> = OnceLock::new();
    PCAP.get_or_init(|| {
        let mut errors = Vec::new();
        for c in candidates() {
            match open_library(&c) {
                Ok(lib) => unsafe {
                    macro_rules! sym {
                        ($n:literal) => {
                            *lib.get(concat!($n, "\0").as_bytes())
                                .map_err(|e| format!("{c}: missing {}: {e}", $n))?
                        };
                    }
                    let version: LibVersion = sym!("pcap_lib_version");
                    let p = Pcap {
                        findalldevs: sym!("pcap_findalldevs"),
                        freealldevs: sym!("pcap_freealldevs"),
                        open_live: sym!("pcap_open_live"),
                        datalink: sym!("pcap_datalink"),
                        compile: sym!("pcap_compile"),
                        setfilter: sym!("pcap_setfilter"),
                        freecode: sym!("pcap_freecode"),
                        next_ex: sym!("pcap_next_ex"),
                        geterr: sym!("pcap_geterr"),
                        close: sym!("pcap_close"),
                        version: CStr::from_ptr(version()).to_string_lossy().into_owned(),
                        _lib: lib,
                    };
                    return Ok(p);
                },
                Err(e) => errors.push(format!("{c}: {e}")),
            }
        }
        Err(format!(
            "no packet capture library found ({}). {}",
            errors.join("; "),
            if cfg!(windows) {
                "Install Npcap from npcap.com (Wireshark installs it too)."
            } else if cfg!(target_os = "macos") {
                "macOS ships libpcap; this should not happen."
            } else {
                "Install libpcap (Debian/Ubuntu: apt install libpcap0.8, Fedora: dnf install libpcap)."
            }
        ))
    })
    .as_ref()
    .map_err(|e| e.clone())
}

#[derive(Debug, Clone, Serialize)]
pub struct Iface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
    pub up: bool,
}

/// Interfaces libpcap can open, or why capture is not available.
pub fn interfaces() -> Result<(Vec<Iface>, String), String> {
    let p = load()?;
    let mut err = [0 as c_char; 512];
    let mut list: *mut PcapIf = std::ptr::null_mut();
    unsafe {
        if (p.findalldevs)(&mut list, err.as_mut_ptr()) != 0 {
            return Err(CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned());
        }
        let mut out = Vec::new();
        let mut cur = list;
        while !cur.is_null() {
            let i = &*cur;
            let name = CStr::from_ptr(i.name).to_string_lossy().into_owned();
            let description = (!i.description.is_null())
                .then(|| CStr::from_ptr(i.description).to_string_lossy().into_owned());
            let mut addresses = Vec::new();
            let mut a = i.addresses;
            while !a.is_null() {
                if let Some(s) = sockaddr_ip((*a).addr) {
                    addresses.push(s);
                }
                a = (*a).next;
            }
            out.push(Iface {
                name,
                description,
                addresses,
                loopback: i.flags & 0x1 != 0,
                up: i.flags & 0x2 != 0 || i.flags == 0,
            });
            cur = i.next;
        }
        (p.freealldevs)(list);
        Ok((out, p.version.clone()))
    }
}

unsafe fn sockaddr_ip(sa: *mut SockAddr) -> Option<String> {
    if sa.is_null() {
        return None;
    }
    let s = &*sa;
    // AF_INET is 2 everywhere; AF_INET6 is 10 (Linux), 23 (Windows), 30 (macOS).
    let bsd = cfg!(any(target_os = "macos", target_os = "freebsd"));
    let fam = if bsd {
        s.head[1] as u16
    } else {
        u16::from_ne_bytes(s.head)
    };
    match fam {
        2 => Some(std::net::Ipv4Addr::new(s.data[2], s.data[3], s.data[4], s.data[5]).to_string()),
        10 | 23 | 30 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&s.data[6..22]);
            Some(std::net::Ipv6Addr::from(b).to_string())
        }
        _ => None,
    }
}

/// One SIP message seen on the wire, for the live list.
#[derive(Debug, Clone, Serialize)]
pub struct SeenSip {
    pub seq: u64,
    pub ts_ms: i64,
    pub transport: String,
    pub src: String,
    pub dst: String,
    pub first_line: String,
    pub call_id: String,
    pub cseq: String,
    pub status: Option<u16>,
    pub size: usize,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SniffStatus {
    pub running: bool,
    pub iface: Option<String>,
    pub filter: Option<String>,
    pub linktype: Option<u32>,
    pub packets: u64,
    pub bytes: u64,
    pub sip: u64,
    pub rtp: u64,
    pub kept: usize,
    pub error: Option<String>,
    pub started_ms: Option<i64>,
}

struct Shared {
    status: SniffStatus,
    packets: Vec<(i64, Vec<u8>)>,
    sip: Vec<SeenSip>,
}

/// Packets kept per capture before the oldest are dropped.
const KEEP: usize = 1_000_000;
const KEEP_SIP: usize = 5_000;

/// A running (or finished) interface capture.
pub struct Sniffer {
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Default for Sniffer {
    fn default() -> Self {
        Sniffer {
            shared: Arc::new(Mutex::new(Shared {
                status: SniffStatus::default(),
                packets: Vec::new(),
                sip: Vec::new(),
            })),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Sniffer {
    /// Opens `iface` and starts capturing with a BPF `filter` (may be empty).
    pub fn start(&mut self, iface: &str, filter: &str) -> Result<(), String> {
        self.stop_capture();
        let p = load()?;
        let dev = CString::new(iface).map_err(|_| "bad interface name".to_string())?;
        let mut err = [0 as c_char; 512];
        let h = unsafe { (p.open_live)(dev.as_ptr(), 65535, 1, 200, err.as_mut_ptr()) };
        if h.is_null() {
            let e = unsafe { CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned() };
            return Err(explain_open_error(iface, &e));
        }
        let linktype = unsafe { (p.datalink)(h) } as u32;
        if !filter.trim().is_empty() {
            let f = CString::new(filter.trim()).map_err(|_| "bad filter".to_string())?;
            let mut prog = BpfProgram {
                len: 0,
                insns: std::ptr::null_mut(),
            };
            unsafe {
                if (p.compile)(h, &mut prog, f.as_ptr(), 1, 0xffff_ffff) != 0 {
                    let e = CStr::from_ptr((p.geterr)(h)).to_string_lossy().into_owned();
                    (p.close)(h);
                    return Err(format!("filter \"{}\": {e}", filter.trim()));
                }
                let r = (p.setfilter)(h, &mut prog);
                (p.freecode)(&mut prog);
                if r != 0 {
                    let e = CStr::from_ptr((p.geterr)(h)).to_string_lossy().into_owned();
                    (p.close)(h);
                    return Err(format!("cannot apply the filter: {e}"));
                }
            }
        }
        {
            let mut s = self.shared.lock().unwrap();
            s.packets.clear();
            s.sip.clear();
            s.status = SniffStatus {
                running: true,
                iface: Some(iface.to_string()),
                filter: Some(filter.trim().to_string()).filter(|f| !f.is_empty()),
                linktype: Some(linktype),
                started_ms: Some(now_ms()),
                ..Default::default()
            };
        }
        self.stop = Arc::new(AtomicBool::new(false));
        let stop = self.stop.clone();
        let shared = self.shared.clone();
        let handle = h as usize;
        self.thread = Some(
            std::thread::Builder::new()
                .name("sidetone-sniff".into())
                .spawn(move || capture_loop(p, handle as *mut c_void, linktype, stop, shared))
                .map_err(|e| e.to_string())?,
        );
        Ok(())
    }

    pub fn stop_capture(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    pub fn status(&self) -> SniffStatus {
        self.shared.lock().unwrap().status.clone()
    }

    /// SIP messages seen after `since` (their seq numbers).
    pub fn sip_since(&self, since: u64, max: usize) -> Vec<SeenSip> {
        let s = self.shared.lock().unwrap();
        s.sip
            .iter()
            .filter(|m| m.seq > since)
            .take(max)
            .cloned()
            .collect()
    }

    pub fn to_pcapng(&self) -> Vec<u8> {
        let s = self.shared.lock().unwrap();
        let lt = s.status.linktype.unwrap_or(1);
        let out: Vec<OutPacket<'_>> = s
            .packets
            .iter()
            .map(|(t, d)| OutPacket {
                ts_ns: *t,
                linktype: lt,
                data: d,
                orig_len: d.len() as u32,
                comment: None,
            })
            .collect();
        write_pcapng(
            &out,
            &PcapngOptions {
                user_appl: Some(format!(
                    "Sidetone {} interface capture{}",
                    env!("CARGO_PKG_VERSION"),
                    s.status
                        .iface
                        .as_ref()
                        .map(|i| format!(" on {i}"))
                        .unwrap_or_default()
                )),
                ..Default::default()
            },
        )
    }
}

impl Drop for Sniffer {
    fn drop(&mut self) {
        self.stop_capture();
    }
}

fn explain_open_error(iface: &str, e: &str) -> String {
    let low = e.to_ascii_lowercase();
    let hint = if low.contains("permission") || low.contains("operation not permitted") {
        if cfg!(target_os = "linux") {
            " Capturing needs root or the CAP_NET_RAW capability: run sudo setcap cap_net_raw,cap_net_admin=eip on the Sidetone binary, or start it with sudo."
        } else if cfg!(target_os = "macos") {
            " Capturing needs read access to /dev/bpf*: install Wireshark's ChmodBPF (it adds you to the access_bpf group) or start Sidetone with sudo."
        } else {
            " Run Sidetone as administrator, or reinstall Npcap without the \"Restrict Npcap driver's access to Administrators only\" option."
        }
    } else {
        ""
    };
    format!("cannot open {iface}: {e}.{hint}")
}

fn capture_loop(
    p: &'static Pcap,
    h: *mut c_void,
    linktype: u32,
    stop: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
) {
    let mut seq = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let mut hdr: *mut PktHdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        let r = unsafe { (p.next_ex)(h, &mut hdr, &mut data) };
        match r {
            1 => {}
            0 => continue,
            _ => {
                let e = unsafe { CStr::from_ptr((p.geterr)(h)).to_string_lossy().into_owned() };
                let mut s = shared.lock().unwrap();
                s.status.error = Some(if r == -2 { "capture ended".into() } else { e });
                break;
            }
        }
        let (ts_ns, bytes, len) = unsafe {
            let hd = &*hdr;
            let ts = hd.sec as i64 * 1_000_000_000 + hd.usec as i64 * 1000;
            (
                ts,
                std::slice::from_raw_parts(data, hd.caplen as usize).to_vec(),
                hd.len,
            )
        };
        let mut sip_item = None;
        let mut is_rtp = false;
        if let Some(d) = net::decode(linktype, &bytes) {
            if sidetone_core::sip::looks_like_sip(d.payload) {
                let (msgs, _) = sidetone_core::sip::parse_stream(d.payload);
                let m = msgs
                    .into_iter()
                    .next()
                    .or_else(|| sidetone_core::sip::parse_datagram(d.payload));
                if let Some(m) = m {
                    seq += 1;
                    let raw = String::from_utf8_lossy(d.payload).into_owned();
                    sip_item = Some(SeenSip {
                        seq,
                        ts_ms: ts_ns / 1_000_000,
                        transport: match d.transport {
                            Transport::Udp => "UDP",
                            Transport::Tcp => "TCP",
                            Transport::Tls => "TLS",
                        }
                        .into(),
                        src: d.src.to_string(),
                        dst: d.dst.to_string(),
                        first_line: raw.lines().next().unwrap_or("").to_string(),
                        call_id: m.call_id().unwrap_or("").to_string(),
                        cseq: m.header("CSeq").unwrap_or("").to_string(),
                        status: m.status(),
                        size: d.payload.len(),
                        raw,
                    });
                }
            } else if d.transport == Transport::Udp
                && sidetone_core::rtp::parse_rtp(d.payload).is_some()
            {
                is_rtp = true;
            }
        }
        let mut s = shared.lock().unwrap();
        s.status.packets += 1;
        s.status.bytes += len as u64;
        if is_rtp {
            s.status.rtp += 1;
        }
        if let Some(m) = sip_item {
            s.status.sip += 1;
            if s.sip.len() >= KEEP_SIP {
                s.sip.drain(..KEEP_SIP / 10);
            }
            s.sip.push(m);
        }
        if s.packets.len() >= KEEP {
            s.packets.drain(..KEEP / 10);
        }
        s.packets.push((ts_ns, bytes));
        s.status.kept = s.packets.len();
    }
    unsafe { (p.close)(h) };
    let mut s = shared.lock().unwrap();
    s.status.running = false;
}

/// The capture shared by the local server.
pub fn global() -> &'static Mutex<Sniffer> {
    static S: OnceLock<Mutex<Sniffer>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Sniffer::default()))
}
