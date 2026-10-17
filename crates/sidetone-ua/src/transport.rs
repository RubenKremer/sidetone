//! SIP transports for the phone engine: UDP datagrams, or one persistent
//! TCP or TLS connection to the server (RFC 3261 section 18, RFC 5626 style
//! reuse: requests from the server come back on the same connection).

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Udp,
    Tcp,
    Tls,
}

impl Kind {
    pub fn parse(s: &str) -> Kind {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Kind::Tcp,
            "tls" => Kind::Tls,
            _ => Kind::Udp,
        }
    }
    /// Name in the Via header.
    pub fn via(self) -> &'static str {
        match self {
            Kind::Udp => "UDP",
            Kind::Tcp => "TCP",
            Kind::Tls => "TLS",
        }
    }
    pub fn reliable(self) -> bool {
        self != Kind::Udp
    }
    pub fn default_port(self) -> u16 {
        if self == Kind::Tls {
            5061
        } else {
            5060
        }
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

struct Conn {
    io: Arc<Mutex<Box<dyn Stream>>>,
    rx: Receiver<Vec<u8>>,
    alive: Arc<AtomicBool>,
    peer: SocketAddr,
}

/// A SIP socket: UDP, or a TCP/TLS connection to one peer.
pub struct Sock {
    pub kind: Kind,
    udp: Option<UdpSocket>,
    conn: Option<Conn>,
    pub local: SocketAddr,
    /// TLS certificate summary (subject and issuer) for diagnostics.
    pub tls_info: Option<String>,
}

impl Sock {
    pub fn udp(s: UdpSocket) -> std::io::Result<Sock> {
        s.set_nonblocking(true)?;
        let local = s.local_addr()?;
        Ok(Sock {
            kind: Kind::Udp,
            udp: Some(s),
            conn: None,
            local,
            tls_info: None,
        })
    }

    /// Connects to `peer` over TCP or TLS. `sni` is the server name for TLS;
    /// `verify` checks the certificate against the system's public roots.
    pub fn connect(kind: Kind, peer: SocketAddr, sni: &str, verify: bool) -> Result<Sock, String> {
        let tcp = TcpStream::connect_timeout(&peer, Duration::from_secs(5))
            .map_err(|e| format!("cannot connect to {peer}: {e}"))?;
        tcp.set_nodelay(true).ok();
        let local = tcp.local_addr().map_err(|e| e.to_string())?;
        if kind == Kind::Tcp {
            // The reader polls with a short timeout so writers can take the lock.
            tcp.set_read_timeout(Some(Duration::from_millis(20))).ok();
        }
        let mut tls_info = None;
        let stream: Box<dyn Stream> = match kind {
            Kind::Tls => {
                let cfg = tls_config(verify);
                let name = ServerName::try_from(sni.to_string())
                    .or_else(|_| ServerName::try_from(peer.ip().to_string()))
                    .map_err(|e| format!("bad TLS server name {sni}: {e}"))?;
                let conn = rustls::ClientConnection::new(Arc::new(cfg), name)
                    .map_err(|e| e.to_string())?;
                let mut s = rustls::StreamOwned::new(conn, tcp);
                tcp_ref(&s)
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .ok();
                // Complete the handshake now so certificate errors show up here.
                while s.conn.is_handshaking() {
                    s.conn
                        .complete_io(&mut s.sock)
                        .map_err(|e| format!("TLS handshake with {peer} failed: {e}"))?;
                }
                if let Some(certs) = s.conn.peer_certificates() {
                    tls_info = Some(cert_summary(certs.first()));
                }
                s.sock
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .ok();
                Box::new(s)
            }
            _ => Box::new(tcp.try_clone().map_err(|e| e.to_string())?),
        };
        let io: Arc<Mutex<Box<dyn Stream>>> = Arc::new(Mutex::new(stream));
        let (tx, rx) = channel();
        let alive = Arc::new(AtomicBool::new(true));
        {
            let io = io.clone();
            let alive = alive.clone();
            thread::Builder::new()
                .name("sidetone-sip-stream".into())
                .spawn(move || {
                    let mut acc: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 16384];
                    while alive.load(Ordering::Relaxed) {
                        let r = {
                            let mut g = io.lock().unwrap();
                            g.read(&mut buf)
                        };
                        match r {
                            Ok(0) => break,
                            Ok(n) => {
                                acc.extend_from_slice(&buf[..n]);
                                let (msgs, used) = sidetone_core::sip::parse_stream(&acc);
                                for m in msgs {
                                    if tx.send(m.raw.into_bytes()).is_err() {
                                        return;
                                    }
                                }
                                acc.drain(..used);
                            }
                            Err(e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                thread::sleep(Duration::from_millis(2));
                            }
                            Err(_) => break,
                        }
                    }
                    alive.store(false, Ordering::Relaxed);
                })
                .map_err(|e| e.to_string())?;
        }
        Ok(Sock {
            kind,
            udp: None,
            conn: Some(Conn {
                io,
                rx,
                alive,
                peer,
            }),
            local,
            tls_info,
        })
    }

    /// Sends one message. Streams ignore `dest`: everything goes to the peer.
    pub fn send_to(&self, data: &[u8], dest: SocketAddr) -> std::io::Result<SocketAddr> {
        if let Some(u) = &self.udp {
            u.send_to(data, dest)?;
            return Ok(dest);
        }
        let c = self.conn.as_ref().expect("socket");
        let mut g = c.io.lock().unwrap();
        g.write_all(data)?;
        g.flush()?;
        Ok(c.peer)
    }

    /// Next received message or datagram, without blocking.
    pub fn try_recv(&self, buf: &mut [u8]) -> Option<(Vec<u8>, SocketAddr)> {
        if let Some(u) = &self.udp {
            return u.recv_from(buf).ok().map(|(n, f)| (buf[..n].to_vec(), f));
        }
        let c = self.conn.as_ref()?;
        c.rx.try_recv().ok().map(|m| (m, c.peer))
    }

    /// False once a stream connection has closed.
    pub fn alive(&self) -> bool {
        self.conn
            .as_ref()
            .map(|c| c.alive.load(Ordering::Relaxed))
            .unwrap_or(true)
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        self.conn.as_ref().map(|c| c.peer)
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        if let Some(c) = &self.conn {
            c.alive.store(false, Ordering::Relaxed);
        }
    }
}

fn tcp_ref(s: &rustls::StreamOwned<rustls::ClientConnection, TcpStream>) -> &TcpStream {
    &s.sock
}

fn cert_summary(c: Option<&CertificateDer<'_>>) -> String {
    match c {
        Some(c) => format!("server certificate, {} bytes", c.len()),
        None => "no certificate".into(),
    }
}

fn tls_config(verify: bool) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("TLS versions");
    if verify {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    }
}

/// Accepts any certificate: for labs and PBXs with self-signed certificates,
/// chosen explicitly per account.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
