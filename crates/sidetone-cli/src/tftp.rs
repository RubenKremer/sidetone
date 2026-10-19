//! A TFTP client (RFC 1350) for provisioning files, with the block size and
//! transfer size options (RFC 2347/2348/2349) when the server offers them.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const RRQ: u16 = 1;
const DATA: u16 = 3;
const ACK: u16 = 4;
const ERROR: u16 = 5;
const OACK: u16 = 6;

/// Asks for a block size that fits a 1500-byte Ethernet frame.
const BLKSIZE: usize = 1432;

/// Splits `tftp://host[:port]/path` into the server and the file name.
pub fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("tftp://")
        .or_else(|| url.strip_prefix("TFTP://"))
        .ok_or("not a tftp:// URL")?;
    let (authority, path) = rest.split_once('/').ok_or("tftp URL has no file name")?;
    if path.is_empty() {
        return Err("tftp URL has no file name".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.starts_with('[') => (
            h.trim_matches(['[', ']']).to_string(),
            p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?,
        ),
        _ => (authority.trim_matches(['[', ']']).to_string(), 69),
    };
    if host.is_empty() {
        return Err("tftp URL has no host".into());
    }
    Ok((host, port, path.to_string()))
}

fn error_text(code: u16, msg: &str) -> String {
    let what = match code {
        1 => "File not found",
        2 => "Access violation",
        3 => "Disk full",
        4 => "Illegal TFTP operation",
        5 => "Unknown transfer ID",
        6 => "File already exists",
        7 => "No such user",
        8 => "Option negotiation refused",
        _ => "Not defined",
    };
    if msg.is_empty() || msg.eq_ignore_ascii_case(what) {
        format!("TFTP error {code} ({what})")
    } else {
        format!("TFTP error {code} ({what}): {msg}")
    }
}

/// Downloads `path` from a TFTP server, at most `max` bytes.
pub fn get(
    host: &str,
    port: u16,
    path: &str,
    max: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let server: SocketAddr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host}: no address"))?;
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;

    let mut rrq = RRQ.to_be_bytes().to_vec();
    for part in [path, "octet", "blksize", &BLKSIZE.to_string(), "tsize", "0"] {
        rrq.extend_from_slice(part.as_bytes());
        rrq.push(0);
    }

    let mut out: Vec<u8> = Vec::new();
    let mut blksize = 512usize;
    let mut expect: u16 = 1;
    let mut peer: Option<SocketAddr> = None;
    let mut last_sent = rrq.clone();
    let mut last_to = server;
    let mut tries = 0;
    let mut buf = vec![0u8; 65536];
    sock.send_to(&rrq, server).map_err(|e| e.to_string())?;
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => {
                tries += 1;
                if tries > 4 {
                    return Err(if peer.is_none() {
                        format!("no answer from the TFTP server {server}")
                    } else {
                        format!(
                            "the TFTP transfer from {server} stopped at {} bytes",
                            out.len()
                        )
                    });
                }
                sock.send_to(&last_sent, last_to)
                    .map_err(|e| e.to_string())?;
                continue;
            }
        };
        // The server answers from a new port (its transfer ID); keep to it.
        if from.ip() != server.ip() || peer.is_some_and(|p| p != from) {
            continue;
        }
        if n < 4 {
            continue;
        }
        tries = 0;
        let op = u16::from_be_bytes([buf[0], buf[1]]);
        let p = &buf[..n];
        match op {
            ERROR => {
                let code = u16::from_be_bytes([p[2], p[3]]);
                let msg = String::from_utf8_lossy(&p[4..])
                    .trim_end_matches('\0')
                    .to_string();
                return Err(error_text(code, &msg));
            }
            OACK => {
                peer = Some(from);
                let fields: Vec<String> = p[2..]
                    .split(|b| *b == 0)
                    .map(|x| String::from_utf8_lossy(x).to_ascii_lowercase())
                    .collect();
                for kv in fields.chunks(2) {
                    if kv.len() == 2 {
                        match kv[0].as_str() {
                            "blksize" => blksize = kv[1].parse().unwrap_or(512),
                            "tsize" => {
                                if kv[1].parse::<usize>().is_ok_and(|t| t > max) {
                                    return Err(format!(
                                        "the file is {} bytes, more than {max}",
                                        kv[1]
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                let ack = [0, ACK as u8, 0, 0];
                sock.send_to(&ack, from).map_err(|e| e.to_string())?;
                last_sent = ack.to_vec();
                last_to = from;
            }
            DATA => {
                peer = Some(from);
                let block = u16::from_be_bytes([p[2], p[3]]);
                let ack = [0, ACK as u8, p[2], p[3]];
                if block == expect {
                    out.extend_from_slice(&p[4..]);
                    if out.len() > max {
                        return Err(format!("the file is larger than {max} bytes"));
                    }
                    expect = expect.wrapping_add(1);
                    sock.send_to(&ack, from).map_err(|e| e.to_string())?;
                    last_sent = ack.to_vec();
                    last_to = from;
                    if p.len() - 4 < blksize {
                        return Ok(out);
                    }
                } else {
                    // A repeat of a block already taken: acknowledge it again.
                    sock.send_to(&ack, from).map_err(|e| e.to_string())?;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// A tiny TFTP server: one file, optional option support.
    fn serve(file: Vec<u8>, name: &'static str, options: bool) -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, client) = s.recv_from(&mut buf).unwrap();
            let parts: Vec<String> = buf[2..n]
                .split(|b| *b == 0)
                .map(|x| String::from_utf8_lossy(x).into())
                .collect();
            let t = UdpSocket::bind("127.0.0.1:0").unwrap();
            if parts[0] != name {
                let mut e = vec![0, 5, 0, 1];
                e.extend_from_slice(b"File not found\0");
                t.send_to(&e, client).unwrap();
                return;
            }
            let bs = if options {
                let mut o = vec![0, 6];
                o.extend_from_slice(b"blksize\x001432\x00tsize\x00");
                o.extend_from_slice(file.len().to_string().as_bytes());
                o.push(0);
                t.send_to(&o, client).unwrap();
                t.recv_from(&mut buf).unwrap();
                1432
            } else {
                512
            };
            let mut blk: u16 = 1;
            for chunk in file.chunks(bs).chain(if file.len() % bs == 0 {
                Some(&[][..])
            } else {
                None
            }) {
                let mut d = vec![0, 3];
                d.extend_from_slice(&blk.to_be_bytes());
                d.extend_from_slice(chunk);
                t.send_to(&d, client).unwrap();
                t.recv_from(&mut buf).unwrap();
                blk += 1;
            }
        });
        port
    }

    #[test]
    fn downloads_with_and_without_options() {
        let file: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        for opts in [true, false] {
            let port = serve(file.clone(), "SEP001122334455.cnf.xml", opts);
            let got = get(
                "127.0.0.1",
                port,
                "SEP001122334455.cnf.xml",
                1 << 20,
                Duration::from_secs(2),
            )
            .unwrap();
            assert_eq!(got, file);
        }
        // Exactly one block: an empty block ends it.
        let port = serve(vec![7u8; 512], "x.cfg", false);
        assert_eq!(
            get("127.0.0.1", port, "x.cfg", 1 << 20, Duration::from_secs(2))
                .unwrap()
                .len(),
            512
        );
    }

    #[test]
    fn reports_file_not_found() {
        let port = serve(vec![1], "a.cfg", false);
        let e = get("127.0.0.1", port, "b.cfg", 1 << 20, Duration::from_secs(2)).unwrap_err();
        assert!(e.contains("File not found"), "{e}");
    }

    #[test]
    fn urls() {
        assert_eq!(
            parse_url("tftp://10.0.0.5/SEP1.cnf.xml").unwrap(),
            ("10.0.0.5".into(), 69, "SEP1.cnf.xml".into())
        );
        assert_eq!(
            parse_url("tftp://pbx:6969/dir/a.cfg").unwrap(),
            ("pbx".into(), 6969, "dir/a.cfg".into())
        );
        assert!(parse_url("tftp://pbx/").is_err());
    }
}
