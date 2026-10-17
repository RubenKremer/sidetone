//! SIP server location (RFC 3263): NAPTR, SRV and A/AAAA lookups, plus a
//! diagnostic report of every step for the Diagnostics tab.

use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;
use serde::Serialize;
use sidetone_core::sip;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct DnsError(pub String);

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for DnsError {}

#[derive(Debug, Clone, Serialize)]
pub struct NaptrRec {
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub service: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SrvRec {
    pub name: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DnsReport {
    pub query: String,
    pub naptr: Vec<NaptrRec>,
    pub srv: Vec<SrvRec>,
    pub addresses: Vec<String>,
    /// Address Sidetone would send UDP requests to.
    pub chosen: Option<String>,
    pub steps: Vec<String>,
    pub elapsed_ms: u64,
}

fn resolver() -> Option<&'static Resolver> {
    static R: OnceLock<Option<Resolver>> = OnceLock::new();
    R.get_or_init(|| {
        Resolver::from_system_conf()
            .or_else(|_| Resolver::default())
            .ok()
    })
    .as_ref()
}

fn cache() -> &'static Mutex<HashMap<String, (Instant, SocketAddr)>> {
    static C: OnceLock<Mutex<HashMap<String, (Instant, SocketAddr)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn strip(h: &str) -> &str {
    h.trim()
        .trim_start_matches("sips:")
        .trim_start_matches("sip:")
        .split(';')
        .next()
        .unwrap_or("")
}

fn a_lookup(host: &str, port: u16) -> Vec<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .map(|it| it.collect())
        .unwrap_or_default()
}

fn srv_lookup(name: &str) -> Vec<(u16, u16, u16, String)> {
    let Some(r) = resolver() else {
        return Vec::new();
    };
    match r.lookup(name, RecordType::SRV) {
        Ok(l) => l
            .iter()
            .filter_map(|rd| match rd {
                RData::SRV(s) => Some((
                    s.priority(),
                    s.weight(),
                    s.port(),
                    s.target().to_utf8().trim_end_matches('.').to_string(),
                )),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolves a SIP server for UDP: literal IP, explicit port (A/AAAA), else
/// SRV _sip._udp, else A/AAAA on 5060. Results are cached for 60 s.
pub fn resolve_sip(hostport: &str) -> Result<SocketAddr, DnsError> {
    resolve_sip_for(hostport, crate::transport::Kind::Udp)
}

/// Same as `resolve_sip` for a transport: SRV _sip._tcp or _sips._tcp and
/// port 5061 by default for TLS.
pub fn resolve_sip_for(
    hostport: &str,
    kind: crate::transport::Kind,
) -> Result<SocketAddr, DnsError> {
    let (srv, dport) = match kind {
        crate::transport::Kind::Udp => ("_sip._udp", 5060),
        crate::transport::Kind::Tcp => ("_sip._tcp", 5060),
        crate::transport::Kind::Tls => ("_sips._tcp", 5061),
    };
    let h = strip(hostport);
    if h.is_empty() {
        return Err(DnsError("empty server address".into()));
    }
    let ckey = format!("{srv}|{h}");
    if let Some((t, a)) = cache().lock().unwrap().get(&ckey) {
        if t.elapsed() < Duration::from_secs(60) {
            return Ok(*a);
        }
    }
    let (host, port) = sip::split_host_port(h);
    let res = (|| {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port.unwrap_or(dport)));
        }
        if let Some(p) = port {
            return a_lookup(&host, p)
                .into_iter()
                .find(|a| a.is_ipv4())
                .or_else(|| a_lookup(&host, p).into_iter().next())
                .ok_or_else(|| DnsError(format!("cannot resolve {host}")));
        }
        let mut recs = srv_lookup(&format!("{srv}.{host}."));
        recs.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        for (_, _, p, target) in recs {
            if let Some(a) = a_lookup(&target, p).into_iter().find(|a| a.is_ipv4()) {
                return Ok(a);
            }
        }
        a_lookup(&host, dport)
            .into_iter()
            .find(|a| a.is_ipv4())
            .or_else(|| a_lookup(&host, dport).into_iter().next())
            .ok_or_else(|| DnsError(format!("cannot resolve {host} (no SRV, no A/AAAA)")))
    })();
    if let Ok(a) = &res {
        cache().lock().unwrap().insert(ckey, (Instant::now(), *a));
    }
    res
}

/// Full RFC 3263 walk for diagnostics.
pub fn report(domain: &str) -> DnsReport {
    let t = Instant::now();
    let h = strip(domain).to_string();
    let (host, port) = sip::split_host_port(&h);
    let mut r = DnsReport {
        query: h.clone(),
        ..Default::default()
    };
    if host.parse::<IpAddr>().is_ok() {
        r.steps
            .push("literal IP address: no DNS lookups needed".into());
        r.chosen = Some(SocketAddr::new(host.parse().unwrap(), port.unwrap_or(5060)).to_string());
        r.elapsed_ms = t.elapsed().as_millis() as u64;
        return r;
    }
    let Some(res) = resolver() else {
        r.steps.push("no DNS resolver configuration found".into());
        return r;
    };
    if port.is_some() {
        r.steps
            .push("explicit port: RFC 3263 skips NAPTR and SRV".into());
    } else {
        match res.lookup(format!("{host}."), RecordType::NAPTR) {
            Ok(l) => {
                for rd in l.iter() {
                    if let RData::NAPTR(n) = rd {
                        r.naptr.push(NaptrRec {
                            order: n.order(),
                            preference: n.preference(),
                            flags: String::from_utf8_lossy(n.flags()).into_owned(),
                            service: String::from_utf8_lossy(n.services()).into_owned(),
                            replacement: n.replacement().to_utf8(),
                        });
                    }
                }
                r.naptr.sort_by_key(|n| (n.order, n.preference));
                r.steps
                    .push(format!("NAPTR {host}: {} record(s)", r.naptr.len()));
            }
            Err(e) => r
                .steps
                .push(format!("NAPTR {host}: {}", short_err(&e.to_string()))),
        }
        let mut names: Vec<String> = r
            .naptr
            .iter()
            .filter(|n| n.flags.eq_ignore_ascii_case("s"))
            .map(|n| n.replacement.clone())
            .collect();
        for n in [
            format!("_sip._udp.{host}."),
            format!("_sip._tcp.{host}."),
            format!("_sips._tcp.{host}."),
        ] {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        for name in names {
            let mut v = srv_lookup(&name);
            v.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            r.steps.push(format!(
                "SRV {}: {}",
                name.trim_end_matches('.'),
                if v.is_empty() {
                    "none".to_string()
                } else {
                    format!("{} record(s)", v.len())
                }
            ));
            for (pr, w, p, target) in v {
                let addrs = a_lookup(&target, p)
                    .iter()
                    .map(|a| a.ip().to_string())
                    .collect();
                r.srv.push(SrvRec {
                    name: name.trim_end_matches('.').to_string(),
                    priority: pr,
                    weight: w,
                    port: p,
                    target,
                    addresses: addrs,
                });
            }
        }
    }
    let addrs = a_lookup(&host, port.unwrap_or(5060));
    r.addresses = addrs.iter().map(|a| a.ip().to_string()).collect();
    r.steps.push(format!(
        "A/AAAA {host}: {}",
        if r.addresses.is_empty() {
            "none".to_string()
        } else {
            r.addresses.join(", ")
        }
    ));
    cache().lock().unwrap().remove(&format!("_sip._udp|{h}"));
    match resolve_sip(&h) {
        Ok(a) => {
            r.chosen = Some(a.to_string());
            r.steps.push(format!("UDP requests go to {a}"));
        }
        Err(e) => r.steps.push(format!("cannot pick a server: {e}")),
    }
    r.elapsed_ms = t.elapsed().as_millis() as u64;
    r
}

fn short_err(e: &str) -> String {
    if e.contains("no record") || e.contains("NoRecordsFound") || e.contains("no records") {
        "none".into()
    } else {
        e.chars().take(120).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_port() {
        assert_eq!(
            resolve_sip("127.0.0.1:5070").unwrap(),
            "127.0.0.1:5070".parse().unwrap()
        );
        assert_eq!(
            resolve_sip("sip:10.0.0.5").unwrap(),
            "10.0.0.5:5060".parse().unwrap()
        );
        let r = report("127.0.0.1");
        assert_eq!(r.chosen.as_deref(), Some("127.0.0.1:5060"));
    }
}
