//! homelab-dns — DNS server that resolves Kubernetes Ingress hostnames → LoadBalancer IPs
//!
//! Deployed in-cluster on k3s. Mounts service-account token + CA automatically.
//!
//! Env vars:
//!   BIND_ADDR        (default 0.0.0.0)
//!   DNS_PORT         (default 53 — needs CAP_NET_BIND_SERVICE or root)
//!   REFRESH_SECS     (default 30)
//!   K8S_NAMESPACE    (optional — limit to one namespace)
//!
//! RBAC needed: get/list networking.k8s.io/ingresses (cluster-scoped or namespaced).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

type DnsMap = Arc<RwLock<HashMap<String, IpAddr>>>;

fn main() {
    // Ensure rustls has a deterministic process-level crypto backend.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = std::env::var("DNS_PORT")
        .ok().and_then(|p| p.parse().ok()).unwrap_or(53);
    let refresh: u64 = std::env::var("REFRESH_SECS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(30);

    let dns_map: DnsMap = Arc::new(RwLock::new(HashMap::new()));

    // Initial load
    match fetch_ingresses() {
        Ok(map) => {
            println!("Loaded {} entries:", map.len());
            for (h, ip) in &map { println!("  {h} -> {ip}"); }
            *dns_map.write().unwrap() = map;
        }
        Err(e) => eprintln!("[warn] Initial K8s fetch failed: {e}"),
    }

    // Background refresh
    {
        let map = dns_map.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(refresh));
            match fetch_ingresses() {
                Ok(m) => {
                    println!("[refresh] {} entries", m.len());
                    *map.write().unwrap() = m;
                }
                Err(e) => eprintln!("[warn] K8s refresh: {e}"),
            }
        });
    }

    // UDP listener thread
    {
        let map = dns_map.clone();
        let addr = format!("{bind}:{port}");
        thread::spawn(move || {
            let sock = UdpSocket::bind(&addr).expect("UDP bind failed");
            println!("DNS/UDP listening on {addr}");
            let mut buf = [0u8; 512];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if let Some(resp) = resolve(&buf[..n], &map) {
                            let _ = sock.send_to(&resp, src);
                        }
                    }
                    Err(e) => eprintln!("[udp] recv: {e}"),
                }
            }
        });
    }

    // TCP listener — main thread
    let addr = format!("{bind}:{port}");
    let listener = TcpListener::bind(&addr).expect("TCP bind failed");
    println!("DNS/TCP listening on {addr}");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let m = dns_map.clone();
                thread::spawn(move || tcp_conn(s, m));
            }
            Err(e) => eprintln!("[tcp] accept: {e}"),
        }
    }
}

// ── TCP connection handler ────────────────────────────────────────────────────

fn tcp_conn(mut s: TcpStream, map: DnsMap) {
    // RFC 1035 §4.2.2: TCP messages are preceded by a 2-byte length field.
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut len_buf = [0u8; 2];
    loop {
        if s.read_exact(&mut len_buf).is_err() { return; }
        let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        if s.read_exact(&mut buf).is_err() { return; }
        if let Some(resp) = resolve(&buf, &map) {
            let rlen = (resp.len() as u16).to_be_bytes();
            if s.write_all(&rlen).is_err() || s.write_all(&resp).is_err() { return; }
        }
    }
}

// ── DNS protocol ─────────────────────────────────────────────────────────────

/// Parse a DNS query and return a wire-format response, or None to drop the packet.
fn resolve(pkt: &[u8], map: &DnsMap) -> Option<Vec<u8>> {
    if pkt.len() < 12 { return None; }

    // Byte 2 layout: QR(1) OPCODE(4) AA(1) TC(1) RD(1)
    if pkt[2] & 0x80 != 0 { return None; } // Already a response — ignore
    if pkt[2] & 0x78 != 0 { return None; } // Non-QUERY opcode — ignore
    if u16::from_be_bytes([pkt[4], pkt[5]]) == 0 { return None; } // QDCOUNT=0

    let (name, end) = parse_name(pkt, 12)?;
    if end + 4 > pkt.len() { return None; }
    let qtype  = u16::from_be_bytes([pkt[end],   pkt[end + 1]]);
    let qclass = u16::from_be_bytes([pkt[end + 2], pkt[end + 3]]);
    let rd     = pkt[2] & 0x01; // Recursion Desired bit — copy into response

    // Build a response header with no answer records.
    // DNS flags byte2: QR=1(0x80) AA=1(0x04) RD=copy → 0x84|rd
    let no_ans = |rcode: u8| -> Vec<u8> {
        let mut v = vec![pkt[0], pkt[1], 0x84 | rd, rcode,
                         0, 1, 0, 0, 0, 0, 0, 0]; // QDCOUNT=1, rest=0
        v.extend_from_slice(&pkt[12..end + 4]); // echo question section
        v
    };

    if !matches!(qclass, 1 | 255) { return Some(no_ans(4)); } // NOTIMP — unknown class

    let ip = map.read().ok()?.get(&name).copied();
    let Some(ip) = ip else { return Some(no_ans(3)); }; // NXDOMAIN

    // Build the answer RR matching the requested type and actual IP version.
    let rr: Option<Vec<u8>> = match (qtype, ip) {
        (1 | 255, IpAddr::V4(a)) => {
            // TYPE=A(1)  CLASS=IN(1)  TTL=60  RDLEN=4
            let mut r = vec![0xC0, 0x0C, 0, 1, 0, 1];
            r.extend_from_slice(&60u32.to_be_bytes());
            r.extend_from_slice(&[0, 4]);
            r.extend_from_slice(&a.octets());
            Some(r)
        }
        (28 | 255, IpAddr::V6(a)) => {
            // TYPE=AAAA(28)  CLASS=IN(1)  TTL=60  RDLEN=16
            let mut r = vec![0xC0, 0x0C, 0, 28, 0, 1];
            r.extend_from_slice(&60u32.to_be_bytes());
            r.extend_from_slice(&[0, 16]);
            r.extend_from_slice(&a.octets());
            Some(r)
        }
        _ => None, // Name exists but wrong type (e.g., AAAA for IPv4-only name)
    };

    let Some(rr) = rr else { return Some(no_ans(0)); }; // NOERROR, 0 answers

    // NOERROR response with 1 answer (ANCOUNT=1)
    let mut resp = vec![pkt[0], pkt[1], 0x84 | rd, 0,
                        0, 1, 0, 1, 0, 0, 0, 0];
    resp.extend_from_slice(&pkt[12..end + 4]); // question section
    resp.extend(rr);                            // answer RR
    Some(resp)
}

/// Parse a DNS QNAME (length-prefixed labels) starting at `pos`.
/// Returns `(dotted_name, position_after_null_label)`.
fn parse_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= buf.len() { return None; }
        let len = buf[pos] as usize;
        if len == 0 { return Some((labels.join("."), pos + 1)); }
        if len >= 0x40 { return None; } // Pointer / extended label — unexpected in queries
        pos += 1;
        if pos + len > buf.len() { return None; }
        let label = std::str::from_utf8(&buf[pos..pos + len]).ok()?.to_lowercase();
        labels.push(label);
        pos += len;
    }
}

// ── Kubernetes API ────────────────────────────────────────────────────────────

/// Fetch all Ingress resources and build hostname → LB-IP map.
fn fetch_ingresses() -> Result<HashMap<String, IpAddr>, Box<dyn std::error::Error>> {
    let (base, token, agent) = k8s_client()?;
    let ns  = std::env::var("K8S_NAMESPACE").ok();
    let url = match &ns {
        Some(n) => format!("{base}/apis/networking.k8s.io/v1/namespaces/{n}/ingresses"),
        None    => format!("{base}/apis/networking.k8s.io/v1/ingresses"),
    };

    let body: serde_json::Value = agent
        .get(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .call()?
        .into_json()?;

    let mut map = HashMap::new();
    let items = match body["items"].as_array() {
        Some(a) => a,
        None    => return Ok(map),
    };

    for item in items {
        // Each Ingress may have multiple load-balancer IPs in status.
        let lbs = match item["status"]["loadBalancer"]["ingress"].as_array() {
            Some(a) => a,
            None    => continue,
        };
        for lb in lbs {
            let ip: IpAddr = match lb["ip"].as_str().and_then(|s| s.parse().ok()) {
                Some(ip) => ip,
                None     => continue,
            };
            // Map every spec.rules[*].host to this IP.
            let rules = match item["spec"]["rules"].as_array() {
                Some(a) => a,
                None    => continue,
            };
            for rule in rules {
                if let Some(host) = rule["host"].as_str() {
                    map.insert(host.to_lowercase(), ip);
                }
            }
        }
    }
    Ok(map)
}

/// Build a ureq Agent configured for the cluster API server (in-cluster only).
fn k8s_client() -> Result<(String, String, ureq::Agent), Box<dyn std::error::Error>> {
    let sa = "/var/run/secrets/kubernetes.io/serviceaccount";

    let token = std::fs::read_to_string(format!("{sa}/token"))
        .map_err(|e| format!("Failed to read service account token: {e}"))?;
    
    let ca_bytes = std::fs::read(format!("{sa}/ca.crt"))
        .map_err(|e| format!("Failed to read cluster CA: {e}"))?;
    
    let mut cursor = std::io::Cursor::new(ca_bytes);
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert?)?;
    }
    
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let agent = ureq::AgentBuilder::new().tls_config(Arc::new(config)).build();

    // Use injected env vars (set automatically by kubelet)
    let base = match std::env::var("KUBERNETES_SERVICE_HOST") {
        Ok(h) => {
            let p = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
            if h.contains(':') { format!("https://[{h}]:{p}") }
            else               { format!("https://{h}:{p}") }
        }
        Err(_) => "https://kubernetes.default.svc".into(),
    };
    
    Ok((base, token.trim().to_string(), agent))
}
