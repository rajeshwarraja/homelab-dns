# homelab-dns — Architecture & Sequence Flows

A DNS server written in Rust that resolves Kubernetes Ingress hostnames to their LoadBalancer external IPs, with no system-level dependencies (pure-Rust TLS via `rustls`).

---

## Startup Sequence

```mermaid
sequenceDiagram
    participant Main
    participant K8sAPI as Kubernetes API (HTTPS)
    participant DnsMap as Shared DNS Map<br/>(Arc<RwLock<HashMap>>)
    participant RefreshThread as Background Refresh Thread
    participant UdpThread as UDP Listener Thread
    participant TcpMain as TCP Listener (main thread)

    Main->>K8sAPI: GET /apis/networking.k8s.io/v1/ingresses<br/>(Bearer token, TLS with cluster CA)
    K8sAPI-->>Main: JSON list of Ingress objects

    Main->>Main: Parse each Ingress:<br/>spec.rules[].host → status.loadBalancer.ingress[].ip

    Main->>DnsMap: write() — populate hostname→IP map

    Main->>RefreshThread: spawn (loops every REFRESH_SECS)
    Main->>UdpThread: spawn (binds UDP 0.0.0.0:53)
    Main->>TcpMain: bind TCP 0.0.0.0:53 (main thread loops here)
```

---

## Background Refresh Sequence

```mermaid
sequenceDiagram
    participant RefreshThread as Background Refresh Thread
    participant K8sAPI as Kubernetes API (HTTPS)
    participant DnsMap as Shared DNS Map

    loop every REFRESH_SECS (default 30s)
        RefreshThread->>K8sAPI: GET /apis/networking.k8s.io/v1/ingresses
        K8sAPI-->>RefreshThread: updated Ingress list

        RefreshThread->>DnsMap: write() — replace entire map atomically
    end
```

---

## DNS Query over UDP

```mermaid
sequenceDiagram
    participant Client as DNS Client
    participant UdpThread as UDP Listener Thread
    participant Resolve as resolve()
    participant DnsMap as Shared DNS Map

    Client->>UdpThread: UDP datagram (DNS query, max 512 bytes)

    UdpThread->>Resolve: resolve(packet, &dns_map)

    Resolve->>Resolve: Validate header (QR=0, OPCODE=QUERY, QDCOUNT≥1)
    Resolve->>Resolve: parse_name() — decode wire-format QNAME

    Resolve->>DnsMap: read() — lookup hostname

    alt hostname found
        DnsMap-->>Resolve: IpAddr (V4 or V6)
        Resolve->>Resolve: Build A (type 1) or AAAA (type 28) answer RR<br/>TTL=60s, pointer 0xC00C back to question
        Resolve-->>UdpThread: NOERROR response with 1 answer
    else hostname not found
        DnsMap-->>Resolve: None
        Resolve-->>UdpThread: NXDOMAIN response (RCODE=3)
    end

    UdpThread-->>Client: UDP datagram (DNS response)
```

---

## DNS Query over TCP

```mermaid
sequenceDiagram
    participant Client as DNS Client
    participant TcpMain as TCP Listener (main thread)
    participant TcpConn as tcp_conn() — per-connection thread
    participant Resolve as resolve()
    participant DnsMap as Shared DNS Map

    Client->>TcpMain: TCP connect to port 53
    TcpMain->>TcpConn: spawn thread with TcpStream

    loop until client closes or 5s read timeout
        Client->>TcpConn: 2-byte length prefix + DNS query bytes (RFC 1035 §4.2.2)

        TcpConn->>Resolve: resolve(query_bytes, &dns_map)

        Resolve->>DnsMap: read() — lookup hostname

        alt hostname found
            Resolve-->>TcpConn: NOERROR response bytes
        else hostname not found
            Resolve-->>TcpConn: NXDOMAIN response bytes
        end

        TcpConn-->>Client: 2-byte length prefix + DNS response bytes
    end
```

---

## Kubernetes Client Initialisation (In-Cluster Only)

```mermaid
sequenceDiagram
    participant App
    participant SA as ServiceAccount Mount<br/>(/var/run/secrets/…)
    participant Rustls as rustls (TLS)
    participant Agent as ureq HTTP Agent

    App->>SA: read token file
    SA-->>App: Bearer token

    App->>SA: read ca.crt (PEM)
    SA-->>App: cluster CA certificate

    App->>Rustls: build RootCertStore from cluster CA
    Rustls-->>App: ClientConfig (trusts cluster CA)

    App->>Agent: AgentBuilder::tls_config(cluster CA config)
    Agent-->>App: ureq::Agent ready for HTTPS
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0` | IP address to bind the DNS server |
| `DNS_PORT` | `53` | Port for both UDP and TCP listeners |
| `REFRESH_SECS` | `30` | How often to re-fetch Ingresses from K8s |
| `K8S_NAMESPACE` | *(all)* | Limit Ingress watch to a single namespace |
| `KUBERNETES_SERVICE_HOST` | `kubernetes.default.svc` | Injected by kubelet (auto-detected) |
| `KUBERNETES_SERVICE_PORT` | `443` | Injected by kubelet (auto-detected) |

## RBAC Requirements

```yaml
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list"]
```
