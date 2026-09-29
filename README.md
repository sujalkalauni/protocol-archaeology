# 🏺 Protocol Archaeology Tool

> **Translates raw network packet captures (`.pcap` / `.pcapng`) into an interactive, step-by-step visual narrative story.**

When a computer talks to a website or remote server, it exchanges data through a sequence of network protocol steps: resolving domain names, establishing connection handshakes, negotiating security settings, sending web page requests, and closing connections.

The **Protocol Archaeology Tool** turns raw, intimidating Wireshark hex dumps and packet rows into a human-readable forensic timeline:
> *"Device requested address → Established TCP connection → Negotiated security ciphers → Requested web page → Received response → Closed connection"*

---

## 🌟 Key Features

1. **Multi-Layer Header Dissection (`pcap_parser.py`)**:
   - **Layer 2 (Data Link)**: Ethernet frames, MAC addresses, EtherTypes, ARP Request & Reply mappings.
   - **Layer 3 (Network)**: IPv4 & IPv6, TTL, Protocol ID, Packet identification, ICMP control types.
   - **Layer 4 (Transport)**: TCP & UDP ports, TCP Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), Sequence & Ack numbering, Window sizes.
   - **Layer 7 (Application)**:
     - **DNS**: Query hostnames, query types (`A`, `AAAA`, `CNAME`, `MX`), and resolved IP answers.
     - **HTTP**: Request methods (`GET`, `POST`), URI paths, Host headers, and status codes (`200 OK`, `404 Not Found`).
     - **TLS**: Record types, Handshake types (`Client Hello`, `Server Hello`), Server Name Indication (`SNI`), and cipher suites.

2. **5-Chapter Flow Reassembly & Story Engine (`story_engine.py`)**:
   - **Chapter 1 - Address Resolution**: ARP hardware lookups and DNS domain queries.
   - **Chapter 2 - Connection Setup**: TCP 3-way handshake (`SYN` → `SYN-ACK` → `ACK`).
   - **Chapter 3 - Secure Exchange**: TLS cryptographic handshake and cipher negotiation.
   - **Chapter 4 - Web Content Delivery**: HTTP request methods and response payloads.
   - **Chapter 5 - Connection Teardown & Anomalies**: Graceful (`FIN-ACK`) vs abrupt (`RST`) connection terminations.

3. **Visual Frontend Dashboard (`templates/index.html`)**:
   - **Story Cards View**: Chronological narrative cards with device badges, protocol tags, and plain-English explanations.
   - **Sequence Flow View**: Visual host-to-host interaction ladder diagram (Client ↔ DNS ↔ Server ↔ Gateway).
   - **OSI Inspector Desk**: Unpeel Layer 2, Layer 3, Layer 4, and Layer 7 headers for any individual packet with interactive flags and side-by-side Raw Hex / ASCII terminal viewer.
   - **Protocol Reference Guide**: Educational handbook detailing networking concepts detected in the capture.
   - **Security Audit Engine**: Detects unencrypted cleartext protocols (`HTTP`, plain `DNS`) vs encrypted `TLS` tunnels and flags connection reset anomalies.

4. **Synthetic PCAP Generator (`sample_generator.py`)**:
   - Includes built-in pre-loaded captures for instant exploration:
     - *Full Web Browsing (ARP + DNS + TCP + TLS 1.3 + HTTPS + Teardown)*
     - *Cleartext HTTP & Credential Leakage Audit*
     - *TCP Connection Reset (RST) Anomaly*

---

## 📁 Project Directory Structure

```
protocol-archaeology/
├── backend/
│   ├── app.py                  # FastAPI REST API server
│   ├── requirements.txt        # Python backend dependencies
│   ├── engine/
│   │   ├── pcap_parser.py      # Scapy multi-layer packet dissector
│   │   ├── story_engine.py     # Story translation & chapter grouping
│   │   └── sample_generator.py # Synthetic PCAP file generator
│   ├── samples/                # Pre-loaded sample captures
│   └── templates/
│       └── index.html          # React frontend dashboard
├── Dockerfile                  # Container definition
├── docker-compose.yml          # Docker service orchestrator
├── .gitignore                  # Git repository exclusion rules
└── README.md                   # System documentation
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10 or higher
- `pip`

### 1. Run with Python locally

```bash
# 1. Install dependencies
pip install -r backend/requirements.txt

# 2. Run the FastAPI development server
python -m uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

Open your web browser and navigate to **`http://localhost:8000`**.

### 2. Run with Docker Compose

```bash
docker-compose up --build
```

Access the dashboard at **`http://localhost:8000`**.

---

## 🛠️ REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the interactive React UI dashboard |
| `GET` | `/api/health` | Service health status |
| `GET` | `/api/samples` | Lists all pre-loaded scenario captures |
| `GET` | `/api/samples/{filename}` | Analyzes a specific pre-loaded sample capture |
| `POST` | `/api/analyze` | Upload and analyze any `.pcap` or `.pcapng` file |
