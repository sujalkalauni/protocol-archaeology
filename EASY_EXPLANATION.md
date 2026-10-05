# 🎓 How to Explain This Project Easily (Viva & Presentation Guide)

---

## ⚡ 1-Sentence Summary (The "Elevator Pitch")
> **"This project takes confusing Wireshark network packet files (`.pcap`) and turns them into a step-by-step storybook that anyone can read and understand."**

---

## ❓ The Problem vs Our Solution

| ❌ The Problem (Wireshark / Raw Packets) | ✅ Our Solution (Protocol Archaeology) |
|---|---|
| Thousands of rows of hexadecimal numbers | A clean, chronological storyline with plain English |
| Hard to understand who is talking to whom | Auto-detects device roles (Client, DNS, Web Server, Gateway) |
| Hard to see what happened first, next, and last | Breaks the capture into **5 clear story chapters** |
| Hard to spot security leaks | Built-in **Security Audit** that flags passwords or unencrypted data |

---

## 🧩 How It Works in 3 Simple Steps

```
[ 1. Input .pcap ] ─────────► [ 2. Python Engine ] ─────────► [ 3. Visual Storyboard ]
(Packet Capture File)         • Scapy parses layers           • Story Timeline Cards
                              • Identifies IP roles           • Sequence Ladder Diagram
                              • Groups into 5 Chapters        • OSI Layer Inspector
```

1. **Input**: User uploads a `.pcap` capture file (or picks a pre-loaded sample).
2. **Backend Engine (`backend/engine/`)**:
   - **`pcap_parser.py`**: Reads packets layer by layer (Ethernet $\rightarrow$ IP $\rightarrow$ TCP/UDP $\rightarrow$ HTTP/DNS/TLS).
   - **`story_engine.py`**: Translates technical flags (like `SYN`, `ACK`, `Client Hello`) into plain English descriptions.
3. **Frontend Dashboard (`index.html`)**: Shows the network conversation as an interactive timeline, sequence diagram, and security report.

---

## 📖 The 5 Story Chapters (Every Network Chat Follows This!)

Every web browsing session follows 5 basic steps:
1. **Chapter 1: Address Resolution** — *"Where is the website?"* (ARP finds local router, DNS turns `example.com` into an IP address).
2. **Chapter 2: Connection Setup** — *"Let's shake hands!"* (TCP 3-way handshake: SYN $\rightarrow$ SYN-ACK $\rightarrow$ ACK).
3. **Chapter 3: Secure Exchange** — *"Let's encrypt our messages!"* (TLS handshake negotiates encryption keys so no one can eavesdrop).
4. **Chapter 4: Content Delivery** — *"Here is the web page!"* (HTTP GET request sent, Web server responds with HTML/data).
5. **Chapter 5: Teardown & Anomalies** — *"Goodbye or Error!"* (Clean FIN-ACK closing or RST error if connection dropped).

---

## 🎤 60-Second Presentation Script (Read This in Demos)

> *"Good morning/afternoon! Our project is called the **Protocol Archaeology Tool**.*
>
> *When computers communicate over the internet, they exchange millions of raw binary packets. Traditional tools like Wireshark are extremely powerful, but they show massive tables of hexadecimal bytes that are hard to visualize and explain.*
>
> *Our application acts as a translator. When you give it a packet capture file, it automatically dissects every OSI layer, identifies who the Client, DNS server, and Web server are, and constructs a 5-chapter visual story.*
>
> *It also includes a Sequence Flow diagram, an OSI header inspector, and a Security Auditor that checks whether passwords or sensitive data were leaked in cleartext.*
>
> *Let me demonstrate with a live sample..."*

---

## 🎯 Top Viva Questions & 1-Line Answers

### Q1: What library did you use to parse packets?
> **Answer**: We used **Scapy** in Python, which lets us inspect headers across Layer 2 (Ethernet/ARP), Layer 3 (IP), Layer 4 (TCP/UDP), and Layer 7 (DNS/HTTP/TLS).

### Q2: What is the backend and frontend tech stack?
> **Answer**: The backend is built with **FastAPI** (Python), and the frontend is a responsive single-page dashboard with interactive sequence charts and story cards.

### Q3: How do you detect if traffic is secure or insecure?
> **Answer**: We check Layer 7 protocols. If traffic uses unencrypted HTTP on port 80, we scan for plaintext credentials/cookies and flag security warnings. If it uses TLS 1.3 on port 443, we verify that the payload is properly encrypted.

### Q4: How do you run the project?
> **Answer**: Just run `python run.py` (or double-click `run.bat`). It automatically installs any missing dependencies, starts the server, and opens the browser.
