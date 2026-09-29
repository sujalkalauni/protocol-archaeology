"""
Flow Reassembly and Story Generation Engine
Groups network 5-tuples into sessions, tracks state transitions, and builds
a 5-chapter narrative story, sequence interaction timeline, and security audit report.
"""

from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict


def infer_host_roles(packets: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Infers the semantic role of each IP/host in the packet capture."""
    roles: Dict[str, Dict[str, Any]] = {}

    for pkt in packets:
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        proto = pkt.get("protocol")
        l4 = pkt.get("l4") or {}
        l7 = pkt.get("l7") or {}
        arp = pkt.get("arp") or {}

        # Default info
        for ip in (src, dst):
            if ip and ip not in roles:
                roles[ip] = {
                    "ip": ip,
                    "role": "Host",
                    "badge": "bg-slate-700 text-slate-200 border-slate-600",
                    "hostname": None,
                    "is_local": ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip == "127.0.0.1",
                    "packet_count": 0
                }
            if ip in roles:
                roles[ip]["packet_count"] += 1

        # Check DNS
        if proto == "DNS" and l7:
            if l7.get("is_response"):
                if src in roles:
                    roles[src]["role"] = "DNS Server"
                    roles[src]["badge"] = "bg-amber-950/70 text-amber-300 border-amber-500/40"
            else:
                if dst in roles:
                    roles[dst]["role"] = "DNS Server"
                    roles[dst]["badge"] = "bg-amber-950/70 text-amber-300 border-amber-500/40"

        # Check HTTP / TLS
        if proto in ("HTTP", "TLS") or (l4.get("dst_port") in (80, 443, 8080, 8443)):
            if dst in roles and roles[dst]["role"] == "Host":
                roles[dst]["role"] = "Web Server"
                roles[dst]["badge"] = "bg-emerald-950/70 text-emerald-300 border-emerald-500/40"
            if src in roles and roles[src]["role"] == "Host" and roles[src]["is_local"]:
                roles[src]["role"] = "Client"
                roles[src]["badge"] = "bg-sky-950/70 text-sky-300 border-sky-500/40"

        # Check Gateway via ARP
        if arp and arp.get("op_code") == 2:
            if arp.get("src_ip") in roles and (arp.get("src_ip").endswith(".1") or arp.get("src_ip").endswith(".254")):
                roles[arp.get("src_ip")]["role"] = "Default Gateway"
                roles[arp.get("src_ip")]["badge"] = "bg-purple-950/70 text-purple-300 border-purple-500/40"

        # Check TLS SNI / HTTP Host for hostnames
        if l7:
            if l7.get("sni") and dst in roles:
                roles[dst]["hostname"] = l7.get("sni")
            if l7.get("host") and dst in roles:
                roles[dst]["hostname"] = l7.get("host")

    # If no explicit client assigned, pick the most active local host
    client_candidates = [ip for ip, data in roles.items() if data["is_local"] and data["role"] in ("Host", "Client")]
    if client_candidates:
        primary_client = max(client_candidates, key=lambda ip: roles[ip]["packet_count"])
        roles[primary_client]["role"] = "Client (Origin)"
        roles[primary_client]["badge"] = "bg-cyan-950/70 text-cyan-300 border-cyan-500/40"

    return roles


def classify_packet_to_chapter(pkt: Dict[str, Any]) -> Tuple[int, str, str, str]:
    """
    Categorizes a packet into one of the 5 canonical chapters:
    1 - Address Resolution (ARP & DNS)
    2 - Connection Setup (TCP 3-Way Handshake)
    3 - Secure Exchange (TLS Handshake & Encryption)
    4 - Web Content Delivery (HTTP & Application Data)
    5 - Connection Teardown & Anomalies (FIN/RST/Drops)
    Returns (chapter_num, chapter_title, step_title, story_narrative)
    """
    proto = pkt.get("protocol")
    l4 = pkt.get("l4") or {}
    l7 = pkt.get("l7") or {}
    arp = pkt.get("arp") or {}
    icmp = pkt.get("icmp") or {}
    src = pkt.get("src_ip", "Unknown")
    dst = pkt.get("dst_ip", "Unknown")
    src_p = pkt.get("src_port")
    dst_p = pkt.get("dst_port")

    flags = l4.get("flags") or []

    # CHAPTER 1: Address Resolution
    if arp:
        if arp.get("op_code") == 1:
            return (
                1,
                "Chapter 1 - Address Resolution",
                "ARP Discovery Broadcast",
                f"Device {src} broadcasted an ARP request across the local network asking 'Who has {arp.get('dst_ip')}? Tell {src}' to find the hardware MAC address."
            )
        else:
            return (
                1,
                "Chapter 1 - Address Resolution",
                "ARP Resolution Reply",
                f"Device {src} answered with its MAC address {arp.get('src_mac')} for IP {src}, completing Layer 2 address binding."
            )

    if proto == "DNS" and l7:
        if l7.get("is_response"):
            answers = l7.get("answers", [])
            ans_str = ", ".join(f"{a['name']} \u2192 {a['data']}" for a in answers) if answers else "No Answer"
            return (
                1,
                "Chapter 1 - Address Resolution",
                "DNS Query Resolution",
                f"DNS Server {src} returned query answers to {dst}: [{ans_str}]."
            )
        else:
            queries = l7.get("queries", [])
            q_str = ", ".join(f"{q['name']} ({q['type']})" for q in queries) if queries else "Lookup"
            return (
                1,
                "Chapter 1 - Address Resolution",
                "DNS Domain Lookup",
                f"Client {src} asked DNS resolver {dst} to resolve domain name: [{q_str}]."
            )

    # CHAPTER 5: Connection Teardown or Anomalies (Check RST and FIN early)
    if "RST" in flags:
        return (
            5,
            "Chapter 5 - Connection Teardown & Anomalies",
            "Abrupt TCP Reset (RST)",
            f"Host {src}:{src_p} sent a TCP RST (Reset) to {dst}:{dst_p}. The connection was abruptly terminated or rejected (Port closed / firewall drop)."
        )

    if "FIN" in flags:
        return (
            5,
            "Chapter 5 - Connection Teardown & Anomalies",
            "Graceful TCP Termination (FIN-ACK)",
            f"Host {src}:{src_p} sent FIN-ACK (Seq={l4.get('seq')}, Ack={l4.get('ack')}) to {dst}:{dst_p} initiating graceful connection closure."
        )

    # CHAPTER 2: Connection Setup (TCP Handshake)
    if "SYN" in flags and "ACK" in flags:
        return (
            2,
            "Chapter 2 - Connection Setup",
            "TCP Handshake: SYN-ACK Reply",
            f"Remote Server {src}:{src_p} accepted the connection request and replied with SYN-ACK (Seq={l4.get('seq')}, Ack={l4.get('ack')}) to {dst}:{dst_p}."
        )

    if "SYN" in flags:
        return (
            2,
            "Chapter 2 - Connection Setup",
            "TCP Handshake: SYN Request",
            f"Client {src}:{src_p} initiated a new TCP connection with SYN flag (Initial Seq={l4.get('seq')}) to target server {dst}:{dst_p}."
        )

    # If it's a standalone ACK right after handshake
    if flags == ["ACK"] and l4.get("payload_length", 0) == 0:
        # Check if early sequence or teardown
        return (
            2,
            "Chapter 2 - Connection Setup",
            "TCP Flow Acknowledgment (ACK)",
            f"Host {src}:{src_p} acknowledged packet delivery (Ack={l4.get('ack')}) to {dst}:{dst_p}."
        )

    # CHAPTER 3: Secure Exchange (TLS)
    if proto == "TLS" or (l7 and l7.get("protocol") == "TLS"):
        handshake = l7.get("handshake_type")
        sni = l7.get("sni")
        ciphers = l7.get("ciphers_count", 0)
        sel_cipher = l7.get("selected_cipher")
        content_type = l7.get("content_type")

        if handshake == "Client Hello":
            sni_msg = f" requesting SNI hostname '{sni}'" if sni else ""
            return (
                3,
                "Chapter 3 - Secure Exchange",
                "TLS Client Hello",
                f"Client {src} proposed secure TLS negotiation{sni_msg} offering {ciphers} cipher suites to server {dst}:{dst_p}."
            )
        elif handshake == "Server Hello":
            return (
                3,
                "Chapter 3 - Secure Exchange",
                "TLS Server Hello & Cipher Selection",
                f"Server {src} agreed on cipher suite ({sel_cipher or 'ECDHE-RSA-AES-GCM'}) and established session parameters with {dst}."
            )
        elif handshake in ("Certificate", "Server Key Exchange", "Certificate Request"):
            return (
                3,
                "Chapter 3 - Secure Exchange",
                f"TLS {handshake}",
                f"Server {src} presented its digital certificate and cryptographic exchange keys to authenticate identity to {dst}."
            )
        elif handshake == "Finished" or content_type == "ChangeCipherSpec":
            return (
                3,
                "Chapter 3 - Secure Exchange",
                "TLS Handshake Finalized",
                f"Keys exchanged and verified. All subsequent communications between {src} and {dst} are encrypted."
            )
        elif content_type == "Application Data":
            return (
                4,
                "Chapter 4 - Web Content Delivery",
                "TLS Encrypted Application Data",
                f"Encrypted TLS payload of {l7.get('record_length', l4.get('payload_length', 0))} bytes transferred between {src}:{src_p} and {dst}:{dst_p}."
            )

    # CHAPTER 4: Web Content Delivery (HTTP)
    if proto == "HTTP" or (l7 and l7.get("protocol") == "HTTP"):
        if l7.get("type") == "request":
            return (
                4,
                "Chapter 4 - Web Content Delivery",
                f"HTTP {l7.get('method')} Request",
                f"Client {src} sent cleartext HTTP request: {l7.get('method')} {l7.get('uri')} (Host: {l7.get('host', 'unknown')}) to web server {dst}."
            )
        else:
            return (
                4,
                "Chapter 4 - Web Content Delivery",
                f"HTTP {l7.get('status_code')} {l7.get('reason')}",
                f"Web Server {src} returned HTTP {l7.get('status_code')} {l7.get('reason')} payload ({l7.get('content_type', 'data')}, {l7.get('content_length', 0)} bytes) to {dst}."
            )

    # ICMP
    if icmp:
        return (
            5,
            "Chapter 5 - Connection Teardown & Anomalies",
            f"ICMP {icmp.get('type_name')}",
            f"Diagnostic network control message {icmp.get('type_name')} exchanged between {src} and {dst}."
        )

    # Default fallback chapter
    if l4.get("payload_length", 0) > 0:
        return (
            4,
            "Chapter 4 - Web Content Delivery",
            f"{proto} Data Transmission",
            f"Data payload of {l4.get('payload_length')} bytes transferred from {src}:{src_p} to {dst}:{dst_p}."
        )

    return (
        2,
        "Chapter 2 - Connection Setup",
        f"{proto} Transport Packet",
        f"Transport exchange between {src} and {dst}."
    )


def generate_story_and_analysis(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Transforms dissected packets into a complete educational and forensic story model.
    """
    if not packets:
        return {
            "summary": {
                "total_packets": 0,
                "duration_ms": 0,
                "total_bytes": 0,
                "endpoints_count": 0,
                "protocols": []
            },
            "security_audit": {"cleartext_protocols": [], "encrypted_protocols": [], "anomalies": []},
            "host_roles": {},
            "chapters": [],
            "story_cards": [],
            "sequence_flow": []
        }

    host_roles = infer_host_roles(packets)
    total_bytes = sum(p.get("length", 0) for p in packets)
    duration_ms = packets[-1].get("relative_time_ms", 0) if packets else 0
    
    protocols_found = set(p.get("protocol", "Unknown") for p in packets)
    
    # 5 Chapters setup
    chapters_meta = [
        {"id": 1, "name": "Address Resolution", "description": "ARP lookups and DNS domain resolution."},
        {"id": 2, "name": "Connection Setup", "description": "TCP 3-way handshake (SYN \u2192 SYN-ACK \u2192 ACK)."},
        {"id": 3, "name": "Secure Exchange", "description": "TLS handshake cipher negotiation and certificate exchange."},
        {"id": 4, "name": "Web Content Delivery", "description": "HTTP requests, server responses, and encrypted application data payloads."},
        {"id": 5, "name": "Connection Teardown & Anomalies", "description": "Graceful (FIN-ACK) or abrupt (RST) terminations and packet diagnostics."}
    ]
    
    chapter_map = {c["id"]: {**c, "steps": []} for c in chapters_meta}
    story_cards = []
    sequence_flow = []

    # Security audits
    cleartext_found = []
    encrypted_found = []
    anomalies = []

    for pkt in packets:
        idx = pkt["index"]
        proto = pkt.get("protocol")
        src = pkt.get("src_ip", "Unknown")
        dst = pkt.get("dst_ip", "Unknown")
        src_role = host_roles.get(src, {}).get("role", "Host")
        dst_role = host_roles.get(dst, {}).get("role", "Host")

        ch_id, ch_name, step_title, story_narrative = classify_packet_to_chapter(pkt)

        l4_dict = pkt.get("l4") or {}
        l7_dict = pkt.get("l7") or {}
        flags_list = l4_dict.get("flags") or []
        has_rst = "RST" in flags_list

        card = {
            "index": idx,
            "chapter_id": ch_id,
            "chapter_name": ch_name,
            "title": step_title,
            "narrative": story_narrative,
            "timestamp_ms": pkt.get("relative_time_ms", 0),
            "protocol": proto,
            "src_ip": src,
            "dst_ip": dst,
            "src_role": src_role,
            "dst_role": dst_role,
            "src_port": pkt.get("src_port"),
            "dst_port": pkt.get("dst_port"),
            "length": pkt.get("length", 0),
            "summary": pkt.get("summary", ""),
            "has_anomaly": has_rst,
            "is_cleartext": proto in ("HTTP", "DNS") and not (l7_dict.get("protocol") == "TLS")
        }

        story_cards.append(card)
        chapter_map[ch_id]["steps"].append(card)

        # Build sequence flow item
        flow_item = {
            "packet_index": idx,
            "timestamp_ms": pkt.get("relative_time_ms", 0),
            "from_host": src,
            "to_host": dst,
            "from_role": src_role,
            "to_role": dst_role,
            "protocol": proto,
            "label": step_title,
            "detail": pkt.get("summary", ""),
            "flags": flags_list,
            "status": "danger" if has_rst else "success" if "SYN" in flags_list else "info"
        }
        sequence_flow.append(flow_item)

        # Security checks
        if proto == "HTTP":
            if "HTTP (Cleartext Web Traffic)" not in cleartext_found:
                cleartext_found.append("HTTP (Cleartext Web Traffic - URLs and payloads visible in transit)")
        if proto == "DNS":
            if "DNS (Cleartext Queries)" not in cleartext_found:
                cleartext_found.append("DNS (Plain UDP 53 Queries - Domain queries visible in transit)")
        if proto == "TLS" or (l7_dict.get("protocol") == "TLS"):
            if "TLS / HTTPS (Encrypted Channel)" not in encrypted_found:
                encrypted_found.append("TLS / HTTPS (Encrypted End-to-End Cryptographic Tunnel)")

        if has_rst:
            anomalies.append(f"Packet #{idx}: Connection Reset (RST) sent by {src} to {dst} on port {pkt.get('dst_port')}.")

    return {
        "summary": {
            "total_packets": len(packets),
            "duration_ms": duration_ms,
            "total_bytes": total_bytes,
            "endpoints_count": len(host_roles),
            "protocols": sorted(list(protocols_found)),
            "chapter_counts": {k: len(v["steps"]) for k, v in chapter_map.items()}
        },
        "security_audit": {
            "is_secure": len(cleartext_found) == 0 and len(encrypted_found) > 0,
            "cleartext_protocols": cleartext_found,
            "encrypted_protocols": encrypted_found,
            "anomalies": anomalies,
            "score": "A (Encrypted)" if (not cleartext_found and encrypted_found) else "C (Mixed/Cleartext)" if (cleartext_found and encrypted_found) else "D (Vulnerable)"
        },
        "host_roles": host_roles,
        "chapters": [v for v in chapter_map.values() if len(v["steps"]) > 0],
        "all_chapters": list(chapter_map.values()),
        "story_cards": story_cards,
        "sequence_flow": sequence_flow
    }
