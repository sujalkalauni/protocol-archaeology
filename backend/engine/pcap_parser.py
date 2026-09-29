"""
PCAP Multi-Layer Packet Dissector Engine
Extracts Layer 2 (Data Link), Layer 3 (Network), Layer 4 (Transport), and Layer 7 (Application)
metadata from network capture files (.pcap, .pcapng).
"""

import os
import binascii
from typing import List, Dict, Any, Optional
from scapy.all import (
    rdpcap,
    Ether,
    ARP,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    Packet
)

# Try importing TLS if available in scapy or fallback to custom parser
try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
    HAS_SCAPY_TLS = True
except ImportError:
    HAS_SCAPY_TLS = False

# Mapping for ICMP types
ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem"
}

# Mapping for common ports to protocols
PORT_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS/TLS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

TLS_HANDSHAKE_TYPES = {
    1: "Client Hello",
    2: "Server Hello",
    4: "New Session Ticket",
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished"
}

TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
    24: "Heartbeat"
}

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0300: "SSL 3.0"
}


def format_hex_dump(data: bytes, width: int = 16) -> Dict[str, Any]:
    """Generates side-by-side hex dump and ASCII lines for payload visualization."""
    if not data:
        return {"lines": [], "hex_string": "", "ascii_string": "", "length": 0}

    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append({
            "offset": f"{i:04x}",
            "hex": hex_bytes.ljust(width * 3 - 1),
            "ascii": ascii_chars
        })

    return {
        "lines": lines,
        "hex_string": data.hex(),
        "ascii_string": "".join(chr(b) if 32 <= b <= 126 else "." for b in data),
        "length": len(data)
    }


def parse_tls_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """Dissects TLS record headers and Handshake details manually from bytes."""
    if len(payload) < 5:
        return None

    content_type_byte = payload[0]
    if content_type_byte not in TLS_CONTENT_TYPES:
        return None

    ver_major = payload[1]
    ver_minor = payload[2]
    record_version_val = (ver_major << 8) | ver_minor
    if ver_major != 3:  # TLS record version must be 3.x (0x0301..0x0304)
        return None

    record_length = (payload[3] << 8) | payload[4]
    tls_info = {
        "content_type": TLS_CONTENT_TYPES.get(content_type_byte, f"Unknown ({content_type_byte})"),
        "content_type_id": content_type_byte,
        "record_version": TLS_VERSIONS.get(record_version_val, f"0x{record_version_val:04x}"),
        "record_length": record_length,
        "handshake_type": None,
        "sni": None,
        "ciphers": [],
        "tls_version": TLS_VERSIONS.get(record_version_val, "TLS")
    }

    # If it's a Handshake message
    if content_type_byte == 22 and len(payload) >= 9:
        handshake_type_byte = payload[5]
        tls_info["handshake_type"] = TLS_HANDSHAKE_TYPES.get(
            handshake_type_byte, f"Handshake ({handshake_type_byte})"
        )

        # Parse Client Hello (Type 1)
        if handshake_type_byte == 1 and len(payload) > 43:
            try:
                # Client Hello: Handshake length (3B) + Client Version (2B) + Random (32B) + Session ID length (1B)
                client_ver = (payload[9] << 8) | payload[10]
                tls_info["client_version"] = TLS_VERSIONS.get(client_ver, f"0x{client_ver:04x}")
                
                pos = 11 + 32  # Skip to session ID length
                if pos < len(payload):
                    sess_id_len = payload[pos]
                    pos += 1 + sess_id_len
                    
                    # Cipher Suites
                    if pos + 2 <= len(payload):
                        cipher_suites_len = (payload[pos] << 8) | payload[pos + 1]
                        pos += 2
                        ciphers_data = payload[pos:pos + cipher_suites_len]
                        ciphers = []
                        for ci in range(0, len(ciphers_data), 2):
                            if ci + 1 < len(ciphers_data):
                                val = (ciphers_data[ci] << 8) | ciphers_data[ci + 1]
                                ciphers.append(f"0x{val:04x}")
                        tls_info["ciphers_count"] = len(ciphers)
                        pos += cipher_suites_len

                    # Compression Methods
                    if pos < len(payload):
                        comp_methods_len = payload[pos]
                        pos += 1 + comp_methods_len

                    # Extensions
                    if pos + 2 <= len(payload):
                        ext_total_len = (payload[pos] << 8) | payload[pos + 1]
                        pos += 2
                        ext_end = pos + ext_total_len
                        while pos + 4 <= min(ext_end, len(payload)):
                            ext_type = (payload[pos] << 8) | payload[pos + 1]
                            ext_len = (payload[pos + 2] << 8) | payload[pos + 3]
                            pos += 4
                            # SNI extension is type 0x0000
                            if ext_type == 0 and pos + ext_len <= len(payload):
                                sni_pos = pos + 2  # Skip SNI list length (2B)
                                if sni_pos + 3 <= pos + ext_len:
                                    # Name type (1B) + Name length (2B)
                                    name_len = (payload[sni_pos + 1] << 8) | payload[sni_pos + 2]
                                    sni_bytes = payload[sni_pos + 3:sni_pos + 3 + name_len]
                                    tls_info["sni"] = sni_bytes.decode('utf-8', errors='ignore')
                            pos += ext_len
            except Exception:
                pass

        # Parse Server Hello (Type 2)
        elif handshake_type_byte == 2 and len(payload) > 40:
            try:
                server_ver = (payload[9] << 8) | payload[10]
                tls_info["server_version"] = TLS_VERSIONS.get(server_ver, f"0x{server_ver:04x}")
                pos = 11 + 32
                if pos < len(payload):
                    sess_id_len = payload[pos]
                    pos += 1 + sess_id_len
                    if pos + 2 <= len(payload):
                        selected_cipher = (payload[pos] << 8) | payload[pos + 1]
                        tls_info["selected_cipher"] = f"0x{selected_cipher:04x}"
            except Exception:
                pass

    return tls_info


def parse_http_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """Checks if raw payload contains HTTP request or response and parses it."""
    try:
        text = payload.decode('latin1')
    except Exception:
        return None

    first_line_end = text.find('\r\n')
    if first_line_end == -1:
        first_line_end = text.find('\n')
        if first_line_end == -1:
            return None

    first_line = text[:first_line_end].strip()
    http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT")
    
    # Check for HTTP Request
    if any(first_line.startswith(m + " ") for m in http_methods):
        parts = first_line.split(" ")
        method = parts[0]
        uri = parts[1] if len(parts) > 1 else "/"
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        headers = {}
        header_section = text[first_line_end:].split("\r\n\r\n")[0]
        for line in header_section.split("\r\n"):
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.strip()] = v.strip()

        body = ""
        if "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1]

        return {
            "type": "request",
            "method": method,
            "uri": uri,
            "version": version,
            "headers": headers,
            "host": headers.get("Host", ""),
            "user_agent": headers.get("User-Agent", ""),
            "content_type": headers.get("Content-Type", ""),
            "content_length": headers.get("Content-Length", len(body)),
            "body_preview": body[:500] if body else ""
        }

    # Check for HTTP Response
    if first_line.startswith("HTTP/1.0 ") or first_line.startswith("HTTP/1.1 ") or first_line.startswith("HTTP/2 "):
        parts = first_line.split(" ", 2)
        version = parts[0]
        status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 200
        reason = parts[2] if len(parts) > 2 else "OK"

        headers = {}
        header_section = text[first_line_end:].split("\r\n\r\n")[0]
        for line in header_section.split("\r\n"):
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.strip()] = v.strip()

        body = ""
        if "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1]

        return {
            "type": "response",
            "version": version,
            "status_code": status_code,
            "reason": reason,
            "headers": headers,
            "content_type": headers.get("Content-Type", ""),
            "content_length": headers.get("Content-Length", len(body)),
            "server": headers.get("Server", ""),
            "body_preview": body[:500] if body else ""
        }

    return None


def dissect_packet(pkt: Packet, index: int, base_time: float) -> Dict[str, Any]:
    """Dissects a single Scapy packet across Layer 2, 3, 4, 7 into structured metadata."""
    pkt_time = float(pkt.time) if hasattr(pkt, 'time') else 0.0
    relative_time_ms = round((pkt_time - base_time) * 1000, 2) if base_time > 0 else 0.0

    raw_bytes = bytes(pkt)
    hex_dump = format_hex_dump(raw_bytes)

    # 1. Layer 2: Data Link
    l2_info = None
    if Ether in pkt:
        ether = pkt[Ether]
        eth_type_hex = f"0x{ether.type:04x}"
        eth_type_name = "IPv4" if ether.type == 0x0800 else "ARP" if ether.type == 0x0806 else "IPv6" if ether.type == 0x86DD else eth_type_hex
        l2_info = {
            "name": "Data Link Layer (Ethernet II)",
            "src_mac": ether.src,
            "dst_mac": ether.dst,
            "ethertype": eth_type_name,
            "ethertype_raw": eth_type_hex
        }
    
    arp_info = None
    if ARP in pkt:
        arp = pkt[ARP]
        op_name = "ARP Request (Who has?)" if arp.op == 1 else "ARP Reply (Is at)" if arp.op == 2 else f"ARP Op {arp.op}"
        arp_info = {
            "name": "Address Resolution Protocol (ARP)",
            "operation": op_name,
            "op_code": arp.op,
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst,
            "src_mac": arp.hwsrc,
            "dst_mac": arp.hwdst
        }

    # 2. Layer 3: Network
    l3_info = None
    src_ip = None
    dst_ip = None
    ip_proto = None

    if IP in pkt:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP"}
        ip_proto = proto_map.get(ip.proto, f"Proto-{ip.proto}")
        l3_info = {
            "name": "Network Layer (IPv4)",
            "version": 4,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "ttl": ip.ttl,
            "protocol": ip_proto,
            "protocol_num": ip.proto,
            "header_length": ip.ihl * 4 if hasattr(ip, 'ihl') else 20,
            "total_length": ip.len,
            "id": ip.id,
            "flags": str(ip.flags)
        }
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        src_ip = ip6.src
        dst_ip = ip6.dst
        ip_proto = "IPv6-NextHeader-" + str(ip6.nh)
        l3_info = {
            "name": "Network Layer (IPv6)",
            "version": 6,
            "src_ip": ip6.src,
            "dst_ip": ip6.dst,
            "hop_limit": ip6.hlim,
            "protocol": ip_proto,
            "total_length": ip6.plen
        }
    elif arp_info:
        src_ip = arp_info["src_ip"]
        dst_ip = arp_info["dst_ip"]
        ip_proto = "ARP"

    # ICMP Handling
    icmp_info = None
    if ICMP in pkt:
        icmp = pkt[ICMP]
        icmp_info = {
            "name": "Internet Control Message Protocol (ICMP)",
            "type": icmp.type,
            "type_name": ICMP_TYPES.get(icmp.type, f"Type {icmp.type}"),
            "code": icmp.code,
            "checksum": f"0x{icmp.chksum:04x}" if hasattr(icmp, 'chksum') else None
        }

    # 3. Layer 4: Transport
    l4_info = None
    src_port = None
    dst_port = None
    protocol = ip_proto or "Unknown"

    raw_payload = bytes()
    if Raw in pkt:
        raw_payload = bytes(pkt[Raw])

    if TCP in pkt:
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        protocol = "TCP"
        
        # TCP Flags dissection
        flags_int = int(tcp.flags)
        flags_dict = {
            "SYN": bool(flags_int & 0x02),
            "ACK": bool(flags_int & 0x10),
            "FIN": bool(flags_int & 0x01),
            "RST": bool(flags_int & 0x04),
            "PSH": bool(flags_int & 0x08),
            "URG": bool(flags_int & 0x20),
            "ECE": bool(flags_int & 0x40),
            "CWR": bool(flags_int & 0x80)
        }
        active_flags = [k for k, v in flags_dict.items() if v]

        l4_info = {
            "name": "Transport Layer (TCP)",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "src_service": PORT_SERVICES.get(tcp.sport),
            "dst_service": PORT_SERVICES.get(tcp.dport),
            "seq": tcp.seq,
            "ack": tcp.ack,
            "window": tcp.window,
            "flags": active_flags,
            "flags_str": "+".join(active_flags) if active_flags else "None",
            "flags_raw": str(tcp.flags),
            "flags_map": flags_dict,
            "data_offset": tcp.dataofs * 4 if hasattr(tcp, 'dataofs') else 20,
            "payload_length": len(raw_payload)
        }
    elif UDP in pkt:
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        protocol = "UDP"
        l4_info = {
            "name": "Transport Layer (UDP)",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "src_service": PORT_SERVICES.get(udp.sport),
            "dst_service": PORT_SERVICES.get(udp.dport),
            "length": udp.len,
            "payload_length": len(raw_payload)
        }

    # 4. Layer 7: Application
    l7_info = None
    app_protocol = None

    # DNS Parsing
    if DNS in pkt:
        dns = pkt[DNS]
        app_protocol = "DNS"
        
        queries = []
        if dns.qdcount > 0 and hasattr(dns, 'qd') and dns.qd:
            curr = dns.qd
            while curr:
                qname = curr.qname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(curr, 'qname') and curr.qname else ""
                qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 12: "PTR"}
                qtype = qtype_map.get(curr.qtype, f"TYPE-{curr.qtype}")
                queries.append({"name": qname, "type": qtype})
                curr = curr.payload if hasattr(curr, 'payload') and isinstance(curr.payload, DNSQR) else None

        answers = []
        if dns.ancount > 0 and hasattr(dns, 'an') and dns.an:
            curr = dns.an
            while curr:
                rrname = curr.rrname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(curr, 'rrname') and curr.rrname else ""
                type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS"}
                atype = type_map.get(curr.type, f"TYPE-{curr.type}")
                rdata = str(curr.rdata) if hasattr(curr, 'rdata') else ""
                if isinstance(curr.rdata, bytes):
                    rdata = curr.rdata.decode('utf-8', errors='ignore')
                answers.append({
                    "name": rrname,
                    "type": atype,
                    "data": rdata,
                    "ttl": getattr(curr, 'ttl', 0)
                })
                curr = curr.payload if hasattr(curr, 'payload') and isinstance(curr.payload, DNSRR) else None

        l7_info = {
            "name": "Application Layer (Domain Name System - DNS)",
            "protocol": "DNS",
            "is_response": bool(dns.qr),
            "id": f"0x{dns.id:04x}",
            "opcode": dns.opcode,
            "rcode": dns.rcode,
            "rcode_name": "No Error" if dns.rcode == 0 else f"Error ({dns.rcode})",
            "queries": queries,
            "answers": answers,
            "summary": f"{'DNS Response' if dns.qr else 'DNS Query'}: {queries[0]['name'] if queries else ''} -> {answers[0]['data'] if answers else ''}"
        }

    # HTTP Parsing
    if not l7_info and raw_payload:
        http_data = parse_http_payload(raw_payload)
        if http_data:
            app_protocol = "HTTP"
            l7_info = {
                "name": f"Application Layer (HTTP {http_data.get('type', '').title()})",
                "protocol": "HTTP",
                **http_data
            }

    # TLS Parsing
    if not l7_info and raw_payload:
        tls_data = parse_tls_payload(raw_payload)
        if tls_data:
            app_protocol = "TLS"
            l7_info = {
                "name": f"Application Layer ({tls_data.get('tls_version', 'TLS')} / {tls_data.get('content_type', '')})",
                "protocol": "TLS",
                **tls_data
            }

    # Final overall protocol determination
    primary_protocol = app_protocol or protocol or (arp_info and "ARP") or "Ethernet"

    # Human-readable summary of this packet
    summary_text = ""
    if arp_info:
        summary_text = f"ARP: {arp_info['operation']} - {arp_info['src_ip']} -> {arp_info['dst_ip']}"
    elif l7_info and l7_info.get("protocol") == "DNS":
        summary_text = l7_info.get("summary", "DNS Packet")
    elif l7_info and l7_info.get("protocol") == "HTTP":
        if l7_info.get("type") == "request":
            summary_text = f"HTTP {l7_info.get('method')} {l7_info.get('uri')} (Host: {l7_info.get('host')})"
        else:
            summary_text = f"HTTP {l7_info.get('status_code')} {l7_info.get('reason')} ({l7_info.get('content_type', '')})"
    elif l7_info and l7_info.get("protocol") == "TLS":
        handshake = l7_info.get("handshake_type")
        sni = l7_info.get("sni")
        if handshake:
            summary_text = f"TLS {handshake}{f' (SNI: {sni})' if sni else ''}"
        else:
            summary_text = f"TLS {l7_info.get('content_type', 'Data')} ({l7_info.get('record_length', 0)} bytes)"
    elif icmp_info:
        summary_text = f"ICMP {icmp_info['type_name']} (Code {icmp_info['code']})"
    elif l4_info and l4_info.get("name", "").startswith("Transport Layer (TCP)"):
        flags_str = l4_info.get("flags_str", "")
        summary_text = f"TCP {src_port} \u2192 {dst_port} [{flags_str}] Seq={l4_info.get('seq')} Ack={l4_info.get('ack')} Win={l4_info.get('window')} Len={l4_info.get('payload_length')}"
    elif l4_info and l4_info.get("name", "").startswith("Transport Layer (UDP)"):
        summary_text = f"UDP {src_port} \u2192 {dst_port} Len={l4_info.get('length')}"
    else:
        summary_text = f"{primary_protocol} Packet #{index}"

    return {
        "index": index,
        "timestamp": pkt_time,
        "relative_time_ms": relative_time_ms,
        "length": len(raw_bytes),
        "protocol": primary_protocol,
        "summary": summary_text,
        "src_ip": src_ip or (arp_info and arp_info.get("src_ip")),
        "dst_ip": dst_ip or (arp_info and arp_info.get("dst_ip")),
        "src_port": src_port,
        "dst_port": dst_port,
        "l2": l2_info,
        "arp": arp_info,
        "l3": l3_info,
        "icmp": icmp_info,
        "l4": l4_info,
        "l7": l7_info,
        "hex_dump": hex_dump
    }


def parse_pcap_file(filepath: str) -> List[Dict[str, Any]]:
    """Reads a .pcap / .pcapng file and returns a list of dissected packets."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    packets = rdpcap(filepath)
    if not packets:
        return []

    base_time = float(packets[0].time) if hasattr(packets[0], 'time') else 0.0
    dissected = []

    for idx, pkt in enumerate(packets):
        packet_dict = dissect_packet(pkt, idx + 1, base_time)
        dissected.append(packet_dict)

    return dissected
