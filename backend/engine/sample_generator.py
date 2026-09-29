"""
Synthetic PCAP Generator
Builds realistic network packet capture scenarios using Scapy for testing, demos, and educational exploration.
"""

import os
import time
from scapy.all import (
    Ether,
    ARP,
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    wrpcap
)

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def generate_web_browsing_pcap(filepath: str):
    """Scenario 1: Complete Web Browsing Session (ARP -> DNS -> TCP Handshake -> TLS Handshake -> App Data -> Teardown)"""
    client_mac = "00:1a:2b:3c:4d:5e"
    gateway_mac = "00:50:56:c0:00:08"
    server_mac = "52:54:00:12:34:56"
    
    client_ip = "192.168.1.105"
    gateway_ip = "192.168.1.1"
    dns_ip = "8.8.8.8"
    server_ip = "93.184.216.34"  # example.org
    
    client_port = 54320
    server_port = 443
    dns_port = 53
    
    now = time.time()
    packets = []
    
    # 1. ARP Request: Who has 192.168.1.1?
    p1 = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=client_mac, psrc=client_ip, hwdst="00:00:00:00:00:00", pdst=gateway_ip
    )
    p1.time = now + 0.000
    packets.append(p1)
    
    # 2. ARP Reply: 192.168.1.1 is at gateway_mac
    p2 = Ether(src=gateway_mac, dst=client_mac) / ARP(
        op=2, hwsrc=gateway_mac, psrc=gateway_ip, hwdst=client_mac, pdst=client_ip
    )
    p2.time = now + 0.002
    packets.append(p2)
    
    # 3. DNS Query: Standard query A example.com
    p3 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=dns_ip, ttl=64) / UDP(
        sport=49152, dport=dns_port
    ) / DNS(
        id=0x1a2b, qr=0, opcode=0, rd=1, qd=DNSQR(qname="example.com", qtype="A")
    )
    p3.time = now + 0.015
    packets.append(p3)
    
    # 4. DNS Response: example.com has address 93.184.216.34
    p4 = Ether(src=gateway_mac, dst=client_mac) / IP(src=dns_ip, dst=client_ip, ttl=56) / UDP(
        sport=dns_port, dport=49152
    ) / DNS(
        id=0x1a2b, qr=1, opcode=0, ra=1, rcode=0,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", rdata=server_ip, ttl=300)
    )
    p4.time = now + 0.038
    packets.append(p4)
    
    # 5. TCP Handshake: SYN
    seq_c = 1000000000
    seq_s = 2000000000
    
    p5 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(
        sport=client_port, dport=server_port, flags="S", seq=seq_c, window=65535
    )
    p5.time = now + 0.050
    packets.append(p5)
    
    # 6. TCP Handshake: SYN-ACK
    p6 = Ether(src=gateway_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip, ttl=52) / TCP(
        sport=server_port, dport=client_port, flags="SA", seq=seq_s, ack=seq_c + 1, window=65535
    )
    p6.time = now + 0.082
    packets.append(p6)
    
    # 7. TCP Handshake: ACK
    p7 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=65535
    )
    p7.time = now + 0.083
    packets.append(p7)
    
    # 8. TLS Client Hello (Handshake Type 1, SNI example.com)
    sni_bytes = b"example.com"
    sni_ext = b"\x00\x00" + (len(sni_bytes) + 5).to_bytes(2, "big") + (len(sni_bytes) + 3).to_bytes(2, "big") + b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
    ext_len = len(sni_ext).to_bytes(2, "big")
    ciphers_data = b"\x13\x01\x13\x02\xc0\x2f\xc0\x30"  # TLS_AES_128_GCM_SHA256, etc.
    client_hello_body = (
        b"\x03\x03" + os.urandom(32) + b"\x00" +
        len(ciphers_data).to_bytes(2, "big") + ciphers_data +
        b"\x01\x00" + ext_len + sni_ext
    )
    hs_header = b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body
    tls_client_hello = b"\x16\x03\x01" + len(hs_header).to_bytes(2, "big") + hs_header
    
    p8 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(
        sport=client_port, dport=server_port, flags="PA", seq=seq_c + 1, ack=seq_s + 1
    ) / Raw(load=tls_client_hello)
    p8.time = now + 0.095
    packets.append(p8)
    
    # 9. TLS Server Hello
    server_hello_body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x13\x01" + b"\x00\x00\x00"
    sh_header = b"\x02" + len(server_hello_body).to_bytes(3, "big") + server_hello_body
    tls_server_hello = b"\x16\x03\x03" + len(sh_header).to_bytes(2, "big") + sh_header
    
    p9 = Ether(src=gateway_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip, ttl=52) / TCP(
        sport=server_port, dport=client_port, flags="PA", seq=seq_s + 1, ack=seq_c + 1 + len(tls_client_hello)
    ) / Raw(load=tls_server_hello)
    p9.time = now + 0.130
    packets.append(p9)
    
    # 10. TLS Encrypted Application Data (HTTP/2 or HTTP/3 over TLS)
    enc_data = os.urandom(512)
    tls_app_data_req = b"\x17\x03\x03" + len(enc_data).to_bytes(2, "big") + enc_data
    p10 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(
        sport=client_port, dport=server_port, flags="PA", seq=seq_c + 1 + len(tls_client_hello), ack=seq_s + 1 + len(tls_server_hello)
    ) / Raw(load=tls_app_data_req)
    p10.time = now + 0.150
    packets.append(p10)
    
    # 11. TLS Encrypted Application Data (Server Response)
    enc_resp = os.urandom(1250)
    tls_app_data_resp = b"\x17\x03\x03" + len(enc_resp).to_bytes(2, "big") + enc_resp
    p11 = Ether(src=gateway_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip, ttl=52) / TCP(
        sport=server_port, dport=client_port, flags="PA", seq=seq_s + 1 + len(tls_server_hello), ack=seq_c + 1 + len(tls_client_hello) + len(tls_app_data_req)
    ) / Raw(load=tls_app_data_resp)
    p11.time = now + 0.190
    packets.append(p11)
    
    # 12. TCP Teardown: Client FIN-ACK
    seq_c_end = seq_c + 1 + len(tls_client_hello) + len(tls_app_data_req)
    seq_s_end = seq_s + 1 + len(tls_server_hello) + len(tls_app_data_resp)
    
    p12 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(
        sport=client_port, dport=server_port, flags="FA", seq=seq_c_end, ack=seq_s_end
    )
    p12.time = now + 0.250
    packets.append(p12)
    
    # 13. TCP Teardown: Server FIN-ACK
    p13 = Ether(src=gateway_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip, ttl=52) / TCP(
        sport=server_port, dport=client_port, flags="FA", seq=seq_s_end, ack=seq_c_end + 1
    )
    p13.time = now + 0.280
    packets.append(p13)
    
    # 14. TCP Teardown: Client Final ACK
    p14 = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=seq_c_end + 1, ack=seq_s_end + 1
    )
    p14.time = now + 0.281
    packets.append(p14)
    
    wrpcap(filepath, packets)


def generate_cleartext_http_pcap(filepath: str):
    """Scenario 2: Unencrypted Cleartext HTTP Session with Credential Leak (Security Inspection)"""
    client_ip = "192.168.1.77"
    server_ip = "10.0.0.50"
    client_mac = "00:11:22:33:44:55"
    server_mac = "aa:bb:cc:dd:ee:ff"
    
    now = time.time()
    packets = []
    
    # 1. TCP Handshake SYN
    p1 = Ether(src=client_mac, dst=server_mac) / IP(src=client_ip, dst=server_ip) / TCP(
        sport=51200, dport=80, flags="S", seq=500000
    )
    p1.time = now
    packets.append(p1)
    
    # 2. TCP Handshake SYN-ACK
    p2 = Ether(src=server_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip) / TCP(
        sport=80, dport=51200, flags="SA", seq=800000, ack=500001
    )
    p2.time = now + 0.01
    packets.append(p2)
    
    # 3. TCP Handshake ACK
    p3 = Ether(src=client_mac, dst=server_mac) / IP(src=client_ip, dst=server_ip) / TCP(
        sport=51200, dport=80, flags="A", seq=500001, ack=800001
    )
    p3.time = now + 0.012
    packets.append(p3)
    
    # 4. HTTP POST /api/login with cleartext credentials
    http_req = (
        b"POST /api/v1/auth/login HTTP/1.1\r\n"
        b"Host: internal-bank.corp\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 39\r\n"
        b"\r\n"
        b"username=admin_root&password=SuperSecret99!"
    )
    p4 = Ether(src=client_mac, dst=server_mac) / IP(src=client_ip, dst=server_ip) / TCP(
        sport=51200, dport=80, flags="PA", seq=500001, ack=800001
    ) / Raw(load=http_req)
    p4.time = now + 0.035
    packets.append(p4)
    
    # 5. HTTP 200 OK Response with Session Cookie
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.52 (Ubuntu)\r\n"
        b"Set-Cookie: session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; Path=/; HttpOnly\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 48\r\n"
        b"\r\n"
        b"{\"status\":\"success\",\"message\":\"Authentication OK\"}"
    )
    p5 = Ether(src=server_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip) / TCP(
        sport=80, dport=51200, flags="PA", seq=800001, ack=500001 + len(http_req)
    ) / Raw(load=http_resp)
    p5.time = now + 0.065
    packets.append(p5)
    
    # 6. HTTP GET /account/balance
    http_req2 = (
        b"GET /account/balance HTTP/1.1\r\n"
        b"Host: internal-bank.corp\r\n"
        b"Cookie: session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n"
        b"\r\n"
    )
    p6 = Ether(src=client_mac, dst=server_mac) / IP(src=client_ip, dst=server_ip) / TCP(
        sport=51200, dport=80, flags="PA", seq=500001 + len(http_req), ack=800001 + len(http_resp)
    ) / Raw(load=http_req2)
    p6.time = now + 0.090
    packets.append(p6)
    
    # 7. HTTP 200 OK with Balance Data
    http_resp2 = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 52\r\n"
        b"\r\n"
        b"{\"account_no\":\"4489-0012-9981\",\"balance\":125000.50}"
    )
    p7 = Ether(src=server_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip) / TCP(
        sport=80, dport=51200, flags="PA", seq=800001 + len(http_resp), ack=500001 + len(http_req) + len(http_req2)
    ) / Raw(load=http_resp2)
    p7.time = now + 0.110
    packets.append(p7)
    
    # 8. FIN Teardown
    p8 = Ether(src=client_mac, dst=server_mac) / IP(src=client_ip, dst=server_ip) / TCP(
        sport=51200, dport=80, flags="FA", seq=500001 + len(http_req) + len(http_req2), ack=800001 + len(http_resp) + len(http_resp2)
    )
    p8.time = now + 0.150
    packets.append(p8)
    
    wrpcap(filepath, packets)


def generate_tcp_reset_pcap(filepath: str):
    """Scenario 3: TCP Connection Anomaly / Port Closed (SYN followed by immediate RST)"""
    client_ip = "192.168.1.120"
    server_ip = "203.0.113.88"
    client_mac = "00:aa:bb:cc:dd:ee"
    router_mac = "00:50:56:00:11:22"
    
    now = time.time()
    packets = []
    
    # 1. SYN to closed port 8080
    p1 = Ether(src=client_mac, dst=router_mac) / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(
        sport=61001, dport=8080, flags="S", seq=333000
    )
    p1.time = now
    packets.append(p1)
    
    # 2. Server responds with RST-ACK (Connection Refused)
    p2 = Ether(src=router_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip, ttl=53) / TCP(
        sport=8080, dport=61001, flags="RA", seq=0, ack=333001
    )
    p2.time = now + 0.025
    packets.append(p2)
    
    # 3. Retry SYN (Retransmission attempt)
    p3 = Ether(src=client_mac, dst=router_mac) / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(
        sport=61001, dport=8080, flags="S", seq=333000
    )
    p3.time = now + 1.000
    packets.append(p3)
    
    # 4. Immediate RST again
    p4 = Ether(src=router_mac, dst=client_mac) / IP(src=server_ip, dst=client_ip, ttl=53) / TCP(
        sport=8080, dport=61001, flags="RA", seq=0, ack=333001
    )
    p4.time = now + 1.028
    packets.append(p4)
    
    wrpcap(filepath, packets)


def generate_all_samples():
    """Generates all standard sample PCAPs into backend/samples/ directory."""
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    
    s1 = os.path.join(SAMPLES_DIR, "web_browsing_full.pcap")
    s2 = os.path.join(SAMPLES_DIR, "cleartext_http_audit.pcap")
    s3 = os.path.join(SAMPLES_DIR, "tcp_reset_anomaly.pcap")
    
    generate_web_browsing_pcap(s1)
    generate_cleartext_http_pcap(s2)
    generate_tcp_reset_pcap(s3)
    
    return [s1, s2, s3]


if __name__ == "__main__":
    generate_all_samples()
    print("Generated sample PCAPs successfully.")
