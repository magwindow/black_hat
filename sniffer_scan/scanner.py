#!/usr/bin/env python3
import sys
import os
import time
import socket
import struct
import threading
from netaddr import IPNetwork, IPAddress

# Usage: python scanner.py <listen_ip> <target_subnet>
# Example: python scanner.py 192.168.0.11 192.168.0.0/24

if len(sys.argv) != 3:
    print("Usage: python scanner.py <listen_ip> <target_subnet>")
    sys.exit(1)

HOST = sys.argv[1]
SUBNET = sys.argv[2]
MAGIC = b"PYTHONRULES!"
UDP_PORT = 65212  # high port unlikely to be open

def hexdump(src, length=16):
    if not src:
        return
    result_lines = []
    for i in range(0, len(src), length):
        chunk = src[i:i+length]
        hexa = " ".join(f"{b:02X}" for b in chunk)
        text = "".join((chr(b) if 0x20 <= b < 0x7f else ".") for b in chunk)
        result_lines.append(f"{i:04X}   {hexa:<{length*3}}   {text}")
    print("\n".join(result_lines))

def parse_ip_header(buffer):
    """Парсим первые 20 байт IP заголовка (network order). Возвращаем dict."""
    if len(buffer) < 20:
        return None
    ver_ihl = buffer[0]
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    # unpack rest with struct for clarity
    (tos, total_len, ident, flags_offset, ttl, proto, chksum, src, dst) = struct.unpack("!BHHHBBHII", buffer[1:20])
    src_addr = socket.inet_ntoa(struct.pack("!I", src))
    dst_addr = socket.inet_ntoa(struct.pack("!I", dst))
    return {
        "version": version,
        "ihl": ihl,
        "tos": tos,
        "len": total_len,
        "id": ident,
        "offset": flags_offset,
        "ttl": ttl,
        "protocol": proto,
        "checksum": chksum,
        "src": src_addr,
        "dst": dst_addr,
    }

def sniff():
    """Сниффер — принимает IP пакеты и обрабатывает ICMP ответы."""
    if os.name == "nt":
        sock_proto = socket.IPPROTO_IP
    else:
        sock_proto = socket.IPPROTO_ICMP

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
    except PermissionError:
        print("[!] Need to run as Administrator/root to create raw socket.")
        return
    except Exception as e:
        print("[!] Socket error:", e)
        return

    try:
        sniffer.bind((HOST, 0))
    except Exception as e:
        print(f"[!] Failed to bind to {HOST}: {e}")
        sniffer.close()
        return

    # include IP headers
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Windows-specific: enable promiscuous mode
    if os.name == "nt":
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print("[*] RCVALL enabled (Windows).")
        except Exception as e:
            print("[!] Failed to enable RCVALL:", e)
            sniffer.close()
            return

    print(f"[*] Sniffer started on {HOST}, listening for ICMP responses...")

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            if not raw_buffer:
                continue
            ip = parse_ip_header(raw_buffer)
            if not ip:
                continue

            # only interested in ICMP (protocol number 1)
            if ip["protocol"] == 1:
                # calculate IP header length in bytes
                ip_header_len = ip["ihl"] * 4
                # ICMP header is 8 bytes; ICMP payload contains original IP header + first 8 bytes of data
                icmp_offset = ip_header_len
                if len(raw_buffer) >= icmp_offset + 8:
                    icmp_header = raw_buffer[icmp_offset:icmp_offset+8]
                    icmp_type, icmp_code, icmp_chksum = struct.unpack("!BBH", icmp_header[:4])
                    # trailing payload (original datagram header + some bytes)
                    icmp_payload = raw_buffer[icmp_offset+8:]
                    # check for Port Unreachable (type 3, code 3)
                    if icmp_type == 3 and icmp_code == 3:
                        # check that source is inside target subnet
                        if IPAddress(ip["src"]) in IPNetwork(SUBNET):
                            # check if our magic exists inside the embedded packet payload
                            if MAGIC in icmp_payload:
                                print(f"[+] Host up: {ip['src']}")
                                # optional: show some packet info
                                print(f"    -> ICMP type={icmp_type} code={icmp_code} from {ip['src']} to {ip['dst']}")
                                # optionally hexdump embedded payload
                                # hexdump(icmp_payload[:64])
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer.")
    finally:
        if os.name == "nt":
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                print("[*] RCVALL disabled.")
            except Exception:
                pass
        sniffer.close()

def udp_sender():
    """Рассылает UDP datagrams с MAGIC в указанный subnet на порт UDP_PORT."""
    time.sleep(2)  # дать снифферу время включиться
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.settimeout(0.5)
    print(f"[*] Sending UDP probes to {SUBNET} on port {UDP_PORT}...")
    for ip in IPNetwork(SUBNET):
        # skip network and broadcast addresses (netaddr handles that)
        try:
            sender.sendto(MAGIC, (str(ip), UDP_PORT))
        except Exception:
            pass
    sender.close()
    print("[*] Finished sending probes.")

if __name__ == "__main__":
    # start sniffer thread
    t = threading.Thread(target=sniff, daemon=True)
    t.start()

    # send probes from main thread (or separate thread)
    udp_sender()

    # keep main alive while sniffer runs
    try:
        while t.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting.")
