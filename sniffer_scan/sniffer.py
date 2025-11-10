#!/usr/bin/env python3
import os
import socket
import struct
import sys

# Вставь IP интерфейса своей машины (или 0.0.0.0 / 127.0.0.1)
HOST = "192.168.0.11"


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
    """Парсим 20-байтный IP заголовок (network byte order). Возвращаем dict."""
    if len(buffer) < 20:
        return None
    # ! - network byte order, B B H H H B B H 4s 4s
    ver_ihl, tos, total_len, ident, flags_offset, ttl, proto, chksum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", buffer[:20]
    )
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    src_addr = socket.inet_ntoa(src)
    dst_addr = socket.inet_ntoa(dst)
    return {
        "version": version,
        "ihl": ihl,
        "tos": tos,
        "len": total_len,
        "id": ident,
        "offset": flags_offset,
        "ttl": ttl,
        "protocol_num": proto,
        "checksum": chksum,
        "src": src_addr,
        "dst": dst_addr,
    }


def main(host):
    # настройка сокета в зависимости от платформы
    if os.name == "nt":
        sock_proto = socket.IPPROTO_IP
    else:
        # на Unix/Linux чаще используют IPPROTO_ICMP для raw или AF_PACKET
        sock_proto = socket.IPPROTO_ICMP

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
    except PermissionError as e:
        print("[!] Permission error: you must run as administrator/root to open raw sockets.")
        print(e)
        sys.exit(1)
    except Exception as e:
        print("[!] Failed to create raw socket:", e)
        sys.exit(1)

    try:
        sniffer.bind((host, 0))
    except Exception as e:
        print(f"[!] Failed to bind to {host}: {e}")
        sniffer.close()
        sys.exit(1)

    # Включаем захват заголовков IP
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Включаем promiscuous mode только для Windows
    if os.name == "nt":
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print("[*] RCVALL enabled (Windows).")
        except Exception as e:
            print("[!] Failed to enable RCVALL:", e)
            sniffer.close()
            sys.exit(1)

    print(f"[*] Sniffer started on {host}. Press Ctrl-C to stop.")

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            if not raw_buffer:
                continue
            ip_info = parse_ip_header(raw_buffer)
            if ip_info:
                print(f"\nProtocol: {ip_info['protocol_num']} Source: {ip_info['src']} -> Destination: {ip_info['dst']}")
                # распечатать hexdump первых 64 байт пакета (по желанию)
                hexdump(raw_buffer[:64])
            else:
                print("[!] Received packet too short to parse IP header.")
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer.")
    finally:
        if os.name == "nt":
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                print("[*] RCVALL disabled.")
            except Exception as e:
                print("[!] Failed to disable RCVALL:", e)
        sniffer.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        HOST = sys.argv[1]
    main(HOST)
