#!/usr/bin/env python3
import sys
import socket
import threading

def hexdump(src, length=16):
    """
    Печать шестнадцатеричного и ASCII представления байтов.
    src должно быть bytes.
    """
    if not src:
        return
    result_lines = []
    for i in range(0, len(src), length):
        chunk = src[i:i+length]
        hexa = " ".join(f"{b:02X}" for b in chunk)
        text = "".join((chr(b) if 0x20 <= b < 0x7f else ".") for b in chunk)
        result_lines.append(f"{i:04X}   {hexa:<{length*3}}   {text}")
    print("\n".join(result_lines))


def receive_from(connection, timeout=2):
    buffer = b""
    connection.settimeout(timeout)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
            # если пришло меньше чем буфер — возможно больше не будет данных сейчас
            if len(data) < 4096:
                break
    except socket.timeout:
        # таймаут — возвращаем то, что накопили
        pass
    except Exception:
        pass
    return buffer


def request_handler(buffer):
    # place to modify requests going to remote host
    return buffer


def response_handler(buffer):
    # place to modify responses going back to client
    return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = None
    try:
        # подключаемся к удалённому хосту
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((remote_host, remote_port))

        # если нужно — сначала получить данные от удалённого и отправить клиенту
        if receive_first:
            remote_buffer = receive_from(remote_socket)
            if remote_buffer:
                print(f"[<==] Received {len(remote_buffer)} bytes from remote (first).")
                hexdump(remote_buffer)
                remote_buffer = response_handler(remote_buffer)
                client_socket.sendall(remote_buffer)

        # основной цикл проксирования
        while True:
            local_buffer = receive_from(client_socket)
            if local_buffer:
                print(f"[==>] Received {len(local_buffer)} bytes from localhost.")
                hexdump(local_buffer)
                local_buffer = request_handler(local_buffer)
                remote_socket.sendall(local_buffer)
                print("[==>] Sent to remote.")

            remote_buffer = receive_from(remote_socket)
            if remote_buffer:
                print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
                hexdump(remote_buffer)
                remote_buffer = response_handler(remote_buffer)
                client_socket.sendall(remote_buffer)
                print("[<==] Sent to localhost.")

            # если никаких данных нет от обеих сторон — завершаем
            if not local_buffer and not remote_buffer:
                # можно ждать ещё цикл или закрыть
                client_socket.close()
                remote_socket.close()
                print("[*] No more data. Closing connections.")
                break
    except Exception as e:
        print(f"[!] Proxy handler exception: {e}")
    finally:
        try:
            if client_socket:
                client_socket.close()
        except Exception:
            pass
        try:
            if remote_socket:
                remote_socket.close()
        except Exception:
            pass


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print(f"[!!] Failed to listen on {local_host}:{local_port}: {e}")
        sys.exit(1)

    print(f"[*] Listening on {local_host}:{local_port}")
    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        print(f"[==>] Received incoming connection from {addr[0]}:{addr[1]}")
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first),
        )
        proxy_thread.daemon = True
        proxy_thread.start()


def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: python proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("Example: python proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = sys.argv[5].lower() in ("true", "1", "yes")

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)


if __name__ == "__main__":
    main()
