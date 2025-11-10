#!/usr/bin/env python3
import sys
import socket
import threading
import paramiko

# using the key from the Paramiko demo files or one you generated
host_key = paramiko.RSAKey(filename='test_rsa.key')

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # simple hardcoded credential check
        if (username == 'foo') and (password == 'bar'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


def main(listen_host, listen_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_host, listen_port))
        sock.listen(100)
        print(f"[*] Listening for connection on {listen_host}:{listen_port} ...")
        client, addr = sock.accept()
    except Exception as e:
        print("[-] Listen failed: " + str(e))
        sys.exit(1)

    print(f"[*] Got a connection from {addr[0]}:{addr[1]}!")

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = Server()
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            print("[-] SSH negotiation failed.")
            return

        chan = transport.accept(20)
        if chan is None:
            print("[-] No channel.")
            return

        print("[*] Authenticated!")
        # optional: send banner
        chan.send(b"Welcome to bh_ssh!\r\n")

        while True:
            try:
                command = input("Enter command: ").strip()
                if not command:
                    continue
                # send the command (bytes)
                chan.send(command.encode() + b"\n")
                if command.lower() == "exit":
                    print("[*] Exiting and closing transport.")
                    transport.close()
                    break
                # wait for response
                resp = b""
                # read until something arrives (or timeout)
                while True:
                    if chan.recv_ready():
                        resp += chan.recv(4096)
                        # break if small chunk (client likely finished)
                        if len(resp) < 4096:
                            break
                    else:
                        break
                if resp:
                    try:
                        print(resp.decode(errors='ignore'))
                    except:
                        print(resp)
            except KeyboardInterrupt:
                print("\n[*] Keyboard interrupt, closing.")
                transport.close()
                break
    except Exception as e:
        print("[-] Caught exception: " + str(e))
        try:
            transport.close()
        except:
            pass
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python bh_sshserver.py <listen_host> <port>")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    main(host, port)
