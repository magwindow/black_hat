import socket

HOST = "127.0.0.1"
PORT = 9001

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
print(f"[echo] Listening on {HOST}:{PORT}")
conn, addr = s.accept()
print("[echo] Connection from", addr)
# необязательно присылать что-то первым — но можно
conn.sendall(b"Hello from remote!\n")
try:
    while True:
        data = conn.recv(4096)
        if not data:
            break
        print("[echo] Received:", data)
        conn.sendall(b"ECHO: " + data)
finally:
    conn.close()
    s.close()