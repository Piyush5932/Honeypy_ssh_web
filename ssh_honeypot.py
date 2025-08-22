# Libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading

# Constants
logging_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# Ensure 'server.key' exists in the same directory or provide the full path
try:
    host_key = paramiko.RSAKey(filename='server.key')
except paramiko.ssh_exception.PasswordRequiredException:
    print("Error: The private key file 'server.key' is encrypted and requires a password.")
    print("Please ensure it's a passwordless key or handle password input.")
    exit()
except FileNotFoundError:
    print("Error: The private key file 'server.key' was not found.")
    print("Please generate a key using 'ssh-keygen -t rsa -f server.key' or provide the correct path.")
    exit()

# Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# Emulated Shell
def emulated_shell(channel, client_ip):
    channel.send(b"corporate-jumpbox2$ ")
    command = b""
    while True:
        char = channel.recv(1)
        if not char:
            print(f"Client {client_ip} disconnected.")
            break
        channel.send(char)
        command += char
        if char == b"\r":
            decoded_command = command.strip().decode('utf-8', errors='ignore')
            response = b""
            if decoded_command == 'exit':
                response = b"\n Goodbye!\n"
                channel.send(response)
                break
            elif decoded_command == 'pwd':
                response = b"\n/usr/local\r\n"
                creds_logger.info(f'Command {decoded_command} executed by {client_ip}')
            elif decoded_command == 'whoami':
                response = b"\ncorpuser1\r\n"
                creds_logger.info(f'Command {decoded_command} executed by {client_ip}')
            elif decoded_command == 'ls':
                response = b"\njumpbox1.conf\r\n"
                creds_logger.info(f'Command {decoded_command} executed by {client_ip}')
            elif decoded_command == 'cat jumpbox1.conf':
                response = b"\nGo to deeboodah.com\r\n"
                creds_logger.info(f'Command {decoded_command} executed by {client_ip}')
            else:
                response = b"\n" + command.strip() + b"\r\n"
                creds_logger.info(f'Unknown command {decoded_command} executed by {client_ip}')
            channel.send(response)
            channel.send(b"corporate-jumpbox2$ ")
            command = b""
    channel.close()

# SSH Server + Sockets
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.authenticated = False

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'{self.client_ip} attempted login with username: {username}, password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                self.authenticated = True
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            self.authenticated = True
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        if self.authenticated:
            self.event.set()
            return True
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        if self.authenticated:
            return True
        return False

    def check_channel_exec_request(self, channel, command):
        if self.authenticated:
            decoded_command = command.decode('utf-8', errors='ignore').strip()
            funnel_logger.info(f'{self.client_ip} attempted to execute: {decoded_command}')
            # You might want to handle specific exec requests here if needed
            return True
        return False

def client_handle(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)
        channel = transport.accept(20)  # Reduced timeout for testing
        if channel is not None:
            print(f"{client_ip} established an SSH channel.")
            server.event.wait(60)  # Wait for shell request
            if server.authenticated and server.event.is_set():
                emulated_shell(channel, client_ip=client_ip)
            else:
                print(f"{client_ip} authentication failed or no shell requested.")
                channel.close()
        else:
            print(f"{client_ip} did not establish a channel within the timeout.")

    except Exception as error:
        print(f"Error handling client {client_ip}: {error}")

    finally:
        if transport and transport.is_active():
            try:
                transport.close()
            except Exception as error:
                print(f"Error closing transport for {client_ip}: {error}")
        print(f"Connection with {client_ip} closed.")

# Provision SSH-based Honeypot
def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        socks.bind((address, port))
        socks.listen(100)
        print(f"SSH server is listening on {address}:{port}.")
        while True:
            client, addr = socks.accept()
            print(f"Incoming connection from {addr[0]}:{addr[1]}")
            client_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        print(f"Error starting the honeypot: {e}")
    finally:
        if 'socks' in locals():
            socks.close()

if __name__ == "__main__":
    # Configure the honeypot settings
    honeypot_address = '127.0.0.1'  # Listen on all interfaces
    honeypot_port = 2223
    expected_username = 'username'
    expected_password = 'password'

    honeypot(honeypot_address, honeypot_port, expected_username, expected_password)