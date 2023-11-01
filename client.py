import socket
import sys
from Crypto.Cipher import AES

KEY_LENGTH = 16  # AES128
BLOCK_SIZE = AES.block_size


def _add_padding(msg):
    pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    padding = bytes([pad_len]) * pad_len
    return msg + padding


def encrypt(iv, msg):
    key = b"m\x856n\xb4\xccF\xa7\xb0\xaas\x9cr\xe08\xce"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(_add_padding(msg))


if len(sys.argv) != 3:
    print("Usage: python client.py <server_address> <server_port>")
    sys.exit(1)

SERVER_ADDRESS = sys.argv[1]

try:
    SERVER_PORT = int(sys.argv[2])
except ValueError:
    print("Invalid port number")
    sys.exit(1)

while True:
    message = input("Enter message: ")
    if len(message) > 16:
        print("Message too long. Max 16 characters.")
        continue
    message = bytes(message, "utf-8")
    break

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_ADDRESS, SERVER_PORT))
    iv = client_socket.recv(1024)
    client_socket.sendall(encrypt(iv, message))

    data = client_socket.recv(1024)

    if data == b"1":
        print(True)
    else:
        print(False)
except ConnectionRefusedError:
    print("Connection refused. Please check the server address and port.")
    sys.exit(1)
finally:
    client_socket.close()
