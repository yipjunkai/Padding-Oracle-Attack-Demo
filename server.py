import socket
import sys
from Crypto.Cipher import AES

BLOCK_SIZE = AES.block_size


def _remove_padding(data):
    pad_len = data[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        return None
    for i in range(1, pad_len):
        if data[-i - 1] != pad_len:
            return None
    return data[:-pad_len]


def _decrypt(data):
    key = b"m\x856n\xb4\xccF\xa7\xb0\xaas\x9cr\xe08\xce"
    iv = b"\xe1o\x840F\xbd\xe2\x8d\xc7\rxT\x0c\x8f\xb02"
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return _remove_padding(cipher.decrypt(data))


if len(sys.argv) != 2:
    print("Usage: python server.py <port>")
    sys.exit(1)

try:
    port = int(sys.argv[1])
except ValueError:
    print("Invalid port number")
    sys.exit(1)

try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as e:
    print("Error creating socket: {}".format(e))
    sys.exit(1)

host = socket.gethostname()
myIP = socket.gethostbyname(host)

try:
    server_socket.bind((host, port))
except socket.error as e:
    print("Error binding socket: {}".format(e))
    sys.exit(1)

server_socket.listen(1)

print("Server is listening on {}:{}".format(myIP, port))

while True:
    try:
        client_socket, addr = server_socket.accept()
        print("Got a connection from {}".format(addr))
    except socket.error as e:
        print("Error accepting connection: {}".format(e))
        continue

    data = client_socket.recv(1024)

    decrypted_data = _decrypt(data)
    # print("Undecrypted data: {}".format(data))
    print("Decrypted data: {}".format(decrypted_data))

    client_socket.close()
