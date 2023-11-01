import logging
import os
import socket
import sys

from Crypto.Cipher import AES

logging.basicConfig(
    format="%(asctime)s: %(levelname)s: %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

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
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(data[BLOCK_SIZE:])

    return _remove_padding(decrypted_data)


if len(sys.argv) != 2:
    logger.error("Usage: python server.py <port>")
    sys.exit(1)

try:
    port = int(sys.argv[1])
except ValueError:
    logger.error("Invalid port number")
    sys.exit(1)

try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as e:
    logger.error("Error creating socket: {}".format(e))
    sys.exit(1)

host = socket.gethostname()
myIP = socket.gethostbyname(host)

try:
    server_socket.bind((host, port))
except socket.error as e:
    logger.error("Error binding socket: {}".format(e))
    sys.exit(1)

server_socket.listen(1)

logger.info("Server is listening on {}:{}".format(myIP, port))

while True:
    try:
        client_socket, addr = server_socket.accept()
        logger.info("Got a connection from {}".format(addr))
    except socket.error as e:
        logger.error("Error accepting connection: {}".format(e))
        continue

    data = client_socket.recv(1024)

    try:
        decrypted_data = _decrypt(data)
        if decrypted_data == None:
            raise Exception("Padding error")
    except Exception as e:
        logger.error("Error decrypting data: {}".format(e))
        client_socket.send(b"0")
        continue

    logger.info("Decrypted data: {}".format(decrypted_data))
    client_socket.send(b"1")

    client_socket.close()
