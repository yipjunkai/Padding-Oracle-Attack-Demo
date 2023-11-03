import logging
import os
import socket
import sys

from Crypto.Cipher import AES
from Crypto import Random

from shared import decrypt


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)


BLOCK_SIZE = AES.block_size
IV = Random.new().read(BLOCK_SIZE)
KEY = b"m\x856n\xb4\xccF\xa7\xb0\xaas\x9cr\xe08\xce"


if len(sys.argv) != 2:
    logger.error(f"Usage: python {os.path.basename(__file__)} <port>")
    sys.exit(1)

try:
    PORT = int(sys.argv[1])
except ValueError:
    logger.error("Invalid port number")
    sys.exit(1)


try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as e:
    logger.exception("Error creating socket")
    sys.exit(1)

host = socket.gethostname()
ip = socket.gethostbyname(host)

try:
    server_socket.bind((host, PORT))
except socket.error as e:
    logger.exception("Error binding socket")
    sys.exit(1)

server_socket.listen(1)

logger.info(f"Server is listening on {ip}:{PORT}")

while True:
    try:
        client_socket, addr = server_socket.accept()
        client_socket.send(IV)
        logger.info(f"Got a connection from {addr}")

        data = client_socket.recv(1024)
        decrypted_data = decrypt(KEY, data)
    except ConnectionError:
        logger.exception("Error with socket connection")
        client_socket.send(b"0")
        client_socket.close()
        continue
    except socket.error as e:
        logger.exception("Error receiving data")
        client_socket.send(b"0")
        client_socket.close()
        continue
    except Exception as e:
        logger.exception("Error decrypting data")
        client_socket.send(b"0")
        client_socket.close()
        continue

    logger.info(f"Decrypted data: {decrypted_data}")
    client_socket.send(b"1")
    client_socket.close()
