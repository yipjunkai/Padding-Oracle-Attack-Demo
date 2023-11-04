import logging
import os
import socket
import sys

from Crypto import Random

from shared import BLOCK_SIZE, decrypt


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)


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
server_socket.settimeout(1)

logger.info(f"Server is listening on {ip}:{PORT}")

try:
    while True:
        try:
            client_socket, addr = server_socket.accept()
            iv = Random.new().read(BLOCK_SIZE)
            client_socket.send(iv)
            logger.info(f"Got a connection from {addr}")

            data = client_socket.recv(1024)
            if data == b"":
                raise ConnectionError("Connection closed by client")
            decrypted_data = decrypt(KEY, data)
            if decrypted_data is None:
                raise Exception("Error decrypting data")
        except ConnectionError:
            logger.exception("Error with socket connection")
            client_socket.send(b"0")
            client_socket.close()
            continue
        except socket.timeout:
            continue
        except socket.error as e:
            logger.exception("Error receiving data")
            client_socket.send(b"0")
            client_socket.close()
            continue
        except Exception as e:
            logger.exception("General error")
            client_socket.send(b"0")
            client_socket.close()
            continue

        logger.info(f"Decrypted data: {decrypted_data}")
        client_socket.send(b"1")
        client_socket.close()
except KeyboardInterrupt:
    logger.info("Shutting down server")
    server_socket.close()
    sys.exit(0)
