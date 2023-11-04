import logging
import os
import socket
import sys

from shared import HASH_SIZE, encrypt


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)


KEY = b"m\x856n\xb4\xccF\xa7\xb0\xaas\x9cr\xe08\xce"
"""
Hash size is subtracted from the max message length because the hash is appended to the message before encryption.

It could be added, but that would result in an additional block.

256 is chose arbitrarily. The current demonstration is limited by the length of bytes sent through the socket; 1024.

This limit can be removed by looping through the message and sending / receiving it in chunks.
"""
MAX_MESSAGE_LENGTH = 256 - HASH_SIZE


if len(sys.argv) != 3:
    logger.error(
        f"Usage: python {os.path.basename(__file__)} <server_address> <server_port>"
    )
    sys.exit(1)

SERVER_ADDRESS = sys.argv[1]

try:
    SERVER_PORT = int(sys.argv[2])
except ValueError:
    logger.error("Invalid port number")
    sys.exit(1)


try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_ADDRESS, SERVER_PORT))
    iv = client_socket.recv(1024)
except ConnectionRefusedError:
    logger.exception("Connection refused")
    sys.exit(1)
except socket.error as e:
    logger.exception("Error receiving iv")

while True:
    message = input("Enter message: ")
    if len(message) > MAX_MESSAGE_LENGTH:
        logger.error(f"Message too long. Max {MAX_MESSAGE_LENGTH} characters.")
        continue
    message = bytes(message, "utf-8")
    break

try:
    client_socket.send(encrypt(KEY, iv, message))

    data = client_socket.recv(1024)

    if data == b"1":
        logger.info("Message sent successfully")
    else:
        logger.error("Error sending message")
except socket.error as e:
    logger.exception("Error sending data")
finally:
    client_socket.close()
