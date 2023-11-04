import logging
import os
import socket
import sys

from Crypto.Cipher import AES
from tqdm import tqdm

from shared import remove_padding


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)


BLOCK_SIZE = AES.block_size


def check_against_server(msg: bytes) -> bool:
    try:
        proxy_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_server_socket.connect((SERVER_ADDRESS, SERVER_PORT))
        proxy_server_socket.recv(1024)  # receive iv
        proxy_server_socket.send(msg)
        data = proxy_server_socket.recv(1024)
    except ConnectionRefusedError:
        logger.exception("Connection refused")
        sys.exit(1)
    except socket.error as e:
        logger.exception("Error creating socket")
        sys.exit(1)

    if data == b"1":
        return True

    return False


def attack_data(ciphertext: bytes) -> bytes:
    plain_text = b""

    start = len(ciphertext) - (BLOCK_SIZE * 2)
    end = len(ciphertext)
    num_of_blocks = len(ciphertext) // BLOCK_SIZE
    for __block in tqdm(range(num_of_blocks, 1, -1), leave=False):
        plain_text = attack(ciphertext[start:end]) + plain_text
        start -= 16
        end -= 16
    return plain_text


def attack(ciphertext: bytes) -> bytes:
    segment = bytearray([0] * 16)
    temp = bytearray([0] * 16)
    mod = bytearray([0] * 16)

    iv_block = ciphertext[:16]
    cipher_block = ciphertext[16:32]

    multiplier = 0

    for index in tqdm(range(15, -1, -1), leave=False):
        multiplier += 1
        extra_bytes = b""
        for inner_index in tqdm(range(15, 15 - (multiplier - 1), -1), leave=False):
            mod[inner_index] = multiplier ^ temp[inner_index]
            extra_bytes = bytes((mod[inner_index],)) + extra_bytes

        for i in tqdm(range(1, 256), leave=False):
            modified_block0 = iv_block[:-multiplier] + bytes((i,)) + extra_bytes
            modified_ciphertext = modified_block0 + cipher_block
            if check_against_server(modified_ciphertext):
                if multiplier == 16:
                    break
                second_modified_block0 = (
                    modified_block0[: -(multiplier + 1)]
                    + b"\xFF"
                    + modified_block0[index:]
                )
                test_correctness = second_modified_block0 + cipher_block
                if check_against_server(test_correctness):
                    break

        temp[index] = i ^ multiplier
        segment[index] = iv_block[index] ^ temp[index]

    return bytes(segment)


if len(sys.argv) != 4:
    logger.error(
        f"Usage: python {os.path.basename(__file__)} <server_address> <server_port> <proxy_port>"
    )
    sys.exit(1)

SERVER_ADDRESS = sys.argv[1]

try:
    SERVER_PORT = int(sys.argv[2])
    PROXY_PORT = int(sys.argv[3])
except ValueError:
    logger.error("Invalid port number")
    sys.exit(1)


try:
    client_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as e:
    logger.exception("Error creating socket")
    sys.exit(1)

host = socket.gethostname()
ip = socket.gethostbyname(host)

try:
    client_proxy_socket.bind((host, PROXY_PORT))
except socket.error as e:
    logger.exception("Error binding socket")
    sys.exit(1)

client_proxy_socket.listen(1)

logger.info(f"Proxy server is listening on {ip}:{PROXY_PORT}")

try:
    proxy_server_socket.connect((SERVER_ADDRESS, SERVER_PORT))
    iv = proxy_server_socket.recv(1024)
    proxy_server_socket.close()
except ConnectionRefusedError:
    logger.exception("Connection refused")
    sys.exit(1)
except socket.error as e:
    logger.exception("Error receiving iv")

while True:
    try:
        client_socket, addr = client_proxy_socket.accept()
        client_socket.send(iv)
        logger.info(f"Got a connection from {addr}")

        data = client_socket.recv(1024)
        logger.info(f"Undecrypted data: {data}")
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

    client_socket.send(b"1")
    client_socket.close()

    plain_text = remove_padding(attack_data(data))
    logger.info(f"Decrypted data: {plain_text}")
