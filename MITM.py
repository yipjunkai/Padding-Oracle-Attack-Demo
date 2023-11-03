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


def is_padding_ok(msg: bytes) -> bool:
    proxy_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    proxy_server_socket.connect((SERVER_ADDRESS, SERVER_PORT))

    proxy_server_socket.recv(1024)

    proxy_server_socket.send(msg)

    data = proxy_server_socket.recv(1024)

    if data == b"1":
        return True

    return False


def attack_data(ciphertext: bytes) -> bytes:
    plain_text = b""

    start = len(ciphertext) - (BLOCK_SIZE * 2)
    end = len(ciphertext)
    num_of_blocks = int(len(ciphertext) / BLOCK_SIZE)
    for __block in tqdm(range(num_of_blocks, 1, -1), leave=False):
        plain_text = attack(ciphertext[start:end]) + plain_text
        start -= 16
        end -= 16
    return plain_text


def attack(ciphertext: bytes) -> bytes:
    segment = [0] * 16
    segment = bytearray(segment)

    temp = [0] * 16
    temp = bytearray(temp)

    mod = [0] * 16
    mod = bytearray(mod)

    # split into 2 blocks
    # block0 XOR D(block1)= plaintext + padding
    block0 = ciphertext[:16]  # contains IV
    block1 = ciphertext[16:32]  # contains plaintext +padding

    mul = 0

    for index in tqdm(range(15, 0, -1), leave=False):
        mul += 1
        extrashit = b""
        for fuck in tqdm(range(15, 15 - (mul - 1), -1), leave=False):
            mod[fuck] = mul ^ temp[fuck]
            extrashit = bytes([mod[fuck]]) + extrashit

        for i in tqdm(range(1, 256), leave=False):
            modified_block0 = block0[:-mul] + bytes([i]) + extrashit
            modified_ciphertext = modified_block0 + block1
            if is_padding_ok(modified_ciphertext):
                second_modified_block0 = (
                    modified_block0[: -(mul + 1)]
                    + bytes([0xFF])
                    + modified_block0[index:]
                )
                test_correctness = second_modified_block0 + block1
                if is_padding_ok(test_correctness):
                    break
        # print(len(test_decrypt(modified_ciphertext)))

        temp[index] = i ^ mul
        element = int(block0[index])
        segment[index] = element ^ temp[index]
        # print("Decoded char:" + chr(segment[index]))
    # =======================================#

    # get first char
    mul += 1
    extrashit = b""
    for fuck in range(15, 0, -1):
        mod[fuck] = mul ^ temp[fuck]
        extrashit = bytes([mod[fuck]]) + extrashit
    for i in range(1, 256):
        modified_block0 = bytes([i]) + extrashit
        modified_ciphertext = modified_block0 + block1
        if is_padding_ok(modified_ciphertext):
            break

    temp[0] = i ^ mul
    element = int(block0[0])
    segment[0] = element ^ temp[0]

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
