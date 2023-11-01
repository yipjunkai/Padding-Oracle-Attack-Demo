from Crypto.Cipher import AES
from Crypto import Random

KEY_LENGTH = 16  # AES128
BLOCK_SIZE = AES.block_size


def _add_padding(msg):
    pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    padding = bytes([pad_len]) * pad_len
    wrongpadding = bytes([1])
    # print(msg + padding)
    return msg + padding


def _remove_padding(data):
    pad_len = data[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        return None
    for i in range(1, pad_len):
        if data[-i - 1] != pad_len:
            return None
    return data[:-pad_len]


def encrypt(msg):
    iv = _random_gen.read(AES.block_size)
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(_add_padding(msg))


def _decrypt(data):
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return _remove_padding(cipher.decrypt(data[BLOCK_SIZE:]))


def test_decrypt(data):
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return cipher.decrypt(data[BLOCK_SIZE:])


def is_padding_ok(data):
    return _decrypt(data) is not None


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


_random_gen = Random.new()
_key = _random_gen.read(KEY_LENGTH)
secret = b"I am a secret"  # currently only work with 16 byte of plaintext
ciphertext = encrypt(secret)

temp = [0] * 16
temp = bytearray(temp)

mod = [0] * 16
mod = bytearray(mod)

plaintext = [0] * 16
plaintext = bytearray(plaintext)

# split into 2 blocks
# block0 XOR D(block1)= plaintext + padding
block0 = ciphertext[:16]  # contains IV
block1 = ciphertext[16:32]  # contains plaintext +padding

mul = 1

# =======================================#
# last char
for i in range(1, 256):
    modified_block0 = block0[:-mul] + bytes([i])
    modified_ciphertext = modified_block0 + block1
    if is_padding_ok(modified_ciphertext):
        second_modified_block0 = block0[:14] + bytes([0xFF]) + bytes([i])
        test_correctness = second_modified_block0 + block1
        if is_padding_ok(test_correctness):
            break
            # print(test_decrypt(modified_ciphertext))

temp[15] = i ^ mul
element = int(block0[15])
plaintext[15] = element ^ temp[15]
# =======================================#

# get char[1:14]
for index in range(14, 0, -1):
    mul += 1
    extrashit = b""
    for fuck in range(15, 15 - (mul - 1), -1):
        mod[fuck] = mul ^ temp[fuck]
        extrashit = bytes([mod[fuck]]) + extrashit

    for i in range(1, 256):
        modified_block0 = block0[:-mul] + bytes([i]) + extrashit
        modified_ciphertext = modified_block0 + block1
        if is_padding_ok(modified_ciphertext):
            second_modified_block0 = (
                modified_block0[: -(mul + 1)] + bytes([0xFF]) + modified_block0[index:]
            )
            test_correctness = second_modified_block0 + block1
            if is_padding_ok(test_correctness):
                break
    # print(len(test_decrypt(modified_ciphertext)))

    temp[index] = i ^ mul
    element = int(block0[index])
    plaintext[index] = element ^ temp[index]
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
plaintext[0] = element ^ temp[0]

print(plaintext)
