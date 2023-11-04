from Crypto.Cipher import AES
from Crypto.Hash import MD5


BLOCK_SIZE = AES.block_size


# For server.py
def remove_padding(data: bytes) -> bytes:
    """
    Removes PKCS#7 padding from the given data.

    Args:
        data (bytes): The data to remove padding from.

    Returns:
        bytes: The data with padding removed, or None if the padding is invalid.
    """
    pad_len = data[-1]

    if not 1 <= pad_len <= BLOCK_SIZE:
        return None

    for i in range(1, pad_len):
        if data[-i - 1] != pad_len:
            return None

    return data[:-pad_len]


def decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decrypts the given data using AES-CBC with the given key.

    Args:
        data (bytes): The data to decrypt.
        key (bytes): The key to use for decryption.

    Returns:
        bytes: The decrypted data with padding removed, or None if the padding is invalid.
    """
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(data[BLOCK_SIZE:])

    if decrypted_data is None:
        raise Exception("Padding error")

    return remove_padding(decrypted_data)


# For client.py
def __add_padding(msg: bytes) -> bytes:
    """
    Adds PKCS#7 padding to the given message.

    Args:
        msg (bytes): The message to add padding to.

    Returns:
        bytes: The message with padding added.
    """
    pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    padding = bytes([pad_len]) * pad_len
    return msg + padding


def encrypt(key: bytes, iv: bytes, msg: bytes) -> bytes:
    """
    Encrypts the given message using AES-CBC with the given key and IV.

    Args:
        key (bytes): The key to use for encryption.
        iv (bytes): The initialization vector to use for encryption.
        msg (bytes): The message to encrypt.
        hash (bytes): Hash of the message

    Returns:
        bytes: The encrypted message.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    hash=add_hash(msg)
    return iv + cipher.encrypt(__add_padding(msg+hash))

def add_hash(msg: bytes):
    
    h = MD5.new()
    h.update(msg)
    return h.digest()

def verify_hash(msg: bytes):
    
    text=msg[:-16]
    h = MD5.new()
    h.update(text)
    if(h.digest() != msg[-16:]):
        return 0
    return 1

def remove_hash(msg: bytes):
    return msg[:-16]