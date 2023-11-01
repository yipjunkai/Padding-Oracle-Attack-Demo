import socket
import sys
from Cryptodome.Cipher import AES

BLOCK_SIZE = AES.block_size

SERVER_ADDRESS="10.91.192.26"
SERVER_PORT=1404

def is_padding_ok(msg):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_ADDRESS, SERVER_PORT))
    client_socket.sendall(msg)

    data = client_socket.recv(1024)

    if data == b'1':
        return True

    return False

def attack(ciphertext):
  
    temp=[0]*16
    temp=bytearray(temp)

    mod=[0]*16
    mod=bytearray(mod)

    plaintext=[0]*16
    plaintext=bytearray(plaintext)

    #split into 2 blocks
    #block0 XOR D(block1)= plaintext + padding
    block0=ciphertext[:16] #contains IV
    block1=ciphertext[16:32] #contains plaintext +padding

    mul=0

    for index in range (15,0,-1):
        mul+=1
        extrashit=b''
        for fuck in range(15,15-(mul-1),-1):
            mod[fuck]=mul^temp[fuck]
            extrashit=bytes([mod[fuck]])+extrashit

        for i in range(1,256):
            modified_block0=block0[:-mul]+bytes([i])+extrashit
            modified_ciphertext=modified_block0+block1
            if(is_padding_ok(modified_ciphertext)):
                second_modified_block0=modified_block0[:-(mul+1)]  + bytes([0xff]) + modified_block0[index:]
                test_correctness=second_modified_block0+block1
                if(is_padding_ok(test_correctness)):
                    break
        #print(len(test_decrypt(modified_ciphertext)))

        temp[index]=i^mul
        element=int(block0[index])
        plaintext[index]=element^temp[index]
  #=======================================#

  #get first char
    mul+=1
    extrashit=b''
    for fuck in range(15,0,-1):
        mod[fuck]=mul^temp[fuck]
        extrashit=bytes([mod[fuck]])+extrashit
    for i in range(1,256):
        modified_block0=bytes([i])+extrashit
        modified_ciphertext=modified_block0+block1
        if(is_padding_ok(modified_ciphertext)):
            break

    temp[0]=i^mul
    element=int(block0[0])
    plaintext[0]=element^temp[0]
    print(plaintext)


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
    print("Undecrypted data: {}".format(data))

    try:
        attack(data)
    except ConnectionRefusedError:
        print("Connection refused. Please check the server address and port.")
        sys.exit(1)
    finally:
        client_socket.send(b"1")
        client_socket.close()
