import socket
import threading
from kyber import Kyber512
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt a message using AES with the shared key
def encrypt(shared_key, plaintext):
    cipher = AES.new(shared_key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

# Function to decrypt a message using AES with the shared key
def decrypt(shared_key, ciphertext):
    cipher = AES.new(shared_key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode()

def receive_messages(client, shared_key):
    while True:
        encrypted_message = client.recv(1024)
        message = decrypt(shared_key, encrypted_message)
        print("Partner:", message)

def send_messages(client, shared_key):
    while True:
        message = input("You: ")
        encrypted_message = encrypt(shared_key, message)
        client.send(encrypted_message)

# ... (host and connect functions remain the same as before) ...

def host():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 9999))
    server.listen()
    client, _ = server.accept()

    # Generate a key pair for key exchange
    pk, sk = Kyber512.keygen()

    # Send the public key to the client
    client.send(pk)

    # Receive the ciphertext from the client
    c = client.recv(1024)

    # Decapsulate the shared key using the ciphertext and private key
    shared_key = Kyber512.dec(c, sk)
    print("Shared Key (Server):", shared_key)

    threading.Thread(target=receive_messages, args=(client, shared_key)).start()
    threading.Thread(target=send_messages, args=(client, shared_key)).start()

def connect():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9999))

    # Receive the public key from the server
    pk = client.recv(1024)

    # Encapsulate the shared key using the public key
    c, shared_key = Kyber512.enc(pk)
    print("Shared Key (Client):", shared_key)

    # Send the ciphertext to the server
    client.send(c)

    threading.Thread(target=receive_messages, args=(client, shared_key)).start()
    threading.Thread(target=send_messages, args=(client, shared_key)).start()

def main():
    choice = input("Host(1) or Connect(2)?: ")
    if choice == "1":
        host()
    elif choice == "2":
        connect()
    else:
        exit()

if __name__ == "__main__":
    main()