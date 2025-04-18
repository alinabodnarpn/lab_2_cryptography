"""
Encrypted Chat Client Module
"""
import socket
import threading
from cryptography import RSA

class Client:
    """
     A client for connecting to an encrypted chat server using RSA encryption
     """
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        """
        Initializes the socket connection to the server, handles key exchange,
        and starts read and write threads for chat functionality
        """
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print('Connection error:', e)
            return

        self.s.send(self.username.encode())
        self.public_key, self.private_key = RSA.generate_keys(bits=32)
        self.s.send(str(self.public_key).encode())
        self.server_pubkey = eval(self.s.recv(2048).decode())
        threading.Thread(target=self.read_handler).start()
        threading.Thread(target=self.write_handler).start()

    def read_handler(self):
        """
        Listens for messages from the server, decrypts them using the client's
        private key, and prints the plaintext messages to the console
        """
        while True:
            message = self.s.recv(2048).decode()
            decrypted = RSA.decrypt(eval(message), self.private_key)
            print(decrypted)

    def write_handler(self):
        """
        Reads user input from the console, encrypts it using the
        server's public key, and sends the encrypted message to the server
        """
        while True:
            message = input()
            encrypted = RSA.encrypt(message, self.server_pubkey)
            self.s.send(str(encrypted).encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
