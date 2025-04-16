import socket
import threading
from cryptography import RSA

class Server:
    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_public_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.public_key, self.private_key = RSA.generate_keys(bits=32)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f'{username} tries to connect')
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)
            client_pubkey = eval(c.recv(2048).decode())
            self.client_public_keys[c] = client_pubkey
            c.send(str(self.public_key).encode())
            threading.Thread(target=self.handle_client, args=(c, addr)).start()

    def broadcast(self, msg: str):
        for client in self.clients:
            pubkey = self.client_public_keys.get(client)
            if pubkey:
                encrypted = RSA.encrypt(msg, pubkey)
                client.send(str(encrypted).encode())

    def handle_client(self, c: socket, addr):
        while True:
            msg = c.recv(2048).decode()
            if not msg:
                break

            encrypted = eval(msg)
            decrypted_msg = RSA.decrypt(encrypted, self.private_key)
            self.broadcast(f"{self.username_lookup[c]}: {decrypted_msg}")

if __name__ == "__main__":
    s = Server(9001)
    s.start()
