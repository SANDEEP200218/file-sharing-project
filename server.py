import socket
import threading
import os
import json
import hashlib
import base64
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class FileServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.BUFFER_SIZE = 4096
        self.SEPARATOR = "<SEPARATOR>"
        self.shared_folder = "server_files"
        self.upload_folder = "uploads"
        
        # Create necessary folders
        os.makedirs(self.shared_folder, exist_ok=True)
        os.makedirs(self.upload_folder, exist_ok=True)
        
        # User database (username: hashed_password)
        self.users = {
            'admin': self.hash_password('admin123'),
            'user': self.hash_password('user123')
        }
        
        # Encryption key (32 bytes for AES-256)
        self.encryption_key = get_random_bytes(32)
        
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def encrypt_data(self, data):
        """Encrypt data using AES encryption"""
        cipher = AES.new(self.encryption_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return json.dumps({'iv': iv, 'ciphertext': ct})
    
    def decrypt_data(self, json_input):
        """Decrypt data using AES decryption"""
        try:
            b64 = json.loads(json_input)
            iv = base64.b64decode(b64['iv'])
            ct = base64.b64decode(b64['ciphertext'])
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt
        except Exception as e:
            return None
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        if username in self.users:
            return self.users[username] == self.hash_password(password)
        return False
    
    def get_file_list(self):
        """Get list of available files in shared folder"""
        files = []
        for file in os.listdir(self.shared_folder):
            file_path = os.path.join(self.shared_folder, file)
            if os.path.isfile(file_path):
                size = os.path.getsize(file_path)
                files.append({'name': file, 'size': size})
        return files
    
    def send_encrypted(self, client_socket, data):
        """Send encrypted data to client"""
        if isinstance(data, str):
            data = data.encode()
        encrypted = self.encrypt_data(data)
        client_socket.send(encrypted.encode())
    
    def receive_encrypted(self, client_socket):
        """Receive and decrypt data from client"""
        data = client_socket.recv(self.BUFFER_SIZE).decode()
        decrypted = self.decrypt_data(data)
        return decrypted.decode() if decrypted else None
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        print(f"[+] Connection from {address}")
        
        try:
            # Send encryption key to client
            client_socket.send(base64.b64encode(self.encryption_key))
            
            # Authentication
            auth_data = client_socket.recv(self.BUFFER_SIZE).decode()
            username, password = auth_data.split(self.SEPARATOR)
            
            if not self.authenticate_user(username, password):
                client_socket.send(b"AUTH_FAILED")
                print(f"[-] Authentication failed for {username} from {address}")
                client_socket.close()
                return
            
            client_socket.send(b"AUTH_SUCCESS")
            print(f"[+] User {username} authenticated successfully from {address}")
            
            # Main command loop
            while True:
                try:
                    command = client_socket.recv(self.BUFFER_SIZE).decode()
                    
                    if not command or command == "QUIT":
                        break
                    
                    if command == "LIST":
                        self.handle_list(client_socket)
                    
                    elif command.startswith("DOWNLOAD"):
                        filename = command.split(self.SEPARATOR)[1]
                        self.handle_download(client_socket, filename)
                    
                    elif command.startswith("UPLOAD"):
                        filename = command.split(self.SEPARATOR)[1]
                        filesize = int(command.split(self.SEPARATOR)[2])
                        self.handle_upload(client_socket, filename, filesize)
                    
                except Exception as e:
                    print(f"[-] Error handling command: {e}")
                    break
            
        except Exception as e:
            print(f"[-] Error with client {address}: {e}")
        
        finally:
            client_socket.close()
            print(f"[-] Connection closed with {address}")
    
    def handle_list(self, client_socket):
        """Send list of available files to client"""
        files = self.get_file_list()
        response = json.dumps(files)
        client_socket.send(response.encode())
        print("[*] Sent file list to client")
    
    def handle_download(self, client_socket, filename):
        """Send file to client"""
        file_path = os.path.join(self.shared_folder, filename)
        
        if not os.path.exists(file_path):
            client_socket.send(b"FILE_NOT_FOUND")
            print(f"[-] File not found: {filename}")
            return
        
        filesize = os.path.getsize(file_path)
        client_socket.send(f"OK{self.SEPARATOR}{filesize}".encode())
        
        print(f"[*] Sending file: {filename} ({filesize} bytes)")
        
        with open(file_path, "rb") as f:
            bytes_sent = 0
            while bytes_sent < filesize:
                bytes_read = f.read(self.BUFFER_SIZE)
                if not bytes_read:
                    break
                client_socket.sendall(bytes_read)
                bytes_sent += len(bytes_read)
        
        print(f"[+] File sent successfully: {filename}")
    
    def handle_upload(self, client_socket, filename, filesize):
        """Receive file from client"""
        file_path = os.path.join(self.upload_folder, filename)
        
        client_socket.send(b"READY")
        print(f"[*] Receiving file: {filename} ({filesize} bytes)")
        
        with open(file_path, "wb") as f:
            bytes_received = 0
            while bytes_received < filesize:
                bytes_read = client_socket.recv(min(self.BUFFER_SIZE, filesize - bytes_received))
                if not bytes_read:
                    break
                f.write(bytes_read)
                bytes_received += len(bytes_read)
        
        print(f"[+] File received successfully: {filename}")
        client_socket.send(b"UPLOAD_SUCCESS")
    
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        print(f"[*] Shared folder: {os.path.abspath(self.shared_folder)}")
        print(f"[*] Upload folder: {os.path.abspath(self.upload_folder)}")
        print("[*] Waiting for connections...")
        
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
        
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        
        finally:
            if self.server_socket:
                self.server_socket.close()

if __name__ == "__main__":
    server = FileServer()
    server.start()
