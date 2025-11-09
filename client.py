import socket
import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from tqdm import tqdm

class FileClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.socket = None
        self.BUFFER_SIZE = 4096
        self.SEPARATOR = "<SEPARATOR>"
        self.encryption_key = None
        self.download_folder = "downloads"
        
        # Create download folder
        os.makedirs(self.download_folder, exist_ok=True)
    
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Receive encryption key from server
            self.encryption_key = base64.b64decode(self.socket.recv(self.BUFFER_SIZE))
            
            print(f"[+] Connected to server {self.host}:{self.port}")
            return True
        
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def authenticate(self, username, password):
        """Authenticate with the server"""
        auth_data = f"{username}{self.SEPARATOR}{password}"
        self.socket.send(auth_data.encode())
        
        response = self.socket.recv(self.BUFFER_SIZE).decode()
        
        if response == "AUTH_SUCCESS":
            print("[+] Authentication successful")
            return True
        else:
            print("[-] Authentication failed")
            return False
    
    def list_files(self):
        """Request and display list of available files"""
        self.socket.send(b"LIST")
        response = self.socket.recv(self.BUFFER_SIZE).decode()
        
        files = json.loads(response)
        
        if not files:
            print("\n[*] No files available on server")
            return []
        
        print("\n" + "="*60)
        print("Available Files on Server")
        print("="*60)
        print(f"{'No.':<5} {'Filename':<35} {'Size':<15}")
        print("-"*60)
        
        for idx, file in enumerate(files, 1):
            size_mb = file['size'] / (1024 * 1024)
            print(f"{idx:<5} {file['name']:<35} {size_mb:.2f} MB")
        
        print("="*60 + "\n")
        return files
    
    def download_file(self, filename):
        """Download a file from the server"""
        command = f"DOWNLOAD{self.SEPARATOR}{filename}"
        self.socket.send(command.encode())
        
        response = self.socket.recv(self.BUFFER_SIZE).decode()
        
        if response == "FILE_NOT_FOUND":
            print(f"[-] File not found on server: {filename}")
            return False
        
        filesize = int(response.split(self.SEPARATOR)[1])
        file_path = os.path.join(self.download_folder, filename)
        
        print(f"[*] Downloading: {filename}")
        progress = tqdm(total=filesize, unit='B', unit_scale=True, desc=filename)
        
        with open(file_path, "wb") as f:
            bytes_received = 0
            while bytes_received < filesize:
                bytes_read = self.socket.recv(min(self.BUFFER_SIZE, filesize - bytes_received))
                if not bytes_read:
                    break
                f.write(bytes_read)
                bytes_received += len(bytes_read)
                progress.update(len(bytes_read))
        
        progress.close()
        print(f"[+] Download complete: {file_path}\n")
        return True
    
    def upload_file(self, file_path):
        """Upload a file to the server"""
        if not os.path.exists(file_path):
            print(f"[-] File not found: {file_path}")
            return False
        
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)
        
        command = f"UPLOAD{self.SEPARATOR}{filename}{self.SEPARATOR}{filesize}"
        self.socket.send(command.encode())
        
        response = self.socket.recv(self.BUFFER_SIZE).decode()
        
        if response != "READY":
            print("[-] Server not ready to receive file")
            return False
        
        print(f"[*] Uploading: {filename}")
        progress = tqdm(total=filesize, unit='B', unit_scale=True, desc=filename)
        
        with open(file_path, "rb") as f:
            bytes_sent = 0
            while bytes_sent < filesize:
                bytes_read = f.read(self.BUFFER_SIZE)
                if not bytes_read:
                    break
                self.socket.sendall(bytes_read)
                bytes_sent += len(bytes_read)
                progress.update(len(bytes_read))
        
        progress.close()
        
        response = self.socket.recv(self.BUFFER_SIZE).decode()
        
        if response == "UPLOAD_SUCCESS":
            print(f"[+] Upload complete: {filename}\n")
            return True
        else:
            print("[-] Upload failed")
            return False
    
    def show_menu(self):
        """Display main menu"""
        print("\n" + "="*60)
        print("File Sharing Client - Main Menu")
        print("="*60)
        print("1. List available files")
        print("2. Download file")
        print("3. Upload file")
        print("4. Quit")
        print("="*60)
    
    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        
        # Authentication
        print("\n=== Authentication Required ===")
        print("Default users: admin/admin123 or user/user123")
        username = input("Username: ")
        password = input("Password: ")
        
        if not self.authenticate(username, password):
            self.socket.close()
            return
        
        # Main menu loop
        while True:
            self.show_menu()
            choice = input("\nEnter your choice (1-4): ").strip()
            
            if choice == '1':
                self.list_files()
            
            elif choice == '2':
                files = self.list_files()
                if files:
                    selection = input("\nEnter file number or name to download: ").strip()
                    
                    if selection.isdigit() and 1 <= int(selection) <= len(files):
                        filename = files[int(selection) - 1]['name']
                    else:
                        filename = selection
                    
                    self.download_file(filename)
            
            elif choice == '3':
                file_path = input("\nEnter path of file to upload: ").strip()
                self.upload_file(file_path)
            
            elif choice == '4':
                print("\n[*] Disconnecting from server...")
                self.socket.send(b"QUIT")
                break
            
            else:
                print("\n[-] Invalid choice. Please try again.")
        
        self.socket.close()
        print("[+] Connection closed. Goodbye!")

if __name__ == "__main__":
    client = FileClient()
    client.run()
