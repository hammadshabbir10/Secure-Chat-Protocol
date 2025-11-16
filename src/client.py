import socket
import json
import base64
import hashlib
import time
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from crypto_utils import CryptoUtils, DiffieHellman
from transcripts import TranscriptManager  # ADD THIS IMPORT

class SecureChatClient:
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.socket = None
        self.session_key = None
        self.sequence = 0
        self.transcript = None  # ADD THIS
        self.server_cert_fingerprint = None  # ADD THIS
        self.user_email = None  # ADD THIS
        self.load_certificates()
    
    def load_certificates(self):
        try:
            with open("certs/client-key.pem", "rb") as f:
                self.client_private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            with open("certs/client-cert.pem", "rb") as f:
                self.client_cert_pem = f.read()
            
            with open("certs/ca-cert.pem", "rb") as f:
                self.ca_cert_pem = f.read()
            
            print("✅ Client certificates loaded")
        except Exception as e:
            print(f"❌ Failed to load certificates: {e}")
            raise
    
    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"🔗 Connected to server {self.host}:{self.port}")
    
    def handshake(self):
        # Send client hello with certificate
        hello_msg = {
            'type': 'hello',
            'client_cert': self.client_cert_pem.decode(),
            'nonce': base64.b64encode(os.urandom(16)).decode()
        }
        self.socket.send(json.dumps(hello_msg).encode())
        
        # Receive server hello
        data = self.socket.recv(4096).decode()
        if not data:
            raise Exception("No response from server")
            
        server_hello = json.loads(data)
        if server_hello.get('type') == 'error':
            raise Exception(f"Server error: {server_hello.get('message')}")
        elif server_hello.get('type') != 'server_hello':
            raise Exception(f"Invalid server response. Expected 'server_hello', got {server_hello.get('type')}")
        
        # Compute server certificate fingerprint
        try:
            server_cert = x509.load_pem_x509_certificate(
                server_hello['server_cert'].encode(), default_backend()
            )
            self.server_cert_fingerprint = hashlib.sha256(
                server_cert.tbs_certificate_bytes
            ).hexdigest()[:16]  # First 16 chars for brevity
            print(f"🔐 Server certificate fingerprint: {self.server_cert_fingerprint}")
        except Exception as e:
            print(f"⚠️  Could not compute server fingerprint: {e}")
            self.server_cert_fingerprint = "unknown"
        
        print("✅ Certificate exchange completed")
        
        # Receive DH parameters for initial key exchange
        data = self.socket.recv(4096).decode()
        if not data:
            raise Exception("No DH parameters from server")
            
        dh_init = json.loads(data)
        p, g, A = dh_init['p'], dh_init['g'], dh_init['public_key']
        
        # Compute shared secret
        client_dh = DiffieHellman()
        client_dh.p = p
        client_dh.g = g
        B = client_dh.public_key
        
        # Send our public key
        self.socket.send(json.dumps({'type': 'dh_response', 'public_key': B}).encode())
        
        # Compute shared secret and derive key
        client_dh.compute_shared_secret(A)
        temp_key = client_dh.derive_session_key()
        
        return temp_key
    
    def authenticate(self, temp_key, auth_type, email, username=None, password=None):
        if auth_type == 'register':
            salt = CryptoUtils.generate_salt()
            creds_data = {
                'type': 'register',
                'email': email,
                'username': username,
                'password': password,
                'salt': base64.b64encode(salt).decode()
            }
        else:  # login
            # For login, we need to handle salt properly - this is simplified
            salt = b'\x00' * 16  # This should be retrieved from server in real implementation
            creds_data = {
                'type': 'login',
                'email': email,
                'password': password
            }
        
        # Encrypt credentials
        encrypted_creds = CryptoUtils.aes_encrypt(temp_key, json.dumps(creds_data).encode())
        
        # Send encrypted credentials
        auth_msg = {
            'type': 'auth_request',
            'data': base64.b64encode(encrypted_creds).decode()
        }
        self.socket.send(json.dumps(auth_msg).encode())
        
        # Receive authentication result
        data = self.socket.recv(4096).decode()
        if not data:
            raise Exception("No authentication response from server")
            
        auth_response = json.loads(data)
        encrypted_result = base64.b64decode(auth_response['data'])
        decrypted_result = CryptoUtils.aes_decrypt(temp_key, encrypted_result)
        result_data = json.loads(decrypted_result.decode())
        
        return result_data['success'], result_data['message']
    
    def establish_session(self):
        # Receive session DH parameters
        data = self.socket.recv(4096).decode()
        if not data:
            raise Exception("No session DH parameters from server")
            
        session_dh_msg = json.loads(data)
        p, g, A = session_dh_msg['p'], session_dh_msg['g'], session_dh_msg['public_key']
        
        # Compute session shared secret
        client_session_dh = DiffieHellman()
        client_session_dh.p = p
        client_session_dh.g = g
        B = client_session_dh.public_key
        
        # Send our public key
        self.socket.send(json.dumps({'type': 'dh_session_response', 'public_key': B}).encode())
        
        # Compute session key
        client_session_dh.compute_shared_secret(A)
        self.session_key = client_session_dh.derive_session_key()
        print("🔑 Session key established")
    
    def send_message(self, message):
        if not self.session_key:
            print("❌ No session key established")
            return False
        
        self.sequence += 1
        plaintext = message.encode()
        
        # Encrypt message
        ciphertext = CryptoUtils.aes_encrypt(self.session_key, plaintext)
        
        # Create REAL signature (not dummy)
        timestamp = int(time.time() * 1000)
        data_to_sign = f"{self.sequence}{timestamp}{base64.b64encode(ciphertext).decode()}".encode()
        signature = CryptoUtils.rsa_sign(self.client_private_key, data_to_sign)
        
        # Create message with real signature
        msg_data = {
            'type': 'msg',
            'seqno': self.sequence,
            'ts': timestamp,
            'ct': base64.b64encode(ciphertext).decode(),
            'sig': base64.b64encode(signature).decode()  # REAL signature now
        }
        
        # Record in transcript BEFORE sending
        if self.transcript:
            self.transcript.add_message(
                seqno=self.sequence,
                timestamp=timestamp,
                ciphertext=ciphertext,
                signature=signature,
                direction='sent',
                peer_cert_fingerprint=self.server_cert_fingerprint
            )
        
        self.socket.send(json.dumps(msg_data).encode())
        return True
    
    def receive_message(self):
        try:
            message = self.socket.recv(4096).decode()
            if not message:
                return None
            
            msg_data = json.loads(message)
            if msg_data['type'] == 'msg':
                ciphertext = base64.b64decode(msg_data['ct'])
                signature = base64.b64decode(msg_data['sig'])
                
                # Record in transcript BEFORE processing
                if self.transcript:
                    self.transcript.add_message(
                        seqno=msg_data['seqno'],
                        timestamp=msg_data['ts'],
                        ciphertext=ciphertext,
                        signature=signature,
                        direction='received',
                        peer_cert_fingerprint=self.server_cert_fingerprint
                    )
                
                # Decrypt message
                plaintext = CryptoUtils.aes_decrypt(self.session_key, ciphertext)
                return plaintext.decode()
            
            return None
        except Exception as e:
            print(f"❌ Error receiving message: {e}")
            return None
    
    def chat_loop(self):
        print("\n💬 Chat started! Type your messages (type 'exit' to quit)")
        
        import threading
        
        # Start receiver thread
        def receiver():
            while True:
                message = self.receive_message()
                if message:
                    print(f"\n📨 Server: {message}")
                else:
                    break
        
        receiver_thread = threading.Thread(target=receiver)
        receiver_thread.daemon = True
        receiver_thread.start()
        
        # Main sender loop
        while True:
            try:
                message = input("You: ")
                if message.lower() == 'exit':
                    break
                
                if not self.send_message(message):
                    break
                    
            except KeyboardInterrupt:
                break
        
        print("👋 Chat ended")
    
    def start(self):
        try:
            self.connect()
            
            # Phase 1: Handshake and initial DH
            temp_key = self.handshake()
            
            # Phase 2: Authentication
            print("\n🔐 Authentication")
            auth_type = input("Register or Login? (r/l): ").lower()
            
            email = input("Email: ")
            password = input("Password: ")
            username = None
            
            if auth_type == 'r':
                username = input("Username: ")
                success, message = self.authenticate(temp_key, 'register', email, username, password)
            else:
                success, message = self.authenticate(temp_key, 'login', email, password=password)
            
            if not success:
                print(f"❌ Authentication failed: {message}")
                return
            
            print(f"✅ {message}")
            
            # Store user email for transcript
            self.user_email = email
            
            # Initialize client transcript AFTER successful authentication
            transcript_name = f"client_{email}_{int(time.time())}"
            self.transcript = TranscriptManager(transcript_name)
            print("📝 Client transcript recording started")
            
            # Phase 3: Session key establishment
            self.establish_session()
            
            # Phase 4: Start chat
            self.chat_loop()
            
        except Exception as e:
            print(f"❌ Client error: {e}")
            import traceback
            traceback.print_exc()  # This will show detailed error
        finally:
            # Generate client receipt before closing
            if self.transcript and len(self.transcript.entries) > 0:
                try:
                    receipt, receipt_file = self.transcript.generate_session_receipt(self.client_private_key)
                    print(f"📄 Client session receipt saved: {receipt_file}")
                except Exception as e:
                    print(f"⚠️  Could not generate client receipt: {e}")
            
            if self.socket:
                self.socket.close()

if __name__ == "__main__":
    # Create transcripts directory if it doesn't exist
    if not os.path.exists("transcripts"):
        os.makedirs("transcripts")
        print("📁 Created transcripts directory")
    
    client = SecureChatClient()
    client.start()
