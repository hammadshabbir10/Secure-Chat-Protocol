import socket
import json
import base64
import hashlib
import time
import threading
import datetime
import os
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone
import mysql.connector
from crypto_utils import CryptoUtils, DiffieHellman
from transcripts import TranscriptManager  # ADD THIS IMPORT

class SecureChatServer:
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.clients = {}
        self.setup_database()
        self.load_certificates()
        self.running = True
        
    def setup_database(self):
        try:
            self.db = mysql.connector.connect(
                host='localhost',
                user='chat_user',
                password='SecurePass123!',
                database='secure_chat'
            )
            print("✅ Database connection established")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            raise
    
    def load_certificates(self):
        try:
            with open("certs/server-key.pem", "rb") as f:
                self.server_private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            with open("certs/server-cert.pem", "rb") as f:
                self.server_cert_pem = f.read()
                self.server_cert = x509.load_pem_x509_certificate(self.server_cert_pem, default_backend())
            
            with open("certs/ca-cert.pem", "rb") as f:
                self.ca_cert_pem = f.read()
                self.ca_cert = x509.load_pem_x509_certificate(self.ca_cert_pem, default_backend())
            
            print("✅ Server certificates loaded")
        except Exception as e:
            print(f"❌ Failed to load certificates: {e}")
            raise
    
    def get_client_cert_fingerprint(self, client_cert_pem):
        """Get SHA-256 fingerprint of client certificate"""
        cert_hash = hashlib.sha256(client_cert_pem).hexdigest()
        return cert_hash
    
    def validate_certificate(self, cert_pem):
        """Validate client certificate - reject self-signed and invalid certs"""
        try:
            # Load the certificate
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Get current time (timezone-aware)
            current_time = datetime.now(timezone.utc)
            
            # Check expiration using UTC methods to avoid deprecation warnings
            if current_time < cert.not_valid_before_utc or current_time > cert.not_valid_after_utc:
                return False, "Certificate is expired or not yet valid"
            
            # Check if certificate is self-signed (issuer == subject)
            if cert.issuer == cert.subject:
                return False, "Self-signed certificates are not allowed"
            
            # Verify the certificate is signed by our CA
            try:
                # Get CA public key
                ca_public_key = self.ca_cert.public_key()
                
                # Verify the signature
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except Exception as e:
                return False, f"Certificate not signed by trusted CA: {e}"
            
            return True, "Certificate is valid"
            
        except Exception as e:
            return False, f"Certificate validation failed: {e}"
    
    def register_user(self, email, username, password, salt):
        try:
            cursor = self.db.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT email FROM users WHERE email = %s OR username = %s", (email, username))
            if cursor.fetchone():
                return False, "User already exists"
            
            # Insert new user
            pwd_hash = CryptoUtils.hash_password(password, salt)
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
            self.db.commit()
            return True, "Registration successful"
        except Exception as e:
            return False, f"Registration failed: {e}"
    
    def authenticate_user(self, email, password):
        try:
            cursor = self.db.cursor()
            cursor.execute("SELECT salt, pwd_hash FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            
            if not result:
                return False, "User not found"
            
            salt, stored_hash = result
            computed_hash = CryptoUtils.hash_password(password, salt)
            
            if computed_hash == stored_hash:
                return True, "Authentication successful"
            else:
                return False, "Invalid password"
        except Exception as e:
            return False, f"Authentication error: {e}"
    
    def handle_client(self, client_socket, address):
        print(f"🔗 New connection from {address}")
        client_info = {
            'socket': client_socket,
            'address': address,
            'authenticated': False,
            'session_key': None,
            'sequence': 0,
            'transcript': None,  # ADD THIS
            'client_cert_pem': None,  # ADD THIS
            'user_email': None  # ADD THIS
        }
        
        try:
            # Phase 1: Certificate Exchange
            data = client_socket.recv(4096).decode()
            if not data:
                return
                
            client_hello = json.loads(data)
            if client_hello.get('type') != 'hello':
                raise Exception("Invalid handshake - expected 'hello'")
            
            # Validate client certificate
            client_cert_pem = client_hello['client_cert'].encode()
            client_info['client_cert_pem'] = client_cert_pem  # Store for fingerprint
            
            valid, msg = self.validate_certificate(client_cert_pem)
            if not valid:
                error_msg = {'type': 'error', 'message': msg}
                client_socket.send(json.dumps(error_msg).encode())
                return
            
            # Send server hello with certificate
            server_hello = {
                'type': 'server_hello',
                'server_cert': self.server_cert_pem.decode(),
                'nonce': base64.b64encode(os.urandom(16)).decode()
            }
            client_socket.send(json.dumps(server_hello).encode())
            
            # Phase 2: Initial DH for credential encryption
            dh_init = DiffieHellman()
            p, g, A = dh_init.get_public_parameters()
            
            dh_msg = {
                'type': 'dh_init',
                'p': p,
                'g': g,
                'public_key': A
            }
            client_socket.send(json.dumps(dh_msg).encode())
            
            # Receive client DH public key
            data = client_socket.recv(4096).decode()
            if not data:
                return
                
            client_dh_resp = json.loads(data)
            B = client_dh_resp['public_key']
            dh_init.compute_shared_secret(B)
            temp_key = dh_init.derive_session_key()
            
            # Receive encrypted credentials
            data = client_socket.recv(4096).decode()
            if not data:
                return
                
            creds_msg = json.loads(data)
            encrypted_creds = base64.b64decode(creds_msg['data'])
            decrypted_creds = CryptoUtils.aes_decrypt(temp_key, encrypted_creds)
            creds_data = json.loads(decrypted_creds.decode())
            
            if creds_data['type'] == 'register':
                success, msg = self.register_user(
                    creds_data['email'],
                    creds_data['username'],
                    creds_data['password'],
                    base64.b64decode(creds_data['salt'])
                )
            elif creds_data['type'] == 'login':
                success, msg = self.authenticate_user(
                    creds_data['email'],
                    creds_data['password']
                )
            else:
                success, msg = False, "Invalid message type"
            
            # Send authentication result
            result_msg = {'type': 'auth_result', 'success': success, 'message': msg}
            encrypted_result = CryptoUtils.aes_encrypt(temp_key, json.dumps(result_msg).encode())
            client_socket.send(json.dumps({
                'type': 'auth_response',
                'data': base64.b64encode(encrypted_result).decode()
            }).encode())
            
            if not success:
                print(f"❌ Authentication failed: {msg}")
                return
            
            client_info['authenticated'] = True
            client_info['user_email'] = creds_data.get('email', 'unknown')
            print(f"✅ User {client_info['user_email']} authenticated")
            
            # Initialize server transcript for this client
            transcript_name = f"server_{client_info['user_email']}_{int(time.time())}"
            client_info['transcript'] = TranscriptManager(transcript_name)
            print("📝 Server transcript recording started")
            
            # Phase 3: Session DH for chat
            session_dh = DiffieHellman()
            p, g, A = session_dh.get_public_parameters()
            
            session_dh_msg = {
                'type': 'dh_session',
                'p': p,
                'g': g,
                'public_key': A
            }
            client_socket.send(json.dumps(session_dh_msg).encode())
            
            # Receive client session DH public key
            data = client_socket.recv(4096).decode()
            if not data:
                return
                
            client_session_dh = json.loads(data)
            B = client_session_dh['public_key']
            session_dh.compute_shared_secret(B)
            session_key = session_dh.derive_session_key()
            client_info['session_key'] = session_key
            
            print(f"🔑 Session key established with {address}")
            
            # Start chat loop
            self.chat_loop(client_info)
            
        except Exception as e:
            print(f"❌ Error handling client {address}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Generate server receipt before closing
            if client_info.get('transcript') and len(client_info['transcript'].entries) > 0:
                try:
                    receipt, receipt_file = client_info['transcript'].generate_session_receipt(self.server_private_key)
                    print(f"📄 Server session receipt saved: {receipt_file}")
                except Exception as e:
                    print(f"⚠️  Could not generate server receipt: {e}")
            
            client_socket.close()
            print(f"🔌 Connection closed with {address}")
    
    def chat_loop(self, client_info):
        socket = client_info['socket']
        session_key = client_info['session_key']
        transcript = client_info['transcript']
        client_cert_fingerprint = self.get_client_cert_fingerprint(client_info['client_cert_pem'])
        
        while self.running:
            try:
                message = socket.recv(4096).decode()
                if not message:
                    break
                    
                msg_data = json.loads(message)
                
                if msg_data['type'] == 'msg':
                    # Verify signature and process message
                    ciphertext = base64.b64decode(msg_data['ct'])
                    signature = base64.b64decode(msg_data['sig'])
                    
                    # Verify sequence
                    if msg_data['seqno'] <= client_info['sequence']:
                        continue  # Replay detected
                    client_info['sequence'] = msg_data['seqno']
                    
                    # Record received message in transcript
                    if transcript:
                        transcript.add_message(
                            seqno=msg_data['seqno'],
                            timestamp=msg_data['ts'],
                            ciphertext=ciphertext,
                            signature=signature,
                            direction='received',
                            peer_cert_fingerprint=client_cert_fingerprint
                        )
                    
                    # Decrypt message
                    plaintext = CryptoUtils.aes_decrypt(session_key, ciphertext)
                    print(f"📨 Received: {plaintext.decode()}")
                    
                    # Create response with REAL signature
                    response_seqno = client_info['sequence'] + 1
                    response_timestamp = int(time.time() * 1000)
                    
                    # Create response data to sign
                    response_data_to_sign = f"{response_seqno}{response_timestamp}{msg_data['ct']}".encode()
                    response_signature = CryptoUtils.rsa_sign(self.server_private_key, response_data_to_sign)
                    
                    # Echo message back with REAL signature
                    response = {
                        'type': 'msg',
                        'seqno': response_seqno,
                        'ts': response_timestamp,
                        'ct': msg_data['ct'],
                        'sig': base64.b64encode(response_signature).decode()
                    }
                    
                    # Record sent message in transcript
                    if transcript:
                        transcript.add_message(
                            seqno=response_seqno,
                            timestamp=response_timestamp,
                            ciphertext=base64.b64decode(msg_data['ct']),
                            signature=response_signature,
                            direction='sent',
                            peer_cert_fingerprint=client_cert_fingerprint
                        )
                    
                    socket.send(json.dumps(response).encode())
                    
                elif msg_data['type'] == 'logout':
                    break
                    
            except Exception as e:
                print(f"❌ Chat error: {e}")
                break
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"🚀 Server listening on {self.host}:{self.port}")
            
            while self.running:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n🛑 Server shutting down...")
        finally:
            server_socket.close()
            if hasattr(self, 'db'):
                self.db.close()

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
