import hashlib
import os
import base64
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CryptoUtils:
    @staticmethod
    def generate_salt():
        return os.urandom(16)
    
    @staticmethod
    def hash_password(password, salt):
        return hashlib.sha256(salt + password.encode()).hexdigest()
    
    @staticmethod
    def derive_aes_key(shared_secret):
        # Convert to big-endian bytes
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        hash_result = hashlib.sha256(secret_bytes).digest()
        return hash_result[:16]  # Truncate to 16 bytes for AES-128
    
    @staticmethod
    def aes_encrypt(key, plaintext):
        # PKCS7 padding
        padding_length = 16 - (len(plaintext) % 16)
        padded_text = plaintext + bytes([padding_length] * padding_length)
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        
        return iv + ciphertext
    
    @staticmethod
    def aes_decrypt(key, encrypted_data):
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = padded_plaintext[-1]
        return padded_plaintext[:-padding_length]
    
    @staticmethod
    def rsa_sign(private_key, data):
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    @staticmethod
    def rsa_verify(public_key, signature, data):
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def hash_message(data):
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).digest()

class DiffieHellman:
    def __init__(self):
        # Use a standard 2048-bit prime from RFC 3526
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.g = 2
        self.private_key = random.randint(2, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)
        self.shared_secret = None
    
    def get_public_parameters(self):
        return self.p, self.g, self.public_key
    
    def compute_shared_secret(self, peer_public_key):
        self.shared_secret = pow(peer_public_key, self.private_key, self.p)
        return self.shared_secret
    
    def derive_session_key(self):
        if not self.shared_secret:
            raise ValueError("No shared secret computed")
        return CryptoUtils.derive_aes_key(self.shared_secret)
