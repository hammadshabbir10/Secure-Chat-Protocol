import unittest
import os
import sys

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto_utils import CryptoUtils, DiffieHellman

class TestCryptoFunctions(unittest.TestCase):
    
    def test_password_hashing(self):
        """Test salted password hashing"""
        password = "my_secure_password_123"
        salt = CryptoUtils.generate_salt()
        
        hash1 = CryptoUtils.hash_password(password, salt)
        hash2 = CryptoUtils.hash_password(password, salt)
        
        # Same salt + password should produce same hash
        self.assertEqual(hash1, hash2)
        
        # Different salt should produce different hash
        different_salt = CryptoUtils.generate_salt()
        hash3 = CryptoUtils.hash_password(password, different_salt)
        self.assertNotEqual(hash1, hash3)
        
        # Hash should be 64 characters (SHA-256 in hex)
        self.assertEqual(len(hash1), 64)
        
        print("✅ Password hashing test passed")
    
    def test_diffie_hellman_key_exchange(self):
        """Test DH key exchange produces same shared secret"""
        # Alice's DH instance
        alice_dh = DiffieHellman()
        alice_public = alice_dh.public_key
        
        # Bob's DH instance
        bob_dh = DiffieHellman()
        bob_dh.p = alice_dh.p  # Use same prime
        bob_dh.g = alice_dh.g  # Use same generator
        bob_public = bob_dh.public_key
        
        # Both compute shared secret
        alice_secret = alice_dh.compute_shared_secret(bob_public)
        bob_secret = bob_dh.compute_shared_secret(alice_public)
        
        # Should be identical
        self.assertEqual(alice_secret, bob_secret)
        
        # Derive session keys
        alice_key = alice_dh.derive_session_key()
        bob_key = bob_dh.derive_session_key()
        
        self.assertEqual(alice_key, bob_key)
        self.assertEqual(len(alice_key), 16)  # AES-128 key length
        
        print("✅ Diffie-Hellman key exchange test passed")
    
    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption"""
        # Generate a key
        test_key = os.urandom(16)
        plaintext = b"This is a secret message for encryption testing!"
        
        # Encrypt
        ciphertext = CryptoUtils.aes_encrypt(test_key, plaintext)
        
        # Should not be same as plaintext
        self.assertNotEqual(plaintext, ciphertext)
        
        # Should be longer due to IV and padding
        self.assertGreater(len(ciphertext), len(plaintext))
        
        # Decrypt
        decrypted = CryptoUtils.aes_decrypt(test_key, ciphertext)
        
        # Should recover original
        self.assertEqual(plaintext, decrypted)
        
        print("✅ AES encryption/decryption test passed")
    
    def test_message_integrity_with_rsa(self):
        """Test RSA signatures for message integrity"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        # Generate test key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Test message
        message = b"Important message that needs signing for integrity verification"
        
        # Sign
        signature = CryptoUtils.rsa_sign(private_key, message)
        
        # Verify valid signature
        self.assertTrue(CryptoUtils.rsa_verify(public_key, signature, message))
        
        # Verify tampered message fails
        tampered_message = b"Important message that needs signing - TAMPERED!"
        self.assertFalse(CryptoUtils.rsa_verify(public_key, signature, tampered_message))
        
        # Verify wrong signature fails
        wrong_signature = b"x" * 256  # Wrong signature
        self.assertFalse(CryptoUtils.rsa_verify(public_key, wrong_signature, message))
        
        print("✅ Message integrity (RSA signatures) test passed")

if __name__ == '__main__':
    unittest.main()
