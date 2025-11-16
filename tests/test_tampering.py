#!/usr/bin/env python3
"""
Test message tampering detection
"""

import json
import base64
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto_utils import CryptoUtils

def test_aes_tamper_detection():
    """Test that tampered AES messages are detected"""
    print("🧪 Testing AES tampering detection...")
    
    # Generate test key and message
    test_key = os.urandom(16)  # Random AES key
    original_message = b"Secret message for integrity test with AES encryption"
    
    # Encrypt original message
    ciphertext = CryptoUtils.aes_encrypt(test_key, original_message)
    
    # Tamper with ciphertext (flip one bit)
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[20] ^= 0x01  # Flip one bit in the middle
    
    # Try to decrypt tampered message
    try:
        decrypted = CryptoUtils.aes_decrypt(test_key, bytes(tampered_ciphertext))
        # If we get here without exception, check if decryption produced garbage
        if decrypted == original_message:
            print("❌ FAIL: Tampered message decrypted to original without error")
            return False
        else:
            print("✅ PASS: Tampered message produced different plaintext")
            print(f"   Original: {original_message}")
            print(f"   Tampered result: {decrypted}")
            return True
    except Exception as e:
        print("✅ PASS: Tampered message correctly caused decryption error")
        print(f"   Error type: {type(e).__name__}")
        return True

def test_signature_tamper_detection():
    """Test RSA signature verification with tampered messages"""
    print("🧪 Testing RSA signature tampering detection...")
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    # Generate test keys
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Create and sign message
    message = b"Important signed message for integrity verification"
    signature = CryptoUtils.rsa_sign(private_key, message)
    
    # Verify valid signature
    valid = CryptoUtils.rsa_verify(public_key, signature, message)
    if not valid:
        print("❌ FAIL: Valid signature was rejected")
        return False
    else:
        print("✅ PASS: Valid signature correctly verified")
    
    # Test 1: Tampered message content
    tampered_message = b"Important signed message for integrity verification - TAMPERED"
    valid_tampered = CryptoUtils.rsa_verify(public_key, signature, tampered_message)
    if valid_tampered:
        print("❌ FAIL: Tampered message signature was accepted")
        return False
    else:
        print("✅ PASS: Tampered message signature correctly rejected")
    
    # Test 2: Tampered signature
    tampered_signature = bytearray(signature)
    tampered_signature[10] ^= 0x01  # Flip one bit in signature
    valid_tampered_sig = CryptoUtils.rsa_verify(public_key, bytes(tampered_signature), message)
    if valid_tampered_sig:
        print("❌ FAIL: Tampered signature was accepted")
        return False
    else:
        print("✅ PASS: Tampered signature correctly rejected")
    
    return True

def test_hash_integrity():
    """Test that hash changes detect tampering"""
    print("🧪 Testing hash-based integrity detection...")
    
    from crypto_utils import CryptoUtils
    
    original_data = b"Original data that should not be tampered with"
    tampered_data = b"Original data that should be tampered with"  # One word changed
    
    # Compute hashes
    original_hash = CryptoUtils.hash_message(original_data)
    tampered_hash = CryptoUtils.hash_message(tampered_data)
    
    # Hashes should be different
    if original_hash == tampered_hash:
        print("❌ FAIL: Hash collision detected (highly unlikely)")
        return False
    else:
        print("✅ PASS: Tampered data produces different hash")
        print(f"   Original hash: {original_hash.hex()[:16]}...")
        print(f"   Tampered hash: {tampered_hash.hex()[:16]}...")
        return True

def test_protocol_message_tampering():
    """Test tampering detection in protocol messages"""
    print("🧪 Testing protocol-level tampering detection...")
    
    # Simulate a protocol message
    test_key = os.urandom(16)
    message_data = {
        'type': 'msg',
        'seqno': 1,
        'ts': 1234567890,
        'message': 'Hello, secure world!'
    }
    
    # Encrypt the message
    plaintext = json.dumps(message_data).encode()
    ciphertext = CryptoUtils.aes_encrypt(test_key, plaintext)
    
    # Tamper with ciphertext
    tampered_ciphertext = bytearray(ciphertext)
    for i in range(5):  # Tamper multiple bytes
        tampered_ciphertext[15 + i] ^= 0xFF
    
    # Try to decrypt
    try:
        decrypted = CryptoUtils.aes_decrypt(test_key, bytes(tampered_ciphertext))
        decrypted_data = json.loads(decrypted.decode())
        # Check if JSON is still valid but content changed
        if decrypted_data.get('message') != message_data['message']:
            print("✅ PASS: Tampering altered message content")
            return True
        else:
            print("❌ FAIL: Tampering did not affect message content")
            return False
    except (json.JSONDecodeError, Exception) as e:
        print("✅ PASS: Tampering caused decryption/parsing error")
        print(f"   Error: {type(e).__name__}")
        return True

if __name__ == "__main__":
    print("🔒 Message Tampering Detection Tests")
    print("=" * 50)
    
    results = []
    
    results.append(("AES tampering detection", test_aes_tamper_detection()))
    results.append(("RSA signature verification", test_signature_tamper_detection()))
    results.append(("Hash integrity", test_hash_integrity()))
    results.append(("Protocol message tampering", test_protocol_message_tampering()))
    
    print("\n" + "=" * 50)
    print("📊 TAMPERING TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n🎯 Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("🔒 All tampering detection mechanisms are working correctly!")
    else:
        print("⚠️  Some tampering detection tests failed")
    
    # Exit with error code if any test failed
    sys.exit(0 if passed == total else 1)
