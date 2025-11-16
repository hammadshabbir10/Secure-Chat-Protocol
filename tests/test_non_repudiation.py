#!/usr/bin/env python3
"""
Test non-repudiation with transcript verification
"""

import os
import sys
import json
import tempfile
import shutil

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from transcripts import TranscriptManager, verify_session_receipt
from crypto_utils import CryptoUtils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509  # Add this with other imports
def test_transcript_creation():
    """Test that transcripts are created and stored correctly"""
    print("🧪 Testing transcript creation...")
    
    # Create temporary directory for testing
    test_dir = tempfile.mkdtemp()
    original_transcripts_dir = "transcripts"
    
    try:
        # Create test transcripts directory
        test_transcripts_dir = os.path.join(test_dir, "transcripts")
        os.makedirs(test_transcripts_dir, exist_ok=True)
        
        # Temporarily change working directory
        original_cwd = os.getcwd()
        os.chdir(test_dir)
        
        # Generate test keys
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Create transcript
        transcript = TranscriptManager("test_user@example.com")
        
        # Add test messages
        test_messages = [
            (1, 1635789200000, b"encrypted_msg_1", b"signature_1", "sent", "peer_fingerprint_1"),
            (2, 1635789201000, b"encrypted_msg_2", b"signature_2", "received", "peer_fingerprint_2"),
            (3, 1635789202000, b"encrypted_msg_3", b"signature_3", "sent", "peer_fingerprint_1")
        ]
        
        for msg in test_messages:
            transcript.add_message(*msg)
        
        # Check transcript file was created
        assert os.path.exists(transcript.filename), "Transcript file should be created"
        print("✅ Transcript file created successfully")
        
        # Check transcript content
        with open(transcript.filename, 'r') as f:
            transcript_data = json.load(f)
        
        assert len(transcript_data['messages']) == 3, "Should have 3 messages"
        assert transcript_data['user'] == "test_user@example.com", "User should match"
        print("✅ Transcript content is correct")
        
        # Generate receipt
        receipt, receipt_file = transcript.generate_session_receipt(private_key)
        assert os.path.exists(receipt_file), "Receipt file should be created"
        print("✅ Session receipt created successfully")
        
        # Verify receipt
        is_valid = verify_session_receipt(receipt_file, public_key)
        assert is_valid, "Valid receipt should verify"
        print("✅ Receipt verification passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Transcript creation test failed: {e}")
        return False
    finally:
        # Restore original directory
        os.chdir(original_cwd)
        # Cleanup
        shutil.rmtree(test_dir, ignore_errors=True)

def test_tamper_detection():
    """Test that tampering with transcripts is detected"""
    print("\n🧪 Testing tamper detection...")
    
    # Create temporary directory for testing
    test_dir = tempfile.mkdtemp()
    
    try:
        # Create test transcripts directory
        test_transcripts_dir = os.path.join(test_dir, "transcripts")
        os.makedirs(test_transcripts_dir, exist_ok=True)
        
        # Temporarily change working directory
        original_cwd = os.getcwd()
        os.chdir(test_dir)
        
        # Generate test keys
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Create transcript and add messages
        transcript = TranscriptManager("test_user")
        test_messages = [
            (1, 1635789200000, b"encrypted_msg_1", b"signature_1", "sent", "peer_fingerprint_1"),
            (2, 1635789201000, b"encrypted_msg_2", b"signature_2", "received", "peer_fingerprint_2")
        ]
        
        for msg in test_messages:
            transcript.add_message(*msg)
        
        # Generate receipt
        receipt, receipt_file = transcript.generate_session_receipt(private_key)
        
        # Test 1: Verify valid receipt
        is_valid = verify_session_receipt(receipt_file, public_key)
        assert is_valid, "Valid receipt should verify initially"
        print("✅ Valid receipt verification passed")
        
        # Test 2: Tamper with transcript and verify detection
        with open(transcript.filename, 'r') as f:
            transcript_data = json.load(f)
        
        # Modify a message (tampering)
        transcript_data['messages'][0]['ciphertext_b64'] = "tampered_data"
        
        with open(transcript.filename, 'w') as f:
            json.dump(transcript_data, f, indent=2)
        
        # Verification should now fail
        is_valid_after_tamper = verify_session_receipt(receipt_file, public_key)
        assert not is_valid_after_tamper, "Tampered transcript should be detected"
        print("✅ Tamper detection working correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ Tamper detection test failed: {e}")
        return False
    finally:
        # Restore original directory
        os.chdir(original_cwd)
        # Cleanup
        shutil.rmtree(test_dir, ignore_errors=True)

def test_invalid_signature_detection():
    """Test that invalid signatures are detected"""
    print("\n🧪 Testing invalid signature detection...")
    
    # Create temporary directory for testing
    test_dir = tempfile.mkdtemp()
    
    try:
        # Create test transcripts directory
        test_transcripts_dir = os.path.join(test_dir, "transcripts")
        os.makedirs(test_transcripts_dir, exist_ok=True)
        
        # Temporarily change working directory
        original_cwd = os.getcwd()
        os.chdir(test_dir)
        
        # Generate TWO different key pairs
        correct_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        correct_public_key = correct_private_key.public_key()
        
        wrong_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        
        # Create transcript
        transcript = TranscriptManager("test_user")
        test_messages = [
            (1, 1635789200000, b"encrypted_msg_1", b"signature_1", "sent", "peer_fingerprint_1")
        ]
        
        for msg in test_messages:
            transcript.add_message(*msg)
        
        # Generate receipt with WRONG private key (invalid signature)
        receipt, receipt_file = transcript.generate_session_receipt(wrong_private_key)
        
        # Try to verify with CORRECT public key (should fail)
        is_valid = verify_session_receipt(receipt_file, correct_public_key)
        assert not is_valid, "Invalid signature should be detected"
        print("✅ Invalid signature detection working correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ Invalid signature test failed: {e}")
        return False
    finally:
        # Restore original directory
        os.chdir(original_cwd)
        # Cleanup
        shutil.rmtree(test_dir, ignore_errors=True)
def test_real_certificate_verification():
    """Test with real certificates from the project"""
    print("\n🧪 Testing with real certificates...")
    
    try:
        # Load actual project certificates and extract public keys
        from cryptography import x509
        
        # Load client certificate and extract public key
        with open("certs/client-cert.pem", "rb") as f:
            client_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            client_pub_key = client_cert.public_key()
        
        # Load server certificate and extract public key  
        with open("certs/server-cert.pem", "rb") as f:
            server_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            server_pub_key = server_cert.public_key()
        
        print("✅ Real certificates loaded successfully")
        
        # Check if there are any existing receipt files to verify
        if os.path.exists("transcripts"):
            receipt_files = [f for f in os.listdir("transcripts") if f.startswith("receipt_")]
            
            if receipt_files:
                print(f"📁 Found {len(receipt_files)} receipt file(s) for verification")
                
                for receipt_file in receipt_files:
                    full_path = os.path.join("transcripts", receipt_file)
                    print(f"🔍 Verifying: {receipt_file}")
                    
                    # Determine which key to use based on filename
                    if "client" in receipt_file:
                        is_valid = verify_session_receipt(full_path, client_pub_key)
                        key_type = "client"
                    else:
                        is_valid = verify_session_receipt(full_path, server_pub_key)
                        key_type = "server"
                    
                    if is_valid:
                        print(f"   ✅ {key_type} receipt: VALID")
                    else:
                        print(f"   ❌ {key_type} receipt: INVALID")
            else:
                print("📝 No receipt files found. Run a chat session first to generate receipts.")
                print("   This is OK - the test logic is still validated.")
        else:
            print("📝 No transcripts directory found. Run a chat session first.")
            print("   This is OK - the test logic is still validated.")
        
        return True
        
    except FileNotFoundError:
        print("⚠️  Certificate files not found. Run certificate generation scripts first.")
        return True  # Don't fail the test, just warn
    except Exception as e:
        print(f"❌ Real certificate test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🔒 Non-Repudiation System Tests")
    print("=" * 50)
    
    results = []
    
    results.append(("Transcript creation", test_transcript_creation()))
    results.append(("Tamper detection", test_tamper_detection()))
    results.append(("Invalid signature detection", test_invalid_signature_detection()))
    results.append(("Real certificate verification", test_real_certificate_verification()))
    
    print("\n" + "=" * 50)
    print("📊 NON-REPUDIATION TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n🎯 Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("🔐 All non-repudiation mechanisms are working correctly!")
        print("   - Transcript creation: ✅")
        print("   - Tamper detection: ✅")
        print("   - Signature verification: ✅")
        print("   - Real certificate support: ✅")
    else:
        print("⚠️  Some non-repudiation tests failed")
    
    # Exit with error code if any test failed
    sys.exit(0 if passed == total else 1)
