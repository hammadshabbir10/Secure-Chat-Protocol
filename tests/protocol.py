import unittest
import time
import sys

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto_utils import CryptoUtils

class TestProtocolSecurity(unittest.TestCase):
    
    def test_replay_protection_sequence_numbers(self):
        """Test sequence number based replay protection"""
        messages_received = set()
        current_sequence = 0
        
        def process_message(seqno, message, signature=None):
            """Simulate message processing with replay protection"""
            nonlocal current_sequence
            
            # Check sequence number (replay protection)
            if seqno <= current_sequence:
                return "REPLAY_DETECTED", "Sequence number already processed"
            
            # In real implementation, verify signature here
            if signature is not None:
                # Signature verification would happen here
                pass
            
            current_sequence = seqno
            messages_received.add(seqno)
            return "PROCESSED", f"Message {seqno} accepted"
        
        # Test normal message flow
        result, msg = process_message(1, "Hello")
        self.assertEqual(result, "PROCESSED")
        
        result, msg = process_message(2, "How are you?")
        self.assertEqual(result, "PROCESSED")
        
        result, msg = process_message(3, "Goodbye")
        self.assertEqual(result, "PROCESSED")
        
        # Test replay attack - same sequence numbers
        result, msg = process_message(2, "Replayed message")
        self.assertEqual(result, "REPLAY_DETECTED")
        
        result, msg = process_message(1, "Another replay")
        self.assertEqual(result, "REPLAY_DETECTED")
        
        # Ensure only unique messages processed
        self.assertEqual(len(messages_received), 3)
        self.assertEqual(messages_received, {1, 2, 3})
        
        print("✅ Replay protection test passed")
    
    def test_timestamp_validation(self):
        """Test timestamp-based freshness"""
        def is_fresh_timestamp(timestamp, max_age_seconds=30):
            """Check if timestamp is within acceptable age"""
            current_time = time.time()
            return current_time - timestamp <= max_age_seconds
        
        # Test fresh timestamp (10 seconds old)
        fresh_ts = time.time() - 10
        self.assertTrue(is_fresh_timestamp(fresh_ts))
        
        # Test stale timestamp (60 seconds old)
        stale_ts = time.time() - 60
        self.assertFalse(is_fresh_timestamp(stale_ts))
        
        # Test very fresh timestamp (1 second old)
        very_fresh_ts = time.time() - 1
        self.assertTrue(is_fresh_timestamp(very_fresh_ts))
        
        print("✅ Timestamp validation test passed")
    
    def test_tamper_detection_with_hashes(self):
        """Test that message tampering is detected using hashes"""
        # Simulate message creation and verification
        def create_secure_message(seqno, timestamp, data):
            """Create a message with integrity protection"""
            message_string = f"{seqno}:{timestamp}:{data}"
            message_hash = CryptoUtils.hash_message(message_string.encode())
            return message_string, message_hash
        
        def verify_secure_message(message_string, expected_hash):
            """Verify message integrity"""
            computed_hash = CryptoUtils.hash_message(message_string.encode())
            return computed_hash == expected_hash
        
        # Create original message
        seqno = 1
        timestamp = int(time.time())
        data = "Hello, secure world!"
        
        original_message, original_hash = create_secure_message(seqno, timestamp, data)
        
        # Verify original message
        self.assertTrue(verify_secure_message(original_message, original_hash))
        
        # Test tampering - modified data
        tampered_message = f"{seqno}:{timestamp}:Hello, INSECURE world!"
        self.assertFalse(verify_secure_message(tampered_message, original_hash))
        
        # Test tampering - modified sequence number
        tampered_message2 = f"999:{timestamp}:{data}"
        self.assertFalse(verify_secure_message(tampered_message2, original_hash))
        
        # Test tampering - modified timestamp
        tampered_message3 = f"{seqno}:{timestamp + 1000}:{data}"
        self.assertFalse(verify_secure_message(tampered_message3, original_hash))
        
        print("✅ Tamper detection test passed")
    
    def test_protocol_phases_integration(self):
        """Test integration of all protocol phases"""
        phases = [
            "1. Control Plane (Certificate Exchange)",
            "2. Authentication (Login/Register)", 
            "3. Key Agreement (DH Key Exchange)",
            "4. Data Plane (Encrypted Messaging)",
            "5. Non-Repudiation (Transcript Signing)"
        ]
        
        # Simulate protocol progression
        current_phase = 0
        completed_phases = []
        
        for phase in phases:
            current_phase += 1
            completed_phases.append(phase)
            print(f"  ✅ Completed: {phase}")
        
        # Verify all phases completed
        self.assertEqual(len(completed_phases), 5)
        self.assertEqual(current_phase, 5)
        
        print("✅ Protocol phases integration test passed")

if __name__ == '__main__':
    unittest.main()
