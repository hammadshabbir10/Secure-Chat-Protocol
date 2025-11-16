import json
import hashlib
import base64
from datetime import datetime
from crypto_utils import CryptoUtils

class TranscriptManager:
    def __init__(self, user_identifier):
        self.user_identifier = user_identifier
        self.filename = f"transcripts/transcript_{user_identifier}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.entries = []
        self.create_transcript_file()
    
    def create_transcript_file(self):
        """Create initial transcript file"""
        transcript_data = {
            'user': self.user_identifier,
            'start_time': datetime.now().isoformat(),
            'messages': []
        }
        with open(self.filename, 'w') as f:
            json.dump(transcript_data, f, indent=2)
    
    def add_message(self, seqno, timestamp, ciphertext, signature, direction, peer_cert_fingerprint):
        """Add a message to the transcript"""
        entry = {
            'sequence_number': seqno,
            'timestamp': timestamp,
            'ciphertext_b64': base64.b64encode(ciphertext).decode() if isinstance(ciphertext, bytes) else ciphertext,
            'signature_b64': base64.b64encode(signature).decode() if isinstance(signature, bytes) else signature,
            'direction': direction,  # 'sent' or 'received'
            'peer_cert_fingerprint': peer_cert_fingerprint
        }
        
        self.entries.append(entry)
        
        # Append to file
        with open(self.filename, 'r+') as f:
            data = json.load(f)
            data['messages'].append(entry)
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
    
    def compute_transcript_hash(self):
        """Compute SHA-256 hash of entire transcript"""
        transcript_string = json.dumps(self.entries, sort_keys=True)
        return hashlib.sha256(transcript_string.encode()).hexdigest()
    
    def generate_session_receipt(self, private_key):
        """Generate signed session receipt for non-repudiation"""
        transcript_hash = self.compute_transcript_hash()
        
        receipt = {
            'type': 'session_receipt',
            'user': self.user_identifier,
            'transcript_file': self.filename,
            'first_seq': self.entries[0]['sequence_number'] if self.entries else 0,
            'last_seq': self.entries[-1]['sequence_number'] if self.entries else 0,
            'total_messages': len(self.entries),
            'transcript_hash_sha256': transcript_hash,
            'generated_at': datetime.now().isoformat()
        }
        
        # Sign the receipt
        receipt_string = json.dumps(receipt, sort_keys=True)
        signature = CryptoUtils.rsa_sign(private_key, receipt_string.encode())
        receipt['signature_b64'] = base64.b64encode(signature).decode()
        
        # Save receipt
        receipt_filename = f"transcripts/receipt_{self.user_identifier}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(receipt_filename, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        return receipt, receipt_filename

def verify_session_receipt(receipt_file, public_key):
    """Verify a session receipt"""
    with open(receipt_file, 'r') as f:
        receipt = json.load(f)
    
    # Extract signature
    signature = base64.b64decode(receipt['signature_b64'])
    receipt_without_sig = receipt.copy()
    del receipt_without_sig['signature_b64']
    
    # Verify signature
    receipt_string = json.dumps(receipt_without_sig, sort_keys=True)
    is_valid = CryptoUtils.rsa_verify(public_key, signature, receipt_string.encode())
    
    if is_valid:
        print("✅ Session receipt signature is VALID")
        
        # Verify transcript hash matches
        with open(receipt['transcript_file'], 'r') as f:
            transcript_data = json.load(f)
        
        transcript_string = json.dumps(transcript_data['messages'], sort_keys=True)
        computed_hash = hashlib.sha256(transcript_string.encode()).hexdigest()
        
        if computed_hash == receipt['transcript_hash_sha256']:
            print("✅ Transcript hash verification PASSED")
            return True
        else:
            print("❌ Transcript hash verification FAILED")
            return False
    else:
        print("❌ Session receipt signature is INVALID")
        return False
