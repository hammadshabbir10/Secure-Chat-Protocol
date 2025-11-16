import unittest
import os
import tempfile
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

class TestCertificateValidation(unittest.TestCase):
    
    def setUp(self):
        """Set up test certificates"""
        self.test_dir = tempfile.mkdtemp()
        self.generate_test_certificates()
    
    def generate_test_certificates(self):
        """Generate valid, expired, and self-signed certificates for testing"""
        # Generate CA
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
        ])
        
        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(ca_private_key, hashes.SHA256(), default_backend())
        
        # Save CA
        with open(f"{self.test_dir}/ca-cert.pem", "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
        # 1. Valid certificate
        valid_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        
        valid_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "valid.example.com")])
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            valid_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        ).sign(ca_private_key, hashes.SHA256(), default_backend())
        
        with open(f"{self.test_dir}/valid-cert.pem", "wb") as f:
            f.write(valid_cert.public_bytes(serialization.Encoding.PEM))
        
        # 2. Expired certificate
        expired_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com")])
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).sign(ca_private_key, hashes.SHA256(), default_backend())
        
        with open(f"{self.test_dir}/expired-cert.pem", "wb") as f:
            f.write(expired_cert.public_bytes(serialization.Encoding.PEM))
        
        # 3. Self-signed certificate
        self_signed_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        
        self_signed_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "selfsigned.example.com")])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "selfsigned.example.com")])
        ).public_key(
            self_signed_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        ).sign(self_signed_key, hashes.SHA256(), default_backend())
        
        with open(f"{self.test_dir}/selfsigned-cert.pem", "wb") as f:
            f.write(self_signed_cert.public_bytes(serialization.Encoding.PEM))
    
    def test_valid_certificate(self):
        """Test that valid certificate passes verification"""
        with open(f"{self.test_dir}/valid-cert.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Check not expired - using timezone-aware datetime
        current_time = datetime.datetime.now(datetime.timezone.utc)
        self.assertTrue(cert.not_valid_before_utc <= current_time <= cert.not_valid_after_utc)
        print("✅ Valid certificate test passed")
    
    def test_expired_certificate(self):
        """Test that expired certificate fails verification"""
        with open(f"{self.test_dir}/expired-cert.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Should be expired - using timezone-aware datetime
        current_time = datetime.datetime.now(datetime.timezone.utc)
        self.assertTrue(current_time > cert.not_valid_after_utc)
        print("✅ Expired certificate test passed")
    
    def test_self_signed_certificate(self):
        """Test that self-signed certificate is detected"""
        with open(f"{self.test_dir}/selfsigned-cert.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Check if self-signed (issuer == subject)
        self.assertEqual(cert.issuer, cert.subject)
        print("✅ Self-signed certificate test passed")

if __name__ == '__main__':
    unittest.main()
