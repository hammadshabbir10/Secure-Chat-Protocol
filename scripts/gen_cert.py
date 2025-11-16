from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import sys

def generate_certificate(common_name, cert_type="server"):
    try:
        # Load CA
        with open("../certs/ca-key.pem", "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        
        with open("../certs/ca-cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Generate certificate key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )
        
        if cert_type == "server":
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False
            )
        
        cert = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
        
        # Save files
        prefix = "server" if cert_type == "server" else "client"
        
        with open(f"../certs/{prefix}-key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(f"../certs/{prefix}-cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"✅ {cert_type.capitalize()} certificate for '{common_name}' generated!")
        print(f"📁 Files: certs/{prefix}-key.pem, certs/{prefix}-cert.pem")
        
    except FileNotFoundError:
        print("❌ Error: CA files not found. Run gen_ca.py first.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error generating certificate: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python gen_cert.py <common_name> <server|client>")
        print("Example: python gen_cert.py 'SecureChat Server' server")
        sys.exit(1)
    
    generate_certificate(sys.argv[1], sys.argv[2])
