# 🔒 Secure Chat Protocol - CIANR Implementation

A comprehensive secure chat system implementing **Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)** using modern cryptographic techniques.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-Advanced-green.svg)
![Security](https://img.shields.io/badge/Security-CIANR-red.svg)
![Tests](https://img.shields.io/badge/Tests-100%25%20Passed-brightgreen.svg)

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Testing](#testing)
- [Security Implementation](#security-implementation)
- [Documentation](#documentation)
- [GitHub Repository](#github-repository)
- [Recommendations](#recommendations-for-future-assignments)

## 🎯 Overview

This secure chat system provides **end-to-end encrypted communication** with comprehensive security features:

- **Confidentiality**: AES-128 encryption with perfect forward secrecy
- **Integrity**: RSA signatures and SHA-256 hashing  
- **Authenticity**: X.509 certificate-based mutual authentication
- **Non-Repudiation**: Digitally signed session transcripts and receipts

## ✨ Features

- 🔐 **Mutual Certificate Authentication**
- 🗝️ **Diffie-Hellman Key Exchange**
- 📝 **Real-time Encrypted Messaging**
- 📊 **Session Transcripts & Digital Receipts**
- 🛡️ **Replay Attack Protection**
- 🔍 **Tamper Detection**
- ✅ **Comprehensive Test Suite**

## 📁 Project Structure

Secure-Chat-Protocol/
├── 📂 database/
│ └── schema.sql
├── 📂 scripts/
│ ├── gen_ca.py
│ └── gen_cert.py
├── 📂 src/
│ ├── client.py
│ ├── server.py
│ ├── crypto_utils.py
│ ├── transcripts.py
│ └── protocol.py
├── 📂 tests/
│ ├── test_certificates.py
│ ├── test_crypto.py
│ ├── test_tampering.py
│ ├── test_replay.py
│ └── test_non_repudiation.py
├── 📂 docs/
│ ├── 📂 wireshark/
│ ├── 📂 test_results/
│ └── 📂 screenshots/
├── 📄 run_client.py
├── 📄 run_server.py
├── 📄 run_tests.py
├── 📄 requirements.txt
└── 📄 README.md
text


## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- MySQL Server 5.7+
- OpenSSL

### Step-by-Step Setup

1. **Clone the Repository**
```bash
git clone https://github.com/hammadshabbir10/Secure-Chat-Protocol.git
cd Secure-Chat-Protocol

    Create Virtual Environment

bash

python -m venv securechat-env
source securechat-env/bin/activate

    Install Dependencies

bash

pip install -r requirements.txt

    Database Setup

bash

sudo systemctl start mysql
mysql -u root -p < database/schema.sql

    Generate Certificates

bash

python scripts/gen_ca.py
python scripts/gen_cert.py "SecureChat Server" server
python scripts/gen_cert.py "SecureChat Client" client

⚡ Quick Start
Starting the System

    Start the Server

bash

python run_server.py

Expected Output:
text

🚀 Starting Secure Chat Server...
📍 Server running on localhost:8080
✅ Server certificates loaded
✅ Database connection established

    Start the Client

bash

python run_client.py

Expected Output:
text

🚀 Starting Secure Chat Client...
📍 Connecting to localhost:8080
✅ Client certificates loaded
🔗 Connected to server localhost:8080

🎮 Usage
Authentication Process

    Client Connection

text

🔐 Authentication
Register or Login? (r/l): l
Email: user@example.com
Password: ********

    Secure Handshake

    Certificate exchange and validation

    Diffie-Hellman key exchange

    User authentication

    Session key establishment

    Secure Chat

text

💬 Chat started! Type your messages (type 'exit' to quit)
You: Hello, this is a secure message!
📨 Server: Hello, this is a secure message!

🧪 Testing
Running All Tests
bash

python run_tests.py

Individual Test Categories
bash

python -m unittest discover tests/ -p "test_*.py"
python tests/test_tampering.py
python tests/test_replay.py
python tests/test_non_repudiation.py
python tests/test_certificates.py
python tests/test_crypto.py

Test Results

    ✅ Unit Tests: 7/7 passed

    ✅ Security Tests: 4/4 passed

    ✅ Overall: 11/11 tests passed (100%)

    ⏱️ Execution Time: 1.953 seconds

Test Output
text

🧪 Running Secure Chat System Tests
test_expired_certificate ... ✅ PASSED
test_self_signed_certificate ... ✅ PASSED
test_valid_certificate ... ✅ PASSED
test_aes_encryption_decryption ... ✅ PASSED
test_diffie_hellman_key_exchange ... ✅ PASSED
test_message_integrity_with_rsa ... ✅ PASSED
test_password_hashing ... ✅ PASSED

🔒 Running Security Tests
🔍 Invalid Certificate Test ... ✅ PASSED
🔍 Tampering Detection Test ... ✅ PASSED
🔍 Replay Attack Test ... ✅ PASSED
🔍 Non-Repudiation Test ... ✅ PASSED

🎉 ALL TESTS PASSED!

🔒 Security Implementation
Cryptographic Protocols
Security Aspect	Implementation
Confidentiality	AES-128 CBC mode with PKCS7 padding
Integrity	RSA-PSS signatures with SHA-256
Key Exchange	Diffie-Hellman (2048-bit)
Authentication	X.509 certificate mutual auth
Non-Repudiation	Signed transcripts & receipts
Attack Prevention

    🛡️ Replay Attacks: Sequence numbers + timestamp validation

    🔍 Tampering: Digital signatures + hash verification

    👥 MITM Attacks: Certificate pinning + validation

    ⏰ Freshness: Timestamp checks

📚 Documentation
Documentation Structure
text

docs/
├── 📂 wireshark/
├── 📂 test_results/
└── 📂 screenshots/

🌐 GitHub Repository

Repository: https://github.com/hammadshabbir10/Secure-Chat-Protocol
bash

git clone https://github.com/hammadshabbir10/Secure-Chat-Protocol.git
cd Secure-Chat-Protocol

💡 Recommendations
Development Approach

Phase 1: Planning & Design

    Define security requirements

    Design protocol flows

    Plan certificate management

Phase 2: Core Implementation

    Implement crypto utilities

    Set up Certificate Authority

    Create unit tests

Phase 3: Protocol Development

    Implement certificate exchange

    Build Diffie-Hellman key exchange

    Add user authentication

Phase 4: Advanced Features

    Create transcript system

    Implement digital receipts

    Build tamper detection

Phase 5: Testing & Documentation

    Comprehensive testing

    Gather evidence

    Prepare documentation

Technical Recommendations

    Start early with cryptographic implementations

    Use version control continuously

    Test all components thoroughly

    Document everything systematically

    Collect comprehensive evidence

🔧 Troubleshooting
Common Issues

Certificate Generation Errors
bash

openssl version
rm -rf certs/*
python scripts/gen_ca.py

Database Connection Issues
bash

sudo systemctl status mysql
mysql -u root -p -e "SHOW DATABASES;"

Port Already in Use
bash

sudo lsof -i :8080
sudo kill -9 <PID>

📝 Protocol Messages

Client Hello:
json

{
  "type": "hello",
  "client_cert": "BASE64_ENCODED_CERT",
  "nonce": "RANDOM_NONCE"
}

Server Hello:
json

{
  "type": "server_hello", 
  "server_cert": "BASE64_ENCODED_CERT",
  "nonce": "RANDOM_NONCE"
}

Encrypted Message:
json

{
  "type": "msg",
  "seqno": 1,
  "ts": 1635789200000,
  "ct": "BASE64_CIPHERTEXT",
  "sig": "BASE64_SIGNATURE"
}

🤝 Contributing

    Fork the repository

    Create feature branch

    Commit changes

    Push to branch

    Create Pull Request

📄 License

Educational project for Information Security coursework.
👨‍💻 Author

Hammad Shabbir

    Roll Number: 22i-1140

    Section: CS-F

    Email: hammadshabbir507@gmail.com

    GitHub: hammadshabbir10


