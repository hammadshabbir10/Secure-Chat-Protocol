-- Secure Chat System Database Schema
-- Created for Information Security Assignment #2

CREATE DATABASE IF NOT EXISTS secure_chat;
USE secure_chat;

-- Users table for storing authentication information
CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,  -- SHA-256 produces 64 char hex string
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

-- Optional: Sessions table for tracking active sessions (bonus feature)
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
);

-- Create database user and grant privileges
CREATE USER IF NOT EXISTS 'chat_user'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON secure_chat.* TO 'chat_user'@'localhost';
FLUSH PRIVILEGES;

-- Display confirmation
SELECT '✅ Database schema created successfully!' as status;
