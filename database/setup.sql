-- Ma'lumotlar bazasi yaratish
CREATE DATABASE IF NOT EXISTS web_security_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE web_security_db;

-- Foydalanuvchilar jadvali
CREATE TABLE users (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       username VARCHAR(50) NOT NULL UNIQUE,
                       email VARCHAR(100) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL,
                       full_name VARCHAR(100) NOT NULL,
                       role ENUM('user', 'admin') DEFAULT 'user',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       last_login TIMESTAMP NULL,
                       is_active BOOLEAN DEFAULT TRUE,
                       failed_login_attempts INT DEFAULT 0,
                       locked_until TIMESTAMP NULL
);

-- Xavfsizlik loglari jadvali
CREATE TABLE security_logs (
                               id INT AUTO_INCREMENT PRIMARY KEY,
                               user_id INT NULL,
                               action_type VARCHAR(50) NOT NULL,
                               ip_address VARCHAR(45) NOT NULL,
                               user_agent TEXT,
                               timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               details TEXT,
                               risk_level ENUM('low', 'medium', 'high') DEFAULT 'low',
                               FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- CSRF tokenlar jadvali
CREATE TABLE csrf_tokens (
                             id INT AUTO_INCREMENT PRIMARY KEY,
                             user_id INT NOT NULL,
                             token VARCHAR(64) NOT NULL,
                             expires_at TIMESTAMP NOT NULL,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Rate limiting jadvali
CREATE TABLE rate_limits (
                             id INT AUTO_INCREMENT PRIMARY KEY,
                             ip_address VARCHAR(45) NOT NULL,
                             action_type VARCHAR(50) NOT NULL,
                             attempts INT DEFAULT 1,
                             last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             blocked_until TIMESTAMP NULL,
                             INDEX idx_ip_action (ip_address, action_type)
);

-- Test foydalanuvchi (admin)
INSERT INTO users (username, email, password_hash, full_name, role) VALUES
    ('admin', 'admin@test.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'System Administrator', 'admin');

-- Test foydalanuvchi (oddiy)
INSERT INTO users (username, email, password_hash, full_name, role) VALUES
    ('testuser', 'user@test.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test User', 'user');

-- Test ma'lumotlari uchun jadval
CREATE TABLE user_data (
                           id INT AUTO_INCREMENT PRIMARY KEY,
                           user_id INT NOT NULL,
                           title VARCHAR(100) NOT NULL,
                           content TEXT,
                           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                           FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);