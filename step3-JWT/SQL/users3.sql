-- Active: 1770210803187@@127.0.0.1@3306@aloha
DROP TABLE IF EXISTS email_verification,
persistent_logins,
password_history,
login_history,
users3;

CREATE TABLE users3 (
    `no` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `id` VARCHAR(64) UNIQUE NOT NULL,
    `email` VARCHAR(255) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE login_history (
    `no` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_no` BIGINT,
    `ip_address` VARCHAR(100),
    `user_agent` VARCHAR(500),
    `login_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `success` BOOLEAN NOT NULL,
    FOREIGN KEY (user_no) REFERENCES users3 (no) ON DELETE SET NULL
);

CREATE TABLE password_history (
    `no` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_no` BIGINT NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_no) REFERENCES users3 (no) ON DELETE CASCADE
);

CREATE TABLE persistent_logins (
    `series` VARCHAR(64) PRIMARY KEY,
    `username` VARCHAR(64) NOT NULL,
    `token` VARCHAR(64) NOT NULL,
    `last_used` TIMESTAMP NOT NULL
);

CREATE TABLE email_verification (
    `no` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_no` BIGINT,
    `email` VARCHAR(255) NOT NULL,
    `code` VARCHAR(255) NOT NULL,
    `expiry` DATETIME NOT NULL,
    FOREIGN KEY (user_no) REFERENCES users3 (no) ON DELETE CASCADE
);

ALTER TABLE users3 ADD login_fail_count INT DEFAULT 0;
ALTER TABLE users3 ADD locked BOOLEAN DEFAULT FALSE;
-- 인증코드 생성
ALTER TABLE email_verification
ADD created_at DATETIME DEFAULT CURRENT_TIMESTAMP;
-- 인증코드 실패 횟수
ALTER TABLE email_verification ADD fail_count INT DEFAULT 0;

-- step3 추가
CREATE TABLE refresh_tokens (
    `no` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_no` BIGINT NOT NULL,
    `token_hash` VARCHAR(255) NOT NULL,
    `device_info` VARCHAR(255),
    `ip_address` VARCHAR(100),
    `expiry_date` DATETIME NOT NULL,
    `revoked` BOOLEAN NOT NULL DEFAULT FALSE,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_no) REFERENCES users3(no) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_user ON refresh_tokens(user_no);
CREATE INDEX idx_refresh_token_hash ON refresh_tokens(token_hash);