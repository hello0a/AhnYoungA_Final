 -- Active: 1770210803187@@127.0.0.1@3306@aloha
DROP TABLE IF EXISTS 
    email_verification,
    persistent_logins,
    password_history,
    login_history,
    users2;
CREATE TABLE users2 (
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
    FOREIGN KEY (user_no) REFERENCES users2(no) ON DELETE SET NULL
);

CREATE TABLE password_history (
    `no` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_no` BIGINT NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_no) REFERENCES users2(no) ON DELETE CASCADE
);

CREATE TABLE persistent_logins (
    `username` VARCHAR(64) NOT NULL,
    `series` VARCHAR(64) PRIMARY KEY,
    `token` VARCHAR(64) NOT NULL,
    `last_used` TIMESTAMP NOT NULL
);

CREATE TABLE email_verification (
    `no` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_no` BIGINT,
    `email` VARCHAR(255) NOT NULL,
    `code` VARCHAR(255) NOT NULL,
    `expiry` DATETIME NOT NULL,
    FOREIGN KEY (user_no) REFERENCES users2(no) ON DELETE CASCADE
);

ALTER TABLE users2 ADD login_fail_count INT DEFAULT 0;
ALTER TABLE users2 ADD locked BOOLEAN DEFAULT FALSE;