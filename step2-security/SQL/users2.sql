 -- Active: 1770210803187@@127.0.0.1@3306@aloha
DROP TABLE IF EXISTS 
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
    `user_id` BIGINT,
    `ip_address` VARCHAR(100),
    `user_agent` VARCHAR(500),
    `login_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `success` BOOLEAN NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users2(no) ON DELETE SET NULL
);

CREATE TABLE password_history (
    `no` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_id` BIGINT NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users2(no) ON DELETE CASCADE
);

CREATE TABLE persistent_logins (
    `series` VARCHAR(64) PRIMARY KEY,
    `user_id` BIGINT NOT NULL,
    `token` VARCHAR(255) NOT NULL,
    `last_used` DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users2(no) ON DELETE CASCADE
);

ALTER TABLE users2 ADD login_fail_count INT DEFAULT 0;