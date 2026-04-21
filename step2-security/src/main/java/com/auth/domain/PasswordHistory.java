package com.auth.domain;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class PasswordHistory {
    private Long no;
    private Long userId;
    private String password;
    private LocalDateTime createdAt;
}
