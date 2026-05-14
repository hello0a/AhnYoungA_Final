package com.auth.domain;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class RefreshToken {
    private Long no;
    private Long userNo;
    private String tokenHash;
    private String deviceInfo;
    private String ipAddress;
    private LocalDateTime expiryDate;
    private boolean revoked;
    private LocalDateTime createdAt;
}
