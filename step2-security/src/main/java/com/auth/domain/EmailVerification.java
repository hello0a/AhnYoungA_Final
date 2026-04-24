package com.auth.domain;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class EmailVerification {
    private Long no;
    private Long userNo;
    private String email;
    private String code;
    private LocalDateTime expiry;
}
