package com.auth.domain;

import lombok.Data;

@Data
public class LoginHistory {
    private Long no;
    private Long userNo;
    private String ipAddress;
    private String userAgent;
    private boolean success;
}
