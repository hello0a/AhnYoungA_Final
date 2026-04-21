package com.auth.domain;

import lombok.Data;

@Data
public class LoginHistory {
    private Long no;
    private String userId;
    private String ipAddress;
    private String userAgent;
    private boolean success;
}
