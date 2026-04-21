package com.auth.service;

import org.springframework.stereotype.Service;

@Service
public class PasswordPolicyService {
    
    public void validate(String password) {

        if (password.length() < 8) {
            throw new RuntimeException("비밀번호는 8자 이상");
        }
        if (!password.matches(".*[!@#$%^&*()].*")) {
            throw new RuntimeException("특수문자 포함 필요");
        }
        if (!password.matches(".*\\d.*")) {
            throw new RuntimeException("숫자 포함 필요");
        }
    }
}
