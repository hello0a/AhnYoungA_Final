package com.auth.service;

import java.time.LocalDateTime;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {
    
    private final EmailVerificationMapper mapper;
    private final PasswordEncoder passwordEncoder;

    public void sendCode(String email) {
        String code = String.valueOf((int)(Math.random() * 900000) + 100000);
        String encoded = passwordEncoder.encode(code);

        mapper.insert(0L, email, encoded, LocalDateTime.now().plusMinutes(5));

        System.out.println("인증코드: " + code);
    }

    public boolean verify(String input, String stored) {
        return passwordEncoder.matches(input, stored);
    }

}
