package com.auth.service;

import java.time.LocalDateTime;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.domain.EmailVerification;
import com.auth.domain.User;
import com.auth.mapper.EmailVerificationMapper;
import com.auth.mapper.UserMapper;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {
    
    private final UserMapper userMapper;
    private final EmailVerificationMapper mapper;
    private final PasswordEncoder passwordEncoder;

    public void sendCode(String email) {
        User user = userMapper.findByEmail(email);
        if (user == null) {
            return;
        }

        String code = String.valueOf((int)(Math.random() * 900000) + 100000);
        String encoded = passwordEncoder.encode(code);

        mapper.insert(user.getNo(), email, encoded, LocalDateTime.now().plusMinutes(5));

        System.out.println("인증코드: " + code);
    }

    public boolean verifyCode(String email, String input) {
        EmailVerification verification = mapper.findByEmail(email);
        if (verification == null || verification.getExpiry() == null || verification.getExpiry().isBefore(LocalDateTime.now())) {
            return false;
        }

        boolean valid = passwordEncoder.matches(input, verification.getCode());
        if (valid) {
            mapper.deleteByEmail(email);
        }
        return valid;
    }

    public void deleteVerification(String email) {
        mapper.deleteByEmail(email);
    }
}
