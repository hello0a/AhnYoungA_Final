package com.auth.service;

import java.time.LocalDateTime;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
        String code = String.valueOf((int)(Math.random() * 900000) + 100000);
        String encoded = passwordEncoder.encode(code);

        User user = userMapper.findByEmail(email);
        Long userNo = (user != null) ? user.getNo() : null;

        mapper.insert(userNo, email, encoded, LocalDateTime.now().plusMinutes(5));

        System.out.println("인증코드: " + code);
    }

    public boolean verify(String input, String stored) {
        return passwordEncoder.matches(input, stored);
    }

}
