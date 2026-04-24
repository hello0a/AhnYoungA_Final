package com.auth.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.domain.User;
import com.auth.mapper.LoginHistoryMapper;
import com.auth.mapper.UserMapper;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

// 클래스 정의/구현 이유
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{

    private final UserMapper userMapper;
    private final LoginHistoryMapper loginHistoryMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User login(String email, String password, HttpServletRequest request) {

        User user = userMapper.findByEmail(email);

        if (user == null) {
            saveHistory(null, request, false);
            throw new RuntimeException("아이디 또는 비밀번호 오류");
        }

        // 계정 잠금 체크
        if (user.getLoginFailCount() >= 3) {
            throw new RuntimeException("계정 잠금");
        }
        // 비밀번호 검증
        if (!passwordEncoder.matches(password, user.getPassword())) {
            userMapper.increaseFailCount(user.getNo());
            saveHistory(user.getNo(), request, false);

            throw new RuntimeException("아이디 또는 비밀번호 오류");
        }
        // 로그인 성공
        userMapper.resetFailCount(user.getNo());
        saveHistory(user.getNo(), request, true);

        return user;
    }

    @Override
    public void saveHistory(Long userId, HttpServletRequest request, boolean success) {
        
        loginHistoryMapper.insert(
            userId,
            request.getRemoteAddr(),
            request.getHeader("User-Agent"),
            success
        );

    }
    
}
