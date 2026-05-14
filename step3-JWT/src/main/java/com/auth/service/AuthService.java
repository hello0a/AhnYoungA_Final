package com.auth.service;

import java.util.List;

import com.auth.domain.LoginHistory;
import com.auth.dto.AuthResponse;
import com.auth.dto.LoginRequest;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
    // 로그인 저장 기록
    void saveHistory(Long userNo, HttpServletRequest request, boolean success);

    // step3 추가
    // 로그인
    AuthResponse login(LoginRequest request, HttpServletRequest httpRequest);
    AuthResponse refresh(String refreshToken);
    // 로그아웃
    void logout(String refreshToken);
    List<LoginHistory> getLoginHistory(Long userNo);
}
