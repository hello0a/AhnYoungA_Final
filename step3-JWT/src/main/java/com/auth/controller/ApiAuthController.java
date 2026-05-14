package com.auth.controller;

import org.springframework.web.bind.annotation.RestController;

import com.auth.domain.LoginHistory;
import com.auth.domain.User;
import com.auth.dto.AuthResponse;
import com.auth.dto.LoginRequest;
import com.auth.dto.LogoutRequest;
import com.auth.dto.MeResponse;
import com.auth.dto.RefreshRequest;
import com.auth.mapper.UserMapper;
import com.auth.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;

// AuthController: 화면용
// JWT API
@RestController
@RequiredArgsConstructor
public class ApiAuthController {
    
    private final AuthService authService;
    private final UserMapper userMapper;

    @PostMapping("/api/auth/login")
    public AuthResponse login (
        @RequestBody LoginRequest loginRequest,
        HttpServletRequest httpRequest
    ) {
        return authService.login(loginRequest, httpRequest);
    }

    @PostMapping("/api/auth/refresh")
    public AuthResponse refresh(@RequestBody RefreshRequest request) {
        return authService.refresh(request.getRefreshToken());
    }
    
    @PostMapping("/api/auth/logout")
    public Map<String, Object> logout(@RequestBody LogoutRequest request) {
        authService.logout(request.getRefreshToken());
        return Map.of("success", true);
    }
    
    @GetMapping("/api/auth/me")
    public MeResponse meResponse(Authentication authentication) {
        Long userNo = (Long) authentication.getPrincipal();
        
        User user = userMapper.findByNo(userNo);
        if (user == null) {
            throw new RuntimeException("사용자 없음");
        }

        return new MeResponse(user);
    }

    @GetMapping("/api/auth/login-history")
    public List<LoginHistory> loginHistory(Authentication authentication) {
        Long userNo = (Long) authentication.getPrincipal();
        return authService.getLoginHistory(userNo);
    }
    
    
}
