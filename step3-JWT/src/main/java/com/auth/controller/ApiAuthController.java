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
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;

// AuthController: 화면용
// JWT API
@Slf4j
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
        log.info("***API Auth 로그인 요청: email={}, ip={}",
            loginRequest.getEmail(),
            httpRequest.getRemoteAddr()
        );
        return authService.login(loginRequest, httpRequest);
    }

    @PostMapping("/api/auth/refresh")
    public AuthResponse refresh(@RequestBody RefreshRequest request) {
        log.info("***API Auth: Acess Token 재발급 요청");

        return authService.refresh(request.getRefreshToken());
    }
    
    @PostMapping("/api/auth/logout")
    public Map<String, Object> logout(
        @RequestBody LogoutRequest request,
        Authentication authentication
    ) {
        Long userNo = (Long) authentication.getPrincipal();

        log.info("***API Auth 로그아웃 요청: userNo={}", userNo);

        authService.logout(request.getRefreshToken(), userNo);

        return Map.of("success", true);
    }
    
    @GetMapping("/api/auth/me")
    public MeResponse meResponse(Authentication authentication) {
        Long userNo = (Long) authentication.getPrincipal();

        log.debug("***API Auth 내 정보 조회 요청: userNo={}", userNo);
        
        User user = userMapper.findByNo(userNo);
        if (user == null) {
            log.warn("***API Auth 내 정보 조회 실패: 사용자 없음, userNo={}", userNo);
            throw new RuntimeException("사용자 없음");
        }

        return new MeResponse(user);
    }

    @GetMapping("/api/auth/login-history")
    public List<LoginHistory> loginHistory(Authentication authentication) {
        Long userNo = (Long) authentication.getPrincipal();

        log.debug("***API Auth 로그인 이력 조회 요청: userNo={}", userNo);
        
        return authService.getLoginHistory(userNo);
    }
    
    
}
