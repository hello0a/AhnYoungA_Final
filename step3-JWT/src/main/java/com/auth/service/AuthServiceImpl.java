package com.auth.service;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.domain.LoginHistory;
import com.auth.domain.RefreshToken;
import com.auth.domain.User;
import com.auth.dto.AuthResponse;
import com.auth.dto.LoginRequest;
import com.auth.mapper.LoginHistoryMapper;
import com.auth.mapper.RefreshTokenMapper;
import com.auth.mapper.UserMapper;
import com.auth.security.JwtProvider;
import com.auth.util.TokenHashUtil;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final LoginHistoryMapper loginHistoryMapper;
    // step3 추가
    private final UserMapper userMapper;
    private final RefreshTokenMapper refreshTokenMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    @Override
    public void saveHistory(Long userNo, HttpServletRequest request, boolean success) {

        loginHistoryMapper.insert(
                userNo,
                request.getRemoteAddr(),
                request.getHeader("User-Agent"),
                success);

    }

    // step3 추가
    @Override
    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        
        User user = userMapper.findByEmail(request.getEmail());

        if (user == null) {
            saveHistory(null, httpRequest, false);
            throw new RuntimeException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        if (user.isLocked() || user.getLoginFailCount() >= 3) {
            saveHistory(user.getNo(), httpRequest, false);
            throw new RuntimeException("계정이 잠겼습니다. 관리자에게 문의하세요.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            userMapper.increaseFailCount(user.getNo());

            User updatedUser = userMapper.findByEmail(request.getEmail());
            if (updatedUser.getLoginFailCount() >= 3) {
                userMapper.lockedUser(user.getNo());
            }

            saveHistory(user.getNo(), httpRequest, false);
            throw new RuntimeException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        userMapper.resetFailCount(user.getNo());
        saveHistory(user.getNo(), httpRequest, true);

        String accessToken = jwtProvider.createAccessToken(user.getNo());
        String refreshToken = jwtProvider.createRefreshToken(user.getNo());

        saveRefreshToken(user.getNo(), refreshToken, httpRequest);
        
        return new AuthResponse(accessToken, refreshToken);
    }

    @Override
    @Transactional
    public AuthResponse refresh(String refreshToken) {
        
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new RuntimeException("Refresh Token이 없습니다.");
        }

        if (!jwtProvider.validateToken(refreshToken)) {
            throw new RuntimeException("Refresh Token이 유효하지 않습니다.");
        }

        if (!"REFRESH".equals(jwtProvider.getTokenType(refreshToken))) {
            throw new RuntimeException("Refresh Token 형식이 아닙니다.");
        }

        String tokenHash = TokenHashUtil.sha256(refreshToken);
        RefreshToken savedToken = refreshTokenMapper.findByTokenHash(tokenHash);

        if (savedToken == null) {
            throw new RuntimeException("Refresh Token이 존재하지 않습니다.");
        }

        if (savedToken.isRevoked()) {
            throw new RuntimeException("폐기된 Refresh Token입니다.");
        }

        if (savedToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh Token이 만료되었습니다.");
        }

        Long userNo = jwtProvider.getUserNo(refreshToken);

        if (!savedToken.getUserNo().equals(userNo)) {
            throw new RuntimeException("Refresh Token 사용자 정보가 일치하지 않습니다.");
        }

        String newAccessToken = jwtProvider.createAccessToken(userNo);

        // Step3 기본 정책: Refresh Token 그대로 유지
        return new AuthResponse(newAccessToken, refreshToken);

    }

    @Override
    @Transactional
    public void logout(String refreshToken, Long userNo) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new RuntimeException("Refresh Token이 없습니다.");
        }

        String tokenHash = TokenHashUtil.sha256(refreshToken);
        RefreshToken savedToken = refreshTokenMapper.findByTokenHash(tokenHash);

        if (savedToken == null) {
            throw new RuntimeException("Refresh Token이 존재하지 않습니다.");
        }
        if (!savedToken.getUserNo().equals(userNo)) {
            throw new RuntimeException("본인의 Refresh Token만 로그아웃할 수 있습니다.");
        }

        refreshTokenMapper.revokeByTokenHash(tokenHash);
    }

    @Override
    public List<LoginHistory> getLoginHistory(Long userNo) {
        return loginHistoryMapper.findByUserNo(userNo);
    }

    private void saveRefreshToken(Long userNo, String refreshToken, HttpServletRequest request) {
        RefreshToken token = new RefreshToken();
        token.setUserNo(userNo);
        token.setTokenHash(TokenHashUtil.sha256(refreshToken));
        token.setDeviceInfo(request.getHeader("User-Agent"));
        token.setIpAddress(request.getRemoteAddr());
        token.setExpiryDate(LocalDateTime.now().plusSeconds(jwtProvider.getRefreshTokenValidityMs() / 1000));
        token.setRevoked(false);

        refreshTokenMapper.insert(token);
    }

}
