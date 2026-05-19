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
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final LoginHistoryMapper loginHistoryMapper;
    // step3 추가
    private final UserMapper userMapper;
    private final RefreshTokenMapper refreshTokenMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    // 실패 처리 트랜잭션
    private final AuthFailureService authFailureService;

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
        
        log.info("***Auth Login 로그인 요청: email={}, ip={}",
            request.getEmail(),
            httpRequest.getRemoteAddr()
        );

        User user = userMapper.findByEmail(request.getEmail());

        if (user == null) {
            log.warn("***Auth login 실패: 존재하지 않는 이메일, email={}",
                request.getEmail()
            );
            authFailureService.recordFailure(null, request.getEmail(), httpRequest);
            throw new RuntimeException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        if (user.isLocked() || user.getLoginFailCount() >= 3) {
            log.warn("***Auth Login 실패: 잠금 계정, userNo={}", user.getNo());
            authFailureService.recordLockedFailure(user.getNo(), httpRequest);

            throw new RuntimeException("로그인 실패 횟수가 초과되어 계정이 잠겼습니다.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            log.warn("***Auth Login 실패: 비밀번호 불일치, userNo={}", user.getNo());
            
            int failCount = authFailureService.recordFailure(
                user.getNo(), request.getEmail(), httpRequest
            );

            // login_fail_count 안됌
            log.warn("***Auth Login 실패 횟수 확인: userNo={}, failCount={}",
                user.getNo(),
                failCount
            );

            throw new RuntimeException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        userMapper.resetFailCount(user.getNo());
        saveHistory(user.getNo(), httpRequest, true);

        String accessToken = jwtProvider.createAccessToken(user.getNo());
        String refreshToken = jwtProvider.createRefreshToken(user.getNo());

        saveRefreshToken(user.getNo(), refreshToken, httpRequest);

        log.info("***Auth Login 성공: userNo={}", user.getNo());
        
        return new AuthResponse(accessToken, refreshToken);
    }

    @Override
    @Transactional
    public AuthResponse refresh(String refreshToken) {

        log.info("***Auth Refresh 재발급 요청");
        
        if (refreshToken == null || refreshToken.isBlank()) {
            log.warn("***Auth Refresh 실패: Refresh Token 없음");
            throw new RuntimeException("Refresh Token이 없습니다.");
        }

        if (!jwtProvider.validateToken(refreshToken)) {
            log.warn("***Auth Refresh 실패: Refresh Token 검증 실패");
            throw new RuntimeException("Refresh Token이 유효하지 않습니다.");
        }

        if (!"REFRESH".equals(jwtProvider.getTokenType(refreshToken))) {
            log.warn("***Auth Refresh 실패: 토큰 타입 불일치");
            throw new RuntimeException("Refresh Token 형식이 아닙니다.");
        }

        String tokenHash = TokenHashUtil.sha256(refreshToken);
        RefreshToken savedToken = refreshTokenMapper.findByTokenHash(tokenHash);

        if (savedToken == null) {
            log.warn("***Auth Refresh 실패: DB에 토큰 없음");
            throw new RuntimeException("Refresh Token이 존재하지 않습니다.");
        }

        if (savedToken.isRevoked()) {
            log.warn("***Auth Refresh 실패: 폐기된 토큰, userNo={}", savedToken.getUserNo());
            throw new RuntimeException("폐기된 Refresh Token입니다.");
        }

        if (savedToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            log.warn("***Auth Refresh 실패: 만료된 토큰, userNo={}", savedToken.getUserNo());
            throw new RuntimeException("Refresh Token이 만료되었습니다.");
        }

        Long userNo = jwtProvider.getUserNo(refreshToken);

        if (!savedToken.getUserNo().equals(userNo)) {
            log.warn("***Auth Refresh 실패: 사용자 불일치, tokenUserNo={}, dbUserNo={}",
                userNo,
                savedToken.getUserNo()
            );
            throw new RuntimeException("Refresh Token 사용자 정보가 일치하지 않습니다.");
        }

        String newAccessToken = jwtProvider.createAccessToken(userNo);

        log.info("***Auth Refresh 성공: userNo={}", userNo);

        // Step3 기본 정책: Refresh Token 그대로 유지
        return new AuthResponse(newAccessToken, refreshToken);

    }

    @Override
    @Transactional
    public void logout(String refreshToken, Long userNo) {

        log.info("***Auth Logout 로그아웃 요청: userNo={}", userNo);

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new RuntimeException("Refresh Token이 없습니다.");
        }

        String tokenHash = TokenHashUtil.sha256(refreshToken);
        RefreshToken savedToken = refreshTokenMapper.findByTokenHash(tokenHash);

        if (savedToken == null) {
            log.warn("***Auth Logout 실패: DB에 토큰 없음, userNo={}", userNo);
            throw new RuntimeException("Refresh Token이 존재하지 않습니다.");
        }
        if (!savedToken.getUserNo().equals(userNo)) {
            log.warn("***Auth Logout 실패: 본인 토큰 아님, requestUserNo={}, tokenUserNo={}",
                userNo,
                savedToken.getUserNo()
            );
            throw new RuntimeException("본인의 Refresh Token만 로그아웃할 수 있습니다.");
        }

        int updated = refreshTokenMapper.revokeByTokenHash(tokenHash);

        if (updated != 1) {
            log.warn("***Auth Logout 실패: Refresh Token 폐기 실패, userNo={}", userNo);
            throw new RuntimeException("Refresh Token 폐기 실패");
        }

        log.info("***Auth Logout 성공: userNo={}", userNo);
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
