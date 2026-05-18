package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.auth.domain.RefreshToken;
import com.auth.domain.User;
import com.auth.dto.AuthResponse;
import com.auth.dto.LoginRequest;
import com.auth.mapper.LoginHistoryMapper;
import com.auth.mapper.RefreshTokenMapper;
import com.auth.mapper.UserMapper;
import com.auth.security.JwtProvider;
import com.auth.service.AuthServiceImpl;
import com.auth.util.TokenHashUtil;

import jakarta.servlet.http.HttpServletRequest;

// Step3 핵심 테스트
// login / refresh / logout 검증용
@ExtendWith(MockitoExtension.class)
class AuthServiceUnitTest {
    
    @Mock
    private LoginHistoryMapper loginHistoryMapper;

    @Mock
    private UserMapper userMapper;

    @Mock
    private RefreshTokenMapper refreshTokenMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    private JwtProvider jwtProvider;

    private AuthServiceImpl authServiceImpl;

    private User user;
    private HttpServletRequest httpRequest;

    @BeforeEach
    void setup() {
        jwtProvider = new JwtProvider(
            "step3-jwt-secret-key-must-be-at-least-32-bytes-2026", 
            1800000, 
            604800000
        );

        authServiceImpl = new AuthServiceImpl(
            loginHistoryMapper, userMapper, refreshTokenMapper, passwordEncoder, jwtProvider
        );

        user = new User();
        user.setNo(1L);
        user.setEmail("test@test.com");
        user.setPassword("encoded-password");
        user.setName("테스터");
        user.setLoginFailCount(0);
        user.setLocked(false);

        httpRequest = mock(HttpServletRequest.class);
        when(httpRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(httpRequest.getHeader("User-Agent")).thenReturn("JUnit");
    }

    @Test
    void login_succes_issues_tokens_and_saves_refresh_token() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@test.com");
        request.setPassword("Abcd1234!");

        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(passwordEncoder.matches("Abcd1234!", "encoded-password")).thenReturn(true);

        AuthResponse response = authServiceImpl.login(request, httpRequest);

        assertNotNull(response.getAccessToken());
        assertNotNull(response.getRefreshToken());

        verify(userMapper).resetFailCount(1L);
        verify(loginHistoryMapper).insert(1L, "127.0.0.1", "JUnit", true);

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenMapper).insert(captor.capture());

        RefreshToken saved = captor.getValue();

        assertEquals(1L, saved.getUserNo());
        assertNotNull(saved.getTokenHash());
        assertEquals("127.0.0.1", saved.getIpAddress());
        assertEquals("JUnit", saved.getDeviceInfo());
    }

     @Test
    void login_fail_when_user_not_found() {
        LoginRequest request = new LoginRequest();
        request.setEmail("none@test.com");
        request.setPassword("Abcd1234!");

        when(userMapper.findByEmail("none@test.com")).thenReturn(null);

        assertThrows(RuntimeException.class, () -> {
            authServiceImpl.login(request, httpRequest);
        });

        verify(loginHistoryMapper).insert(null, "127.0.0.1", "JUnit", false);
        verify(refreshTokenMapper, never()).insert(any());
    }

    @Test
    void login_fail_wrong_password_increases_fail_count() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@test.com");
        request.setPassword("wrong");

        User updated = new User();
        updated.setNo(1L);
        updated.setEmail("test@test.com");
        updated.setPassword("encoded-password");
        updated.setLoginFailCount(1);

        when(userMapper.findByEmail("test@test.com"))
                .thenReturn(user)
                .thenReturn(updated);

        when(passwordEncoder.matches("wrong", "encoded-password")).thenReturn(false);

        assertThrows(RuntimeException.class, () -> {
            authServiceImpl.login(request, httpRequest);
        });

        verify(userMapper).increaseFailCount(1L);
        verify(loginHistoryMapper).insert(1L, "127.0.0.1", "JUnit", false);
    }

    @Test
    void refresh_success() {
        String refreshToken = jwtProvider.createRefreshToken(1L);
        String hash = TokenHashUtil.sha256(refreshToken);

        RefreshToken saved = new RefreshToken();
        saved.setUserNo(1L);
        saved.setTokenHash(hash);
        saved.setRevoked(false);
        saved.setExpiryDate(LocalDateTime.now().plusDays(7));

        when(refreshTokenMapper.findByTokenHash(hash)).thenReturn(saved);

        AuthResponse response = authServiceImpl.refresh(refreshToken);

        assertNotNull(response.getAccessToken());
        assertEquals(refreshToken, response.getRefreshToken());
    }

    @Test
    void refresh_fail_when_revoked() {
        String refreshToken = jwtProvider.createRefreshToken(1L);
        String hash = TokenHashUtil.sha256(refreshToken);

        RefreshToken saved = new RefreshToken();
        saved.setUserNo(1L);
        saved.setTokenHash(hash);
        saved.setRevoked(true);
        saved.setExpiryDate(LocalDateTime.now().plusDays(7));

        when(refreshTokenMapper.findByTokenHash(hash)).thenReturn(saved);

        assertThrows(RuntimeException.class, () -> {
            authServiceImpl.refresh(refreshToken);
        });
    }

    @Test
    void refresh_fail_when_expired() {
        String refreshToken = jwtProvider.createRefreshToken(1L);
        String hash = TokenHashUtil.sha256(refreshToken);

        RefreshToken saved = new RefreshToken();
        saved.setUserNo(1L);
        saved.setTokenHash(hash);
        saved.setRevoked(false);
        saved.setExpiryDate(LocalDateTime.now().minusSeconds(1));

        when(refreshTokenMapper.findByTokenHash(hash)).thenReturn(saved);

        assertThrows(RuntimeException.class, () -> {
            authServiceImpl.refresh(refreshToken);
        });
    }

    @Test
    void logout_success() {
        String refreshToken = jwtProvider.createRefreshToken(1L);
        String hash = TokenHashUtil.sha256(refreshToken);

        RefreshToken saved = new RefreshToken();
        saved.setUserNo(1L);
        saved.setTokenHash(hash);
        saved.setRevoked(false);
        saved.setExpiryDate(LocalDateTime.now().plusDays(7));

        when(refreshTokenMapper.findByTokenHash(hash)).thenReturn(saved);

        authServiceImpl.logout(refreshToken, 1L);

        verify(refreshTokenMapper).revokeByTokenHash(hash);
    }

    @Test
    void logout_fail_when_other_user_token() {
        String refreshToken = jwtProvider.createRefreshToken(1L);
        String hash = TokenHashUtil.sha256(refreshToken);

        RefreshToken saved = new RefreshToken();
        saved.setUserNo(1L);
        saved.setTokenHash(hash);
        saved.setRevoked(false);
        saved.setExpiryDate(LocalDateTime.now().plusDays(7));

        when(refreshTokenMapper.findByTokenHash(hash)).thenReturn(saved);

        assertThrows(RuntimeException.class, () -> {
            authServiceImpl.logout(refreshToken, 2L);
        });

        verify(refreshTokenMapper, never()).revokeByTokenHash(hash);
    }
}
