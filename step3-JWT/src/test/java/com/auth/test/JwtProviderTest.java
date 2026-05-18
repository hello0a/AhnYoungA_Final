package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.auth.security.JwtProvider;

class JwtProviderTest {

    private JwtProvider jwtProvider;

    @BeforeEach
    void setup() {
        jwtProvider = new JwtProvider(
            "step3-jwt-secret-key-must-be-at-least-32bytes-2026", 
            1800000, 
            60480000
        );
    }

    @Test
    void create_access_token_success() {
        String token = jwtProvider.createAccessToken(1L);

        assertTrue(jwtProvider.validateToken(token));
        assertEquals(1L, jwtProvider.getUserNo(token));
        assertEquals("ACCESS", jwtProvider.getTokenType(token));
    }

    @Test
    void create_refresh_token_success() {
        String token = jwtProvider.createRefreshToken(1L);

        assertTrue(jwtProvider.validateToken(token));
        assertEquals(1L, jwtProvider.getUserNo(token));
        assertEquals("REFRESH", jwtProvider.getTokenType(token));
    }

    @Test
    void invalid_token_should_fail() {
        boolean result = jwtProvider.validateToken("wrong.token.value");

        assertFalse(result);
    }
}
