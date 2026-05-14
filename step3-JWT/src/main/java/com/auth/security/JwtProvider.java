package com.auth.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtProvider {
    
    private final SecretKey key;
    private final long accessTokenValidityMs;
    private final long refreshTokenValidityMs;

    public JwtProvider(
        @Value("${jwt.secret}") String secret,
        @Value("${jwt.access-token-validity-ms}") long accessTokenValidityMs,
        @Value("${jwt.refresh-token-validity-ms}") long refreshTokenValidityMs
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenValidityMs = accessTokenValidityMs;
        this.refreshTokenValidityMs = refreshTokenValidityMs;
    }

    public String createAccessToken(Long userNo) {
        return createToken(userNo, accessTokenValidityMs, "ACCESS");
    }

    public String createRefreshToken(Long userNo) {
        return createToken(userNo, refreshTokenValidityMs, "REFRESH");
    }

    private String createToken(Long userNo, long validityMs, String type) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + validityMs);

        return Jwts.builder()
                .subject(String.valueOf(userNo))
                .claim("type", type)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Long getUserNo(String token) {
        return Long.valueOf(parseClaims(token).getSubject());
    }

    public String getTokenType(String token) {
        return parseClaims(token).get("type", String.class);
    }

    public long getRefreshTokenValidityMs() {
        return refreshTokenValidityMs;
    }
    
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
