package com.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class TokenHashUtil {
    public static String sha256(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = digest.digest(token.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : encoded) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("토큰 해시 생성 실패", e);
        }
    }
}
