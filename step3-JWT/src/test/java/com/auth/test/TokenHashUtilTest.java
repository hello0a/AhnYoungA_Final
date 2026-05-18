package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.auth.util.TokenHashUtil;

class TokenHashUtilTest {

    @Test
    void sha256_success() {
        String token = "refresh-token-sample";

        String hash1 = TokenHashUtil.sha256(token);
        String hash2 = TokenHashUtil.sha256(token);

        assertEquals(hash1, hash2);
        assertEquals(64, hash1.length());
    }

    @Test
    void sha256_fail_when_null() {
        assertThrows(RuntimeException.class, () -> {
            TokenHashUtil.sha256(null);
        });
    }

    @Test
    void sha256_fail_when_blank() {
        assertThrows(RuntimeException.class, () -> {
            TokenHashUtil.sha256(" ");
        });
    }

}
