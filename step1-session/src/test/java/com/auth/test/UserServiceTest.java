package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.auth.domain.User;
import com.auth.exception.LoginFailException;
import com.auth.service.UserService;

// 클래스 정의
// 개념/사용 이유
// @SpringBootTest, @Autowired, @Test
@SpringBootTest
class UserServiceTest {
    
    @Autowired
    private UserService userService;

    @BeforeEach
    void setup() {
        try{ 
            User user = new User();
            user.setEmail("test@test.com");
            user.setPassword("1234");
            user.setName("테스터");
    
            userService.signup(user);
        } catch (RuntimeException e) {
            
        }
    }

    @Test
    void login_success() {
        User user = userService.login("test@test.com", "1234");

        assertNotNull(user);
    }

    @Test
    void login_fail_wrong_password() {
        assertThrows(LoginFailException.class, () -> {
            userService.login("test@test.com", "wrong");
        });
    }

    @Test
    void login_fail_user_not_fount() {
        assertThrows(LoginFailException.class, () -> {
            userService.login("none@test.com", "1234");
        });
    }

    @Test
    void password_encode_match() {
        String raw = "1234";
        String encoded = new BCryptPasswordEncoder().encode(raw);

        assertTrue(new BCryptPasswordEncoder().matches(raw, encoded));
    }

}
