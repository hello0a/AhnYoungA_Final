package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.auth.domain.User;
import com.auth.exception.LoginFailException;
import com.auth.mapper.UserMapper;
import com.auth.service.UserService;

// 클래스 정의
// 개념/사용 이유
// @SpringBootTest, @Autowired, @Test
@SpringBootTest
@Transactional
class UserServiceTest {
    
    @Autowired
    private UserService userService;

    @Autowired
    private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    @Autowired
    private UserMapper userMapper;

    private String email;

    @BeforeEach
    void setup() {
        email = "test" + System.currentTimeMillis() + "@test.com";

        User user = new User();
        user.setEmail(email);
        user.setPassword("Abcd1234!");
        user.setName("테스터");
    
        userService.signup(user);
    }

    @Test
    void login_success() {
        User user = userService.login(email, "Abcd1234!");

        assertNotNull(user);
    }

    @Test
    void login_fail_wrong_password() {
        assertThrows(LoginFailException.class, () -> {
            userService.login(email, "wrong");
        });
    }

    @Test
    void login_fail_user_not_found() {
        assertThrows(LoginFailException.class, () -> {
            userService.login("none@test.com", "1234");
        });
    }

    @Test
    void signup_success() {
        String newEmail = "new" + System.currentTimeMillis() + "@test.com";

        User user = new User();
        user.setEmail(newEmail);
        user.setPassword("Abcd1234!");
        user.setName("신규");

        userService.signup(user);

        // 🔥 진짜 검증
        User saved = userService.login(newEmail, "Abcd1234!");
        assertNotNull(saved);
    }

    @Test
    void change_password_success() {
        User user = userService.login(email, "Abcd1234!");

        userService.changePassword(
            user.getNo(),
            "Abcd1234!",
            "Newpass123!"
        );

        // 🔥 진짜 검증 (핵심)
        User updated = userService.login(email, "Newpass123!");
        assertNotNull(updated);
    }

    @Test
    void change_password_fail_reuse() {
        User user = userService.login(email, "Abcd1234!");

        assertThrows(RuntimeException.class, () -> {
            userService.changePassword(
                user.getNo(),
                "Abcd1234!",
                "Abcd1234!" // 같은 비밀번호
            );
        });
    }

    @Test
    void login_fail_lock_account() {
        User user = userService.login(email, "Abcd1234!");

        for (int i = 0; i < 3; i++) {
            userMapper.increaseFailCount(user.getNo());
        }

        assertThrows(RuntimeException.class, () -> {
            userService.login(email, "Abcd1234!");
        });
    }

}
