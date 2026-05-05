package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
        email = "test" + java.util.UUID.randomUUID() + "@test.com";

        User user = new User();
        user.setEmail(email);
        user.setPassword("Abcd1234!");
        user.setName("테스터");
    
        userService.signup(user);
    }

    @Test
    void login_success() {
        User user = userService.login(email, "Abcd1234!");

        assertEquals(email, user.getEmail());
        assertNotNull(user.getNo());
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
        String newEmail = "new" + java.util.UUID.randomUUID() + "@test.com";

        User user = new User();
        user.setEmail(newEmail);
        user.setPassword("Abcd1234!");
        user.setName("신규");

        userService.signup(user);

        User saved = userService.login(newEmail, "Abcd1234!");

        assertEquals(newEmail, saved.getEmail());
        assertNotNull(saved.getNo());
    }

    @Test
    void signup_should_encrypt_password() {
        User saved = userMapper.findByEmail(email);

        assertNotEquals("Abcd1234!", saved.getPassword());
        assertTrue(passwordEncoder.matches("Abcd1234!", saved.getPassword()));
    }

    @Test
    void change_password_success() {
        User user = userService.login(email, "Abcd1234!");

        userService.changePassword(
            user.getNo(),
            "Abcd1234!",
            "Newpass123!"
        );

        User updated = userService.login(email, "Newpass123!");
        
        assertEquals(email, updated.getEmail());
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
    void change_password_fail_wrong_current_password() {
        User user = userService.login(email, "Abcd1234!");

        assertThrows(RuntimeException.class, () -> {
            userService.changePassword(
                user.getNo(), 
                "wrong", 
                "Newpass123!"
            );
        });
    }

    @Test
    void locked_user_cannot_login() {
        User user = userService.login(email, "Abcd1234!");

        userMapper.increaseFailCount(user.getNo());
        userMapper.increaseFailCount(user.getNo());
        userMapper.increaseFailCount(user.getNo());

        assertThrows(RuntimeException.class, () -> {
            userService.login(email, "Abcd1234!");
        });
    }

    @Test
    void old_password_should_not_work_after_change() {
        User user = userService.login(email, "Abcd1234!");

        userService.changePassword(
            user.getNo(), 
            "Abcd1234!", 
            "Newpass123!"
        );

        assertThrows(RuntimeException.class, () -> {
            userService.login(email, "Abcd1234!");
        });
    }

}
