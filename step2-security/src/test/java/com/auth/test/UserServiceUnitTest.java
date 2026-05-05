package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.auth.domain.User;
import com.auth.exception.LoginFailException;
import com.auth.mapper.PasswordHistoryMapper;
import com.auth.mapper.UserMapper;
import com.auth.service.EmailService;
import com.auth.service.PasswordPolicyService;
import com.auth.service.UserServiceImpl;

@ExtendWith(MockitoExtension.class)
class UserServiceUnitTest {

    @Mock
    private UserMapper userMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private PasswordHistoryMapper passwordHistoryMapper;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private UserServiceImpl userService;

    private User user;

    @BeforeEach
    void setup() {
        user = new User();
        user.setNo(1L);
        user.setEmail("test@test.com");
        user.setPassword("encoded-password");
        user.setName("테스터");
        user.setLocked(false);
    }

    @Test
    void signup_success() {
        // given
        User signupUser = new User();
        signupUser.setEmail("new@test.com");
        signupUser.setPassword("Abcd1234!");
        signupUser.setName("신규");

        when(userMapper.findByEmail("new@test.com")).thenReturn(null);
        when(passwordEncoder.encode("Abcd1234!")).thenReturn("encoded-password");

        doAnswer(invocation -> {
            User arg = invocation.getArgument(0);
            arg.setNo(10L);
            return 1;
        }).when(userMapper).insertUser(any(User.class));

        // when
        int result = userService.signup(signupUser);

        // then
        assertEquals(1, result);
        assertNotNull(signupUser.getId());
        assertEquals("encoded-password", signupUser.getPassword());

        verify(passwordPolicyService).validate("Abcd1234!");
        verify(userMapper).insertUser(signupUser);
        verify(passwordHistoryMapper).insert(10L, "encoded-password");
    }

    @Test
    void signup_fail_duplicate_email() {
        // given
        User signupUser = new User();
        signupUser.setEmail("test@test.com");
        signupUser.setPassword("Abcd1234!");
        signupUser.setName("테스터");

        when(userMapper.findByEmail("test@test.com")).thenReturn(user);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.signup(signupUser);
        });

        verify(userMapper, never()).insertUser(any(User.class));
        verify(passwordHistoryMapper, never()).insert(any(), any());
    }

    @Test
    void signup_fail_invalid_email() {
        // given
        User signupUser = new User();
        signupUser.setEmail("wrong-email");
        signupUser.setPassword("Abcd1234!");
        signupUser.setName("테스터");

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.signup(signupUser);
        });

        verify(passwordPolicyService, never()).validate(any());
        verify(userMapper, never()).insertUser(any(User.class));
    }

    @Test
    void signup_fail_password_policy() {
        // given
        User signupUser = new User();
        signupUser.setEmail("new@test.com");
        signupUser.setPassword("short");
        signupUser.setName("신규");

        doThrow(new RuntimeException("비밀번호는 8자 이상"))
            .when(passwordPolicyService).validate("short");
        
        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.signup(signupUser);
        });

        verify(userMapper, never()).insertUser(any(User.class));
    }

    @Test
    void login_success() {
        // given
        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(passwordEncoder.matches("Abcd1234!", "encoded-password")).thenReturn(true);

        // when
        User result = userService.login("test@test.com", "Abcd1234!");

        // then
        assertEquals("test@test.com", result.getEmail());
    }

    @Test
    void login_fail_user_not_found() {
        // given
        when(userMapper.findByEmail("none@test.com")).thenReturn(null);

        // when & then
        assertThrows(LoginFailException.class, () -> {
            userService.login("none@test.com", "Abcd1234!");
        });
    }

    @Test
    void login_fail_wrong_password() {
        // given
        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(passwordEncoder.matches("wrong", "encoded-password")).thenReturn(false);

        // when & then
        assertThrows(LoginFailException.class, () -> {
            userService.login("test@test.com", "wrong");
        });
    }

    @Test
    void login_fail_locked_user() {
        // given
        user.setLocked(true);
        when(userMapper.findByEmail("test@test.com")).thenReturn(user);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.login("test@test.com", "Abcd1234!");
        });

        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void change_password_success() {
        // given
        when(passwordHistoryMapper.findByUser(1L)).thenReturn(List.of("old-encoded-password"));
        when(passwordEncoder.matches("Newpass123!", "old-encoded-password")).thenReturn(false);

        when(userMapper.findByNo(1L)).thenReturn(user);
        when(passwordEncoder.matches("Abcd1234!", "encoded-password")).thenReturn(true);

        when(passwordEncoder.encode("Newpass123!")).thenReturn("new-encoded-password");
        when(userMapper.updatePassword(1L, "new-encoded-password")).thenReturn(1);

        // when
        int result = userService.changePassword(1L, "Abcd1234!", "Newpass123!");

        // then
        assertEquals(1, result);

        verify(passwordPolicyService).validate("Newpass123!");
        verify(userMapper).updatePassword(1L, "new-encoded-password");
        verify(passwordHistoryMapper).insert(1L, "new-encoded-password");
    }

    @Test
    void change_password_fail_reuse() {
        // given
        when(passwordHistoryMapper.findByUser(1L)).thenReturn(List.of("old-encoded-password"));
        when(passwordEncoder.matches("Abcd1234!", "old-encoded-password")).thenReturn(true);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.changePassword(1L, "Abcd1234!", "Abcd1234!");
        });

        verify(userMapper, never()).findByNo(any());
        verify(userMapper, never()).updatePassword(any(), any());
    }

    @Test
    void change_password_fail_user_not_found() {
        // given
        when(passwordHistoryMapper.findByUser(1L)).thenReturn(List.of());
        when(userMapper.findByNo(1L)).thenReturn(null);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.changePassword(1L, "Abcd1234!", "Newpass123!");
        });

        verify(userMapper, never()).updatePassword(any(), any());
    }

    @Test
    void change_password_fail_wrong_current_password() {
        // given
        when(passwordHistoryMapper.findByUser(1L)).thenReturn(List.of());
        when(userMapper.findByNo(1L)).thenReturn(user);
        when(passwordEncoder.matches("wrong", "encoded-password")).thenReturn(false);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.changePassword(1L, "wrong","Newpass123!");
        });

        verify(userMapper, never()).updatePassword(any(), any());
    }

    @Test
    void reset_password_success() {
        // given
        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(emailService.verifyCode("test@test.com", "123456")).thenReturn(true);

        when(passwordHistoryMapper.findByUser(1L)).thenReturn(List.of("old-encoded-password"));
        when(passwordEncoder.matches("Newpass123!", "old-encoded-password")).thenReturn(false);

        when(passwordEncoder.encode("Newpass123!")).thenReturn("reset-encoded-password");
        when(userMapper.updatePassword(1L, "reset-encoded-password")).thenReturn(1);

        // when
        int result = userService.resetPasswordByEmail("test@test.com", "123456", "Newpass123!");

        // then
        assertEquals(1, result);

        verify(emailService).verifyCode("test@test.com", "123456");
        verify(passwordPolicyService).validate("Newpass123!");
        verify(emailService).deleteVerification("test@test.com");
        verify(userMapper).updatePassword(1L, "reset-encoded-password");
        verify(passwordHistoryMapper).insert(1L, "reset-encoded-password");
    }

    @Test
    void reset_password_fail_user_not_found() {
        // given
        when(userMapper.findByEmail("none@test.com")).thenReturn(null);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.resetPasswordByEmail("none@test.com", "123456", "Newpass123!");
        });

        verify(emailService, never()).verifyCode(any(), any());
    }

    @Test
    void reset_password_fail_invalid_code() {
        // given
        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(emailService.verifyCode("test@test.com", "000000")).thenReturn(false);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.resetPasswordByEmail("test@test.com", "000000", "Newpass123!");
        });

        verify(userMapper, never()).updatePassword(any(), any());
        verify(emailService, never()).deleteVerification(any());
    }

    @Test
    void reset_password_fail_reuse_password() {
        // given
        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(emailService.verifyCode("test@test.com", "123456")).thenReturn(true);

        when(passwordHistoryMapper.findByUser(1L)).thenReturn(List.of("old-encoded-password"));
        when(passwordEncoder.matches("Newpass123!", "old-encoded-password")).thenReturn(true);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            userService.resetPasswordByEmail("test@test.com", "123456", "Newpass123!");
        });

        verify(userMapper, never()).updatePassword(any(), any());
    }
}

