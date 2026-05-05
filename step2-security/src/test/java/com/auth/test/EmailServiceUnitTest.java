package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.auth.domain.EmailVerification;
import com.auth.domain.User;
import com.auth.mapper.EmailVerificationMapper;
import com.auth.mapper.UserMapper;
import com.auth.service.EmailService;

@ExtendWith(MockitoExtension.class)
class EmailServiceUnitTest {

    @Mock
    private JavaMailSender javaMailSender;

    @Mock
    private UserMapper userMapper;

    @Mock
    private EmailVerificationMapper mapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private EmailService emailService;

    private User user;
    private EmailVerification verification;

    @BeforeEach
    void setup() {
        user = new User();
        user.setNo(1L);
        user.setEmail("test@test.com");
        user.setName("테스터");

        verification = new EmailVerification();
        verification.setNo(1L);
        verification.setUserNo(1L);
        verification.setEmail("test@test.com");
        verification.setCode("encoded-code");
        verification.setFailCount(0);
        verification.setExpiry(LocalDateTime.now().plusMinutes(5));
        verification.setCreatedAt(LocalDateTime.now().minusMinutes(1));
    }

    @Test
    void send_code_success() {
        // given
        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(mapper.findByEmail("test@test.com")).thenReturn(null);
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-code");

        // when
        emailService.sendCode("test@test.com");

        // then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);

        verify(javaMailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();

        assertTrue(message.getSubject().contains("인증코드"));
        assertTrue(message.getText().contains("인증코드"));
        assertTrue(message.getText().contains("5분"));

        verify(mapper).deleteByEmail("test@test.com");
        verify(mapper).insert(
                eq(1L),
                eq("test@test.com"),
                eq("encoded-code"),
                any(LocalDateTime.class)
        );
    }

    @Test
    void send_code_unknown_user_returns_silently() {
        // given
        when(userMapper.findByEmail("none@test.com")).thenReturn(null);

        // when
        emailService.sendCode("none@test.com");

        // then
        verify(javaMailSender, never()).send(any(SimpleMailMessage.class));
        verify(mapper, never()).insert(any(), any(), any(), any());
        verify(mapper, never()).deleteByEmail(anyString());
    }

    @Test
    void send_code_blocked_within_30_seconds() {
        // given
        verification.setCreatedAt(LocalDateTime.now().minusSeconds(10));

        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(mapper.findByEmail("test@test.com")).thenReturn(verification);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            emailService.sendCode("test@test.com");
        });

        verify(javaMailSender, never()).send(any(SimpleMailMessage.class));
        verify(mapper, never()).insert(any(), any(), any(), any());
    }

    @Test
    void send_code_fail_when_mail_send_error() {
        // given
        when(userMapper.findByEmail("test@test.com")).thenReturn(user);
        when(mapper.findByEmail("test@test.com")).thenReturn(null);
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-code");

        doThrow(new MailSendException("SMTP error"))
                .when(javaMailSender)
                .send(any(SimpleMailMessage.class));

        // when & then
        assertThrows(RuntimeException.class, () -> {
            emailService.sendCode("test@test.com");
        });

        verify(mapper, never()).deleteByEmail(anyString());
        verify(mapper, never()).insert(any(), any(), any(), any());
    }

    @Test
    void verify_code_success() {
        // given
        when(mapper.findByEmail("test@test.com")).thenReturn(verification);
        when(passwordEncoder.matches("123456", "encoded-code")).thenReturn(true);

        // when
        boolean result = emailService.verifyCode("test@test.com", "123456");

        // then
        assertTrue(result);
        verify(mapper, never()).deleteByEmail("test@test.com");
        verify(mapper, never()).increaseFailCount("test@test.com");
    }

    @Test
    void verify_code_fail_when_not_found() {
        // given
        when(mapper.findByEmail("test@test.com")).thenReturn(null);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            emailService.verifyCode("test@test.com", "123456");
        });

        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(mapper, never()).increaseFailCount(anyString());
    }

    @Test
    void verify_code_fail_when_expired() {
        // given
        verification.setExpiry(LocalDateTime.now().minusSeconds(1));
        when(mapper.findByEmail("test@test.com")).thenReturn(verification);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            emailService.verifyCode("test@test.com", "123456");
        });

        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(mapper, never()).increaseFailCount(anyString());
    }

    @Test
    void verify_code_fail_when_fail_count_over_limit() {
        // given
        verification.setFailCount(5);
        when(mapper.findByEmail("test@test.com")).thenReturn(verification);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            emailService.verifyCode("test@test.com", "123456");
        });

        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(mapper, never()).increaseFailCount(anyString());
    }

    @Test
    void verify_code_fail_wrong_code_increases_fail_count() {
        // given
        when(mapper.findByEmail("test@test.com")).thenReturn(verification);
        when(passwordEncoder.matches("000000", "encoded-code")).thenReturn(false);

        // when & then
        assertThrows(RuntimeException.class, () -> {
            emailService.verifyCode("test@test.com", "000000");
        });

        verify(mapper).increaseFailCount("test@test.com");
    }

    @Test
    void delete_verification_success() {
        // when
        emailService.deleteVerification("test@test.com");

        // then
        verify(mapper).deleteByEmail("test@test.com");
    }
}