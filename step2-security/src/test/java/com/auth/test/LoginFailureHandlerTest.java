package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.transaction.annotation.Transactional;

import com.auth.domain.User;
import com.auth.handler.LoginFailureHandler;
import com.auth.mapper.UserMapper;
import com.auth.service.UserService;

@SpringBootTest
@Transactional
class LoginFailureHandlerTest {
    
    @Autowired
    private LoginFailureHandler loginFailureHandler;

    @Autowired
    private UserService userService;

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

    // 존재하지 않는 이메일
    // : 로그인 실패 시 이메일 존재 여부 노출없이 일반 오류 보내는지 확인
    @Test
    void unknown_user_redirect_error() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("email", "none@test.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        loginFailureHandler.onAuthenticationFailure(
            request, 
            response, 
            new BadCredentialsException("Bad credentials")
        );

        // then
        assertEquals("/login?error", response.getRedirectedUrl());
    }

    // 존재하는 이메일 + 비밀번호 오류
    // : 실패 횟수가 실제 DB에서 증가하고, 화면에 보여줄 fail 파라미터 전달되는지 확인
    @Test
    void fail_increases_count() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("email", email);

        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        loginFailureHandler.onAuthenticationFailure(
            request, 
            response, 
            new BadCredentialsException("Bad credentials")
        );

        // then
        User updated = userMapper.findByEmail(email);

        assertEquals(1, updated.getLoginFailCount());
        assertEquals("/login?fail=1", response.getRedirectedUrl());
    }

    // 실패 횟수 3회 도달
    // : 로그인 화면에서 "계정 잠금" 메시지 띄우는지 확인
    @Test
    void third_fail_redirect_locked() throws Exception {
        // given
        User user = userMapper.findByEmail(email);

        // 이미 2회 실패한 상태로 만든다.
        userMapper.increaseFailCount(user.getNo());
        userMapper.increaseFailCount(user.getNo());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("email", email);

        MockHttpServletResponse response = new MockHttpServletResponse();

        // when: 3번째 실패
        loginFailureHandler.onAuthenticationFailure(
            request, 
            response, 
            new BadCredentialsException("Bad credentials")
        );

        // then
        User updated = userMapper.findByEmail(email);

        assertTrue(updated.getLoginFailCount() >= 3);
        assertEquals("/login?locked", response.getRedirectedUrl());
    }

    // 이미 LockedException 발생
    // : 실패 횟수를 또 증가시키지 않는지 확인
    // 👉 잠긴 계정에 로그인 시도 해도 fail_count가 무한히 증가하지 않아야 함
    @Test
    void locked_user_no_count_increase() throws Exception {
        // given
        User user = userMapper.findByEmail(email);
        int beforeFailCount = user.getLoginFailCount();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("email", email);

        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        loginFailureHandler.onAuthenticationFailure(
            request, 
            response, 
            new LockedException("Account is locked")
        );

        // then
        User updated = userMapper.findByEmail(email);

        assertEquals(beforeFailCount, updated.getLoginFailCount());
        assertEquals("/login?locked", response.getRedirectedUrl());
    }
}
