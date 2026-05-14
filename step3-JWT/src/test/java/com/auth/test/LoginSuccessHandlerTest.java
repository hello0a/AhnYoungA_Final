package com.auth.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.transaction.annotation.Transactional;

import com.auth.domain.User;
import com.auth.handler.LoginSuccessHandler;
import com.auth.mapper.UserMapper;
import com.auth.security.CustomUserDetails;
import com.auth.service.UserService;

@SpringBootTest
@Transactional
class LoginSuccessHandlerTest {
    
    @Autowired
    private LoginSuccessHandler loginSuccessHandler;

    @Autowired
    private UserService userService;

    @Autowired
    private UserMapper userMapper;

    private String email;

    @BeforeEach
    void signup() {
        email = "test" + java.util.UUID.randomUUID() + "@test.com";

        User user = new User();
        user.setEmail(email);
        user.setPassword("Abcd1234!");
        user.setName("테스터");

        userService.signup(user);
    }

    // 로그인 성공 시 failCount가 0으로 초기화되는지 확인
    @Test
    void success_resets_fail_count() throws Exception {
        // given
        User user = userMapper.findByEmail(email);

        userMapper.increaseFailCount(user.getNo());
        userMapper.increaseFailCount(user.getNo());

        User failedUser = userMapper.findByEmail(email);

        CustomUserDetails userDetails = new CustomUserDetails(failedUser);

        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(
                userDetails, 
                null, 
                userDetails.getAuthorities()
            );

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        loginSuccessHandler.onAuthenticationSuccess(request, response, authenticationToken);

        // then
        User updated = userMapper.findByEmail(email);

        assertEquals(0, updated.getLoginFailCount());
    }

    // 성공 후 mypage로 redirect 되는지 확인
    @Test
    void success_redirects_mypage() throws Exception {
        // given
        User user = userMapper.findByEmail(email);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(
                userDetails, 
                null, 
                userDetails.getAuthorities()
            );
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        loginSuccessHandler.onAuthenticationSuccess(request, response, authenticationToken);

        // then
        assertEquals("/mypage", response.getRedirectedUrl());
    }
}
