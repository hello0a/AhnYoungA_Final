package com.auth.handler;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.auth.domain.User;
import com.auth.mapper.UserMapper;
import com.auth.service.AuthService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler{
    
    private final UserMapper userMapper;
    private final AuthService authService;

    @Override
    public void onAuthenticationFailure(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException exception
    ) throws IOException, ServletException {

        String email = request.getParameter("name");

        User user = userMapper.findByEmail(email);

        if (user != null) {
            userMapper.increaseFailCount(user.getNo());
            authService.saveHistory(user.getNo(), request, false);
        } else {
            authService.saveHistory(null, request, false);
        }

        super.onAuthenticationFailure(request, response, exception);
    }
}
