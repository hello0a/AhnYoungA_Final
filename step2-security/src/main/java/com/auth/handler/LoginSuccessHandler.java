package com.auth.handler;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.auth.mapper.UserMapper;
import com.auth.security.CustomUserDetails;
import com.auth.service.AuthService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler{
    
    private final AuthService authService;
    private final UserMapper userMapper;

    @Override
    public void onAuthenticationSuccess (
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) throws IOException, ServletException {

        if (authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
            userMapper.resetFailCount(userDetails.getUser().getNo());
            authService.saveHistory(userDetails.getUser().getNo(), request, true);
        }
        
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
