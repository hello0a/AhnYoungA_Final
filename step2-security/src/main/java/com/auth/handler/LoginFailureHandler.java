package com.auth.handler;

import java.io.IOException;

import org.springframework.security.authentication.LockedException;
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
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final UserMapper userMapper;
    private final AuthService authService;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {

        log.info("[LoginFailure] 로그인 실패: {}", exception.getClass().getSimpleName());

        String email = request.getParameter("email");
        User user = userMapper.findByEmail(email);

        if (user == null) {
            authService.saveHistory(null, request, false);
            response.sendRedirect("/login?error");
            return;
        }
        // 계정이 잠긴 경우 실패 횟수 증가 X
        if (exception instanceof LockedException) {
            log.warn("[LoginFailure] 계정 잠금 상태 → redirect:/login?locked");
            response.sendRedirect("/login?locked");
            return;
        }
        // 실패 횟수 증가
        userMapper.increaseFailCount(user.getNo());
        authService.saveHistory(user.getNo(), request, false);
        // DB에서 다시 조회 (정확한 값)
        User updatedUser = userMapper.findByEmail(email);
        int failCount = updatedUser.getLoginFailCount();

        log.warn("[LoginFailure] 실패 횟수: {}", failCount);
        // 3회 이상 잠금
        if (failCount >= 3) {
            response.sendRedirect("/login?locked");
            return;
        }
        // 실패 횟수 전달
        response.sendRedirect("/login?fail=" + failCount);
        return;
    }
}
