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
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final AuthService authService;
    private final UserMapper userMapper;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        log.info("[LoginSuccess] 로그인 성공 핸들러 진입");
        log.info("[LoginSuccess] Principal 타입: {}", authentication.getPrincipal().getClass().getName());

        try {
            if (authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
                Long userNo = userDetails.getUser().getNo();
                log.info("[LoginSuccess] 인증된 사용자 no={}, email={}", userNo, userDetails.getUser().getEmail());

                log.debug("[LoginSuccess] resetFailCount 호출 시작");
                userMapper.resetFailCount(userNo);
                log.debug("[LoginSuccess] resetFailCount 완료");

                log.debug("[LoginSuccess] saveHistory 호출 시작");
                authService.saveHistory(userNo, request, true);
                log.debug("[LoginSuccess] saveHistory 완료");

            } else {
                log.warn("[LoginSuccess] Principal이 CustomUserDetails 타입이 아님: {}", authentication.getPrincipal());
            }
        } catch (Exception e) {
            log.error("[LoginSuccess] 예외 발생 - 클래스: {}", e.getClass().getName());
            log.error("[LoginSuccess] 예외 메시지: {}", e.getMessage());
            log.error("[LoginSuccess] 스택트레이스:", e);
        }

        log.info("[LoginSuccess] /mypage 로 redirect 시도");
        response.sendRedirect("/mypage");
        log.info("[LoginSuccess] redirect 완료");
    }
}
