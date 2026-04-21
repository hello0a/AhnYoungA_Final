package com.auth.interceptor;

import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

// 클래스 정의/구현 이유
// HandlerInterceptor 개념/사용 이유
public class LoginInterceptor implements HandlerInterceptor{

    // 개념/사용 이유
    // HttpServletRequest, HttpServletResponse, Object
    @Override
    public boolean preHandle(
        HttpServletRequest request,
        HttpServletResponse response,
        Object handler
    ) throws Exception {
        HttpSession session = request.getSession(false);

        if (session == null || session.getAttribute("LOGIN_USER") == null) {
            response.sendRedirect("/login");
            return false;
        }
        return true;
    }
}
