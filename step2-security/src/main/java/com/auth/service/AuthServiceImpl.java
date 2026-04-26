package com.auth.service;

import org.springframework.stereotype.Service;

import com.auth.mapper.LoginHistoryMapper;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

// 클래스 정의/구현 이유
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final LoginHistoryMapper loginHistoryMapper;

    @Override
    public void saveHistory(Long userNo, HttpServletRequest request, boolean success) {

        loginHistoryMapper.insert(
                userNo,
                request.getRemoteAddr(),
                request.getHeader("User-Agent"),
                success);

    }

}
