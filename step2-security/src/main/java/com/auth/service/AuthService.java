package com.auth.service;

import com.auth.domain.User;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
    
    User login(String email, String password, HttpServletRequest request);
    void saveHistory(Long userNo, HttpServletRequest request, boolean success);

}
