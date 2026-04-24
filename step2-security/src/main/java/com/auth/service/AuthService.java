package com.auth.service;

import com.auth.domain.User;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {

    void saveHistory(Long userNo, HttpServletRequest request, boolean success);

}
