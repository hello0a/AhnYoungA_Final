package com.auth.service;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {

    void saveHistory(Long userNo, HttpServletRequest request, boolean success);

}
