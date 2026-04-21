package com.auth.service;

import com.auth.domain.User;

public interface UserService {
    // 회원가입
    int signup(User user);
    // 로그인
    User login(String email, String password);
    // 비밀번호 변경
    int changePassword(String email, String password, String newPassword);
}
