package com.auth.exception;

// 클래스 정의
public class LoginFailException extends RuntimeException{
    public LoginFailException(String message) {
        super(message);
    }
}
