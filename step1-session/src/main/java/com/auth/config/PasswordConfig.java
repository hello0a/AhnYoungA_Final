package com.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {
    @Bean
    public PasswordEncoder PasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
/**
 * @Configuration 개념/사용 이유
 * @Bean 개념/사용 이유
 * PasswordEncoder 개념/사용 이유
 * BCryptPasswordEncoder 개념/사용 이유
 */
