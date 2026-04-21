package com.auth.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import com.auth.handler.LoginFailureHandler;
import com.auth.handler.LoginSuccessHandler;

import lombok.RequiredArgsConstructor;

/**
 * 클래스 정의/구현 이유
 * @Configuration
 * @EnableWebSecurity
 * @RequiredArgsConstructor 
 * 개념/사용 이유
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final DataSource dataSource;


    @Bean
    public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {

        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);

        return repo;
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/signup", "/api/auth/**", "/email/**").permitAll()
                // .anyRequest().permitAll()
                // Step2 핵심 변경
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")    // 커스텀 로그인 페이지
                .loginProcessingUrl("/login")   // 로그인 요청 처리 URL
                .successHandler(loginSuccessHandler)
                .failureHandler(loginFailureHandler) // 실패 시 이동
            )
            .rememberMe(remember -> remember
                .key("remember-me-key")
                .tokenValiditySeconds(60 * 60 * 24 * 7) // 7일
                .tokenRepository(persistentTokenRepository(dataSource))
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
            );

        return http.build();
    }
}
