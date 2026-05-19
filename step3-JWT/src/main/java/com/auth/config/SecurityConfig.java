package com.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth.security.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;

// JWT 핵심
// formLogin/remember-me 대신 JWT Filter
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
        private final JwtAuthenticationFilter jwtAuthenticationFilter;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                        .csrf(AbstractHttpConfigurer::disable)

                        // formLogin, remember-me, 세션 인증 내려가고(?)
                        // JWT Filter와 Stateless 구조로 전환
                        .sessionManagement(session -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        )
                        .formLogin(AbstractHttpConfigurer::disable)
                        .httpBasic(AbstractHttpConfigurer::disable)
                        .logout(AbstractHttpConfigurer::disable)

                        .authorizeHttpRequests(auth -> auth
                                // 화면
                                .requestMatchers(
                                        "/",
                                        "/login",
                                        "/signup",
                                        "/password-reset",
                                        "/mypage",
                                        "/email/**",
                                        "/api/auth/login",
                                        "/api/auth/refresh",
                                        "/api/password/reset"
                                ).permitAll()
                                // 데이터 API
                                .requestMatchers(
                                        "/api/auth/logout",
                                        "/api/auth/me",
                                        "/api/auth/login-history",
                                        "/api/password"
                                ).authenticated()
                                .anyRequest().authenticated()
                        )
                        .addFilterBefore(
                                jwtAuthenticationFilter, 
                                UsernamePasswordAuthenticationFilter.class
                        );
                return http.build();
        }
}
