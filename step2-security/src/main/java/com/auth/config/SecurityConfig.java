package com.auth.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Value;
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
 * 
 * @Configuration
 * @EnableWebSecurity
 * @RequiredArgsConstructor
 *                          개념/사용 이유
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

        private final LoginSuccessHandler loginSuccessHandler;
        private final LoginFailureHandler loginFailureHandler;
        private final DataSource dataSource;

        @Value("${security.rememberme.key}")
        private  String rememberMeKey;

        @Bean
        public PersistentTokenRepository persistentTokenRepository() {
                JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
                repo.setDataSource(dataSource);
                return repo;
        }

        @Bean
        public SecurityFilterChain filterChain(
                HttpSecurity http,
                PersistentTokenRepository tokenRepository
        ) throws Exception {
                http
                        .csrf(csrf -> csrf
                                        .ignoringRequestMatchers("/api/**", "/email/**") // API와 이메일 인증은 CSRF 제외
                        )

                        .authorizeHttpRequests(auth -> auth
                                .requestMatchers(
                                        "/login", 
                                        "/signup", 
                                        "/password-reset", 
                                        "/api/auth/**",
                                        "/email/**", 
                                        // **: 비밀번호 변경 API(로그인)까지 열릴 수 있으므로 비로그인 허용까지만
                                        "/api/password/reset"
                                ).permitAll()
                                // .anyRequest().permitAll()
                                // Step2 핵심 변경
                                .anyRequest().authenticated())
                        .formLogin(form -> form
                                .loginPage("/login") // 커스텀 로그인 페이지
                                .loginProcessingUrl("/login") // 로그인 요청 처리 URL
                                .usernameParameter("email")
                                .passwordParameter("password")
                                .successHandler(loginSuccessHandler)
                                .failureHandler(loginFailureHandler) // 실패 시 이동
                        )
                        .rememberMe(remember -> remember
                                // 하드 코어 대신 properties로 이동
                                .key(rememberMeKey)
                                .tokenValiditySeconds(60 * 60 * 24 * 7) // 7일
                                .tokenRepository(tokenRepository))
                        .logout(logout -> logout
                                .logoutUrl("/logout")
                                .logoutSuccessUrl("/login")
                        );

                return http.build();
        }
}
