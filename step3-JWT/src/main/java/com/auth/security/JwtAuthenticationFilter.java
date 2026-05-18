package com.auth.security;

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.domain.User;
import com.auth.mapper.UserMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtProvider jwtProvider;
    private final UserMapper userMapper;

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        String uri = request.getRequestURI();
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            log.debug("***JWT Filter: Authorization Header 없음, uri={}", uri);
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);

        if (!jwtProvider.validateToken(token)) {
            log.warn("***JWT Filter: Access Token 검증 실패, uri={}", uri);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String type = jwtProvider.getTokenType(token);
        if (!"ACCESS".equals(type)) {
            log.warn("***JWT Filter: 토큰 타입 불일치, uri={}, type={}", uri, type);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        Long userNo = jwtProvider.getUserNo(token);
        User user = userMapper.findByNo(userNo);

        if (user == null || user.isLocked()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        SecurityContextHolder.clearContext();
        
        UsernamePasswordAuthenticationToken authentication = 
            new UsernamePasswordAuthenticationToken(
                userNo,
                 null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
            );
        
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);

        log.debug("***JWT Filter: 인증 성공, userNo={}, uri={}",
            userNo,
            uri
        );
    }
}
