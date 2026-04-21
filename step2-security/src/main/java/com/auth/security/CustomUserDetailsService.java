package com.auth.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.domain.User;
import com.auth.mapper.UserMapper;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService{
    
    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String email) {

        User user = userMapper.findByEmail(email);

        if (user == null) {
            throw new UsernameNotFoundException("아이디 또는 비밀번호 오류");
        }
        
        return new CustomUserDetails(user);
    }

}
