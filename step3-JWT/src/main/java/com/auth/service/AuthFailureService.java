package com.auth.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.auth.domain.User;
import com.auth.mapper.LoginHistoryMapper;
import com.auth.mapper.UserMapper;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthFailureService {
    
    private final UserMapper userMapper;
    private final LoginHistoryMapper loginHistoryMapper;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int recordFailure(Long userNo, String email, HttpServletRequest request) {
        if (userNo == null) {
            loginHistoryMapper.insert(
                null, 
                request.getRemoteAddr(), 
                request.getHeader("User-Agent"), 
                false
            );
            return 0;
        }
        userMapper.increaseFailCount(userNo);
    
        User updatedUser = userMapper.findByEmail(email);

        if (updatedUser.getLoginFailCount() >= 3) {
            userMapper.lockedUser(userNo);
        }

        loginHistoryMapper.insert(
            userNo, 
            request.getRemoteAddr(), 
            request.getHeader("User-Agent"), 
            false
        );

        return updatedUser.getLoginFailCount();
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordLockedFailure(Long userNo, HttpServletRequest request) {
        loginHistoryMapper.insert(
            userNo,
            request.getRemoteAddr(),
            request.getHeader("User-Agent"),
            false
        );
    }

    
}
