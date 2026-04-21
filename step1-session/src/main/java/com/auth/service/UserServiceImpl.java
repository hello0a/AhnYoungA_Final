package com.auth.service;

import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.domain.User;
import com.auth.mapper.UserMapper;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{
    
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    /**
     * @Transactional 개념/사용 이유
     * : 트랜잭션 관리 (실패 시 롤백)
     */
    // 회원가입
    @Override
    @Transactional
    public int signup(User user) {
        
        // 회원 존재 여부
        User existing = userMapper.findByEmail(user.getEmail());
        if (existing != null) {
            throw new RuntimeException("이미 존재하는 이메일");
        }
        // UUID 부여
        user.setId(UUID.randomUUID().toString());
        // 비밀번호 암호화
        String encoded = passwordEncoder.encode(user.getPassword());
        user.setPassword(encoded);
        // 회원 정보 저장
        int result = userMapper.insertUser(user);

        return result;
    }
    // 로그인
    @Override
    public User login(String email, String password) {

        User user = userMapper.findByEmail(email);

        if (user == null) {
            throw new RuntimeException("아이디 또는 비밀번호 오류");
        }
        // matches 개념/사용 이유
        // : 평문 vs 암호화 비교
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("아이디 또는 비밀번호 오류");
        }

        return user;
    }
    // 비밀번호 변경
    @Override
    public int changePassword(String email, String password, String newPassword) {
        
        User user = userMapper.findByEmail(email);

        if (user == null) {
            throw new RuntimeException("사용자 없음");
        }

        // 기존 비밀번호 확인
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("아이디 또는 비밀번호 오류");
        }
        // 새로운 비밀번호 암호화
        String encoded = passwordEncoder.encode(newPassword);
        // 비밀번호 업데이트
        int result = userMapper.updatePassword(user.getEmail(), encoded);

        return result;
    }

}
