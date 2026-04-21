package com.auth.service;

import java.util.List;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.domain.User;
import com.auth.exception.LoginFailException;
import com.auth.mapper.PasswordHistoryMapper;
import com.auth.mapper.UserMapper;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{
    
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService policyService;
    private final PasswordHistoryMapper passwordHistoryMapper;

    /**
     * @Transactional 개념/사용 이유
     * : 트랜잭션 관리 (실패 시 롤백)
     */
    // 회원가입
    @Override
    @Transactional
    public int signup(User user) {
        
        // 유효성 검사
        validateEmail(user.getEmail());
        policyService.validate(user.getPassword());

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
        Long userNo = user.getNo();

        passwordHistoryMapper.insert(userNo,encoded);

        return result;
    }
    // 로그인
    @Override
    public User login(String email, String password) {

        User user = userMapper.findByEmail(email);

        if (user == null) {
            // LoginFailException() 개념/변경 이유
            // throw new RuntimeException("아이디 또는 비밀번호 오류");
            throw new LoginFailException("아이디 또는 비밀번호 오류");
        }
        // matches 개념/사용 이유
        // : 평문 vs 암호화 비교
        if (!passwordEncoder.matches(password, user.getPassword())) {
            // throw new RuntimeException("아이디 또는 비밀번호 오류");
            throw new LoginFailException("아이디 또는 비밀번호 오류");
        }

        return user;
    }
    // 비밀번호 변경
    @Override
    public int changePassword(Long userNo, String password, String newPassword) {
        
        List<String> history = passwordHistoryMapper.findByUser(userNo);

        for (String oldPassword : history) {
            if (passwordEncoder.matches(newPassword, oldPassword)) {
                throw new RuntimeException("이전 비밀번호 사용 불가");
            }
        }

        User user = userMapper.findByNo(userNo);

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
        int result = userMapper.updatePassword(userNo, encoded);
        // 비밀번호 기록
        passwordHistoryMapper.insert(userNo, encoded);

        return result;
    }

    // 유효성 검사
    private void validateEmail(String email) {
        if (!email.matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            throw new RuntimeException("이메일 형식 오류");
        }
    }
    // 아이디 찾기 (마스킹)
    public String maskEmail(String email) {
        int idx = email.indexOf("@");
        String name = email.substring(0, idx);

        if (name.length() <= 2) {
            return email;
        }

        return name.substring(0,2) + "***" + email.substring(idx);
    }
}
