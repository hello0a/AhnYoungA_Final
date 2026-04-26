package com.auth.service;

import java.time.LocalDateTime;

import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.domain.EmailVerification;
import com.auth.domain.User;
import com.auth.mapper.EmailVerificationMapper;
import com.auth.mapper.UserMapper;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender javaMailSender;
    private final UserMapper userMapper;
    private final EmailVerificationMapper mapper;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void sendCode(String email) {

        try {
            // 사용자 존재 확인
            User user = userMapper.findByEmail(email);
            if (user == null) {
                // 보안: 존재 여부 숨김
                log.warn("[Email] 존재하지 않는 이메일 요청: {}", email);
                return;
            }
            // 재요청 제한
            EmailVerification recent = mapper.findByEmail(email);
            if (recent != null && recent.getCreatedAt() != null
                    && recent.getCreatedAt().isAfter(LocalDateTime.now().minusSeconds(30))) {
                throw new RuntimeException("잠시 후 다시 시도하세요 (30초 제한)");
            }
            // 인증코드 생성
            String code = String.valueOf((int) (Math.random() * 900000) + 100000);
            String encoded = passwordEncoder.encode(code);
            // 이메일 생성
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("[인증코드] 비밀번호 재설정");
            message.setText("인증코드: " + code + "\n5분 내에 입력해주세요.");
            // 메일 전송
            javaMailSender.send(message);
            // 기존 코드 삭제 후 새로 생성
            mapper.deleteByEmail(email);
            // DB 저장 (5분 유효)
            mapper.insert(
                    user.getNo(),
                    email,
                    encoded,
                    LocalDateTime.now().plusMinutes(5));

            log.info("[Email] 인증코드 전송 성공: {}", email);

        } catch (MailException e) {
            // SMTP / 네트워크 문제
            log.error("[Email] 메일 전송 실패 (MailException): {}", e.getMessage(), e);
            throw new RuntimeException("메일 전송 실패. 잠시 후 다시 시도하세요");
        } catch (Exception e) {
            // 기타 예외
            log.error("[Email] 서버 오류: {}", e.getMessage(), e);
            throw e;
        }
    }

    public boolean verifyCode(String email, String input) {

        EmailVerification verification = mapper.findByEmail(email);

        if (verification == null ||
                verification.getExpiry() == null ||
                verification.getExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("인증코드가 만료되었습니다.");
        }
        // 실패 횟수 제한
        if (verification.getFailCount() >= 5) {
            throw new RuntimeException("인증 시도 횟수 초과 (5회)");
        }

        boolean valid = passwordEncoder.matches(input, verification.getCode());

        if (valid) {
            // mapper.deleteByEmail(email);
            return true;
        } else {
            mapper.increaseFailCount(email);
            throw new RuntimeException("인증코드가 올바르지 않습니다.");
        }
    }

    public void deleteVerification(String email) {
        mapper.deleteByEmail(email);
    }
}
