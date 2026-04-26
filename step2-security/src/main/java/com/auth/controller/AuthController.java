package com.auth.controller;

import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

import com.auth.domain.User;
import com.auth.security.CustomUserDetails;
import com.auth.service.EmailService;
import com.auth.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.GetMapping;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final EmailService emailService;

    // 회원가입 페이지
    @GetMapping("/signup")
    public String signupPage() {
        return "signup";
    }

    // 비밀번호 재설정 페이지
    @GetMapping("/password-reset")
    public String passwordResetPage() {
        return "password-reset";
    }

    // 로그인 페이지
    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "locked", required = false) String locked,
            @RequestParam(value = "fail", required = false) String fail,
            Model model) {
        if (locked != null) {
            model.addAttribute("error", "계정이 잠겼습니다. 관리자에게 문의하세요.");
        } else if (fail != null) {
            model.addAttribute("error", "비밀번호 오류 (" + fail + "회)");
        } else if (error != null) {
            model.addAttribute("error", "아이디 또는 비밀번호가 올바르지 않습니다.");
        }
        return "login";
    }

    // 회원정보 조회 페이지 - 비밀번호 변경(부분 렌더링)
    @GetMapping("/mypage")
    public String mypage(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            Model model) {
        log.info("[Mypage] 컨트롤러 진입, userDetails={}", userDetails);

        if (userDetails == null) {
            log.warn("[Mypage] userDetails null → redirect:/login");
            return "redirect:/login";
        }

        log.info("[Mypage] 인증된 사용자 no={}, email={}", userDetails.getUser().getNo(), userDetails.getUser().getEmail());
        model.addAttribute("user", userDetails.getUser());

        return "mypage";
    }

    // 회원가입
    // @RequestPara 개념/사용 이유
    @PostMapping("/signup")
    public String signup(User user, Model model) {
        try {
            userService.signup(user);
            return "redirect:/login";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return "signup";
        }

    }

    // 로그인 - Security 처리
    // 로그아웃 - Security 처리
    // 비밀번호 변경
    @PostMapping("/api/password")
    @ResponseBody
    public Map<String, Object> changePassword(
            @RequestBody Map<String, String> req,
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        if (userDetails == null) {
            return Map.of("success", false, "message", "로그인 필요");
        }

        try {
            userService.changePassword(
                    userDetails.getUser().getNo(),
                    req.get("password"),
                    req.get("newPassword"));
            return Map.of("success", true);
        } catch (Exception e) {
            return Map.of("success", false, "message", e.getMessage());
        }
    }

    // 이메일 2차 인증 코드 발송
    @PostMapping("/email/send")
    @ResponseBody
    public Map<String, Object> send(@RequestBody Map<String, String> req) {
        try {
            emailService.sendCode(req.get("email"));
            return Map.of("success", true);
        } catch (Exception e) {
            return Map.of("success", false, "message", e.getMessage());
        }
    }

    // 이메일 인증 코드 확인
    @PostMapping("/email/verify")
    @ResponseBody
    public Map<String, Object> verifyCode(@RequestBody Map<String, String> req) {
        try {
            boolean valid = emailService.verifyCode(req.get("email"), req.get("code"));
            return Map.of("success", true);
        } catch (Exception e) {
            return Map.of("success", false, "message", e.getMessage());
        }
    }

    // 비밀번호 재설정
    @PostMapping("/api/password/reset")
    @ResponseBody
    public Map<String, Object> resetPassword(@RequestBody Map<String, String> req) {
        try {
            userService.resetPasswordByEmail(
                    req.get("email"),
                    req.get("code"),
                    req.get("newPassword"));
            return Map.of("success", true);
        } catch (Exception e) {
            return Map.of("success", false, "message", e.getMessage());
        }
    }
}
/**
 * 에러1
 * Mapped to com.auth.controller.AuthController#loginPage(String, Model)
 * - 인식: loginPage(String, Model)
 * - 코드: loginPage(String error, Model)
 * - 수정: valeu = "error" 명시
 */
