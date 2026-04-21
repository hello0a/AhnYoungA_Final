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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.GetMapping;

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
    // 로그인 페이지
    @GetMapping("/login")
    public String loginPage(
        @RequestParam(value = "error", required = false) String error,
        Model model
    ) {
        if (error != null) {
            model.addAttribute("error", "아이디 또는 비밀번호가 올바르지 않습니다.");
        }
        return "login";
    }
    // 회원정보 조회 페이지 - 비밀번호 변경(부분 렌더링)
    @GetMapping("/mypage")
    public String mypage(
        @AuthenticationPrincipal CustomUserDetails userDetails,
        Model model
    ) {

        if (userDetails == null) {
            return "redirect:/login";
        }

        model. addAttribute("user", userDetails.getUser());

        return "mypage";
    }
    // 회원가입
    // @RequestPara 개념/사용 이유
    @PostMapping("/signup")
    public void signup(@RequestBody User user) {
        userService.signup(user);
    }
    // 로그인 - Security 처리
    // 로그아웃 - Security 처리
    // 비밀번호 변경
    @PostMapping("/api/password")
    @ResponseBody
    public Map<String, Object> changePassword(
        @RequestBody Map<String, String> req,
        @AuthenticationPrincipal CustomUserDetails userDetails
    ) {

        if (userDetails == null) {
            return Map.of("success", false, "message", "로그인 필요");
        }

        try {
            userService.changePassword(
                userDetails.getUser().getNo(), 
                req.get("password"),
                req.get("newPassword")
            );
            return Map.of("success", true);
        } catch (Exception e) {
            return Map.of("success", false, "message", e.getMessage());
        }
    }
    // 이메일 2차 인증
    @PostMapping("/email/send")
    public void send(@RequestBody Map<String, String> req) {
        emailService.sendCode(req.get("email"));
    }
}
/**
 * 에러1
 * Mapped to com.auth.controller.AuthController#loginPage(String, Model)
 * - 인식: loginPage(String, Model)
 * - 코드: loginPage(String error, Model)
 * - 수정: valeu = "error" 명시
 */
