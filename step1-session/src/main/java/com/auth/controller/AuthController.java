package com.auth.controller;

import jakarta.servlet.http.HttpSession;

import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

import com.auth.domain.User;
import com.auth.exception.LoginFailException;
import com.auth.service.UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

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
        HttpSession session,
        Model model
    ) {
        User loginUser = (User) session.getAttribute("LOGIN_USER");

        if (loginUser == null) {
            return "redirect:/login";
        }

        model. addAttribute("user", loginUser);
        return "mypage";
    }
    // 회원가입
    // @RequestPara 개념/사용 이유
    @PostMapping("/signup")
    public String signup(User user) {

        userService.signup(user);

        return "redirect:/login";
    }
    // 로그인
    // HttpSession 개념/사용 이유
    // : 서버에 로그인 상태 저장
    //  - session.setAttribute("LOGIN_USER", user)
    @PostMapping("/login")
    public String login(
        @RequestParam("email") String email,
        @RequestParam("password") String password,
        HttpSession session
    ) {
        try{
            // 세션 저장
            User user = userService.login(email, password);
            session.setAttribute("LOGIN_USER", user);
            // 세션 만료 시간 설정 (30분)
            session.setMaxInactiveInterval(1800);
    
            return "redirect:/mypage";
        } catch (LoginFailException e) {
            return "redirect:/login?error=true";
        }
    }
    // 로그아웃
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        // 세션 무효화
        session.invalidate();

        return "redirect:/login";
    }
    // 비밀번호 변경
    @PostMapping("/api/password")
    @ResponseBody
    public Map<String, Object> changePassword(
        @RequestBody Map<String, String> req,
        HttpSession session
    ) {
        User loginUser = (User) session.getAttribute("LOGIN_USER");

        if (loginUser == null) {
            return Map.of("success", false, "message", "로그인 필요");
        }

        try {
            userService.changePassword(
                loginUser.getNo(), 
                req.get("password"),
                req.get("newPassword")
            );
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
