package com.auth.controller;

import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;

import com.auth.domain.User;
import com.auth.service.UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
    public String loginPage() {
        return "login";
    }
    // 회원정보 조회 페이지 - 비밀번호 변경(부분 렌더링)
    @GetMapping("/mypage")
    public String getMethodName() {
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
        @RequestParam String email,
        @RequestParam String password,
        HttpSession session
    ) {
        User user = userService.login(email, password);
        session.setAttribute("LOGIN_USER", user);

        return "redirect:/";
    }
    // 로그아웃
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        // 세션 무효화
        session.invalidate();

        return "redirect:/login";
    }
    // 비밀번호 변경
    @PostMapping("/mypage")
    public String mypage(
        @RequestParam String password,
        @RequestParam String newPassword,
        HttpSession session
    ) {
        User loginUser = (User) session.getAttribute("LOGIN_USER");
        if (loginUser == null) {
            return "redirect:/login";
        }

        userService.changePassword(loginUser.getEmail(), password, newPassword);

        return "redirect:/mypage";
    }
}
