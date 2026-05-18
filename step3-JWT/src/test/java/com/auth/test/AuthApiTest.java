package com.auth.test;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.auth.domain.User;
import com.auth.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.transaction.Transactional;

// Step3 핵심 테스트
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthApiTest {
    
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    private String email;
    private String password;

    @BeforeEach
    void setup() {
        email = "jwt" + UUID.randomUUID() + "@test.com";
        password = "Abcd1234!";

        User user = new User();
        user.setEmail(email);
        user.setPassword(password);
        user.setName("JWT테스터");

        userService.signup(user);
    }

    @Test
    void login_success_returns_access_and_refresh_token() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, password)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()));
    }

    @Test
    void me_success_with_access_token() throws Exception {
        TokenPair tokens = login();

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + tokens.accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.name").value("JWT테스터"));
    }

    @Test
    void login_history_success_with_access_token() throws Exception {
        TokenPair tokens = login();

        mockMvc.perform(get("/api/auth/login-history")
                        .header("Authorization", "Bearer " + tokens.accessToken))
                .andExpect(status().isOk());
    }

    @Test
    void refresh_success_returns_new_access_token() throws Exception {
        TokenPair tokens = login();

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "%s"
                                }
                                """.formatted(tokens.refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken").value(tokens.refreshToken));
    }

    @Test
    void logout_success_then_refresh_fails() throws Exception {
        TokenPair tokens = login();

        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + tokens.accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "%s"
                                }
                                """.formatted(tokens.refreshToken)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "%s"
                                }
                                """.formatted(tokens.refreshToken)))
                .andExpect(status().is5xxServerError());
    }

    @Test
    void me_fail_without_access_token() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void me_fail_with_invalid_access_token() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer invalid.token.value"))
                .andExpect(status().isUnauthorized());
    }

    private TokenPair login() throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, password)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode json = objectMapper.readTree(response);

        return new TokenPair(
                json.get("accessToken").asText(),
                json.get("refreshToken").asText()
        );
    }

    private record TokenPair(String accessToken, String refreshToken) {
    }
}
