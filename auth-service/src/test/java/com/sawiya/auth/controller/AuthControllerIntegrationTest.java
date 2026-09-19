package com.sawiya.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sawiya.auth.EmbeddedRedisTestBase;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest extends EmbeddedRedisTestBase {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private Map<String, Object> signupBody(String email, String password) {
        Map<String, Object> body = new HashMap<>();
        body.put("firstName", "Test");
        body.put("lastName", "User");
        body.put("email", email);
        body.put("password", password);
        return body;
    }

    @Test
    void signup_thenSignin_thenMe_fullHappyPath() throws Exception {
        String email = "flow-user@example.com";
        String password = "Password@123";

        // 1. Signup
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupBody(email, password))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("Signup successful"));

        // 2. Signin
        Map<String, String> signinBody = Map.of("email", email, "password", password);
        MvcResult signinResult = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signinBody)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(cookie().exists("access_token"))
                .andExpect(cookie().exists("refresh_token"))
                .andReturn();

        Cookie accessCookie = signinResult.getResponse().getCookie("access_token");

        // 3. /me with the access token cookie
        mockMvc.perform(get("/api/auth/me").cookie(accessCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.name").value("Test User"));
    }

    @Test
    void signup_rejectsDuplicateEmail() throws Exception {
        String email = "dupe@example.com";
        Map<String, Object> body = signupBody(email, "Password@123");

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isConflict());
    }

    @Test
    void signup_rejectsInvalidEmailAndWeakPassword() throws Exception {
        Map<String, Object> body = signupBody("not-an-email", "weak");

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void signin_rejectsWrongPassword() throws Exception {
        String email = "wrongpass@example.com";
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupBody(email, "Password@123"))))
                .andExpect(status().isCreated());

        Map<String, String> signinBody = Map.of("email", email, "password", "WrongPassword@123");
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signinBody)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void me_rejectsRequestWithNoCookie() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signout_invalidatesAccessTokenImmediately() throws Exception {
        String email = "signout-user@example.com";
        String password = "Password@123";

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupBody(email, password))))
                .andExpect(status().isCreated());

        MvcResult signinResult = mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", email, "password", password))))
                .andExpect(status().isOk())
                .andReturn();

        Cookie accessCookie = signinResult.getResponse().getCookie("access_token");
        Cookie refreshCookie = signinResult.getResponse().getCookie("refresh_token");

        // Real clients get their CSRF token from a prior response's XSRF-TOKEN cookie, but
        // that cookie is only written when Spring Security actually resolves a CsrfToken
        // during a request - a plain GET /me never triggers that. .with(csrf()) is Spring
        // Security's supported way to simulate "the client already has a valid CSRF token"
        // without depending on that side effect, and works with any CsrfTokenRepository
        // (including our CookieCsrfTokenRepository).
        mockMvc.perform(post("/api/auth/signout")
                        .with(csrf())
                        .cookie(accessCookie, refreshCookie))
                .andExpect(status().isOk());

        // The same (now-denylisted) access token must no longer work.
        mockMvc.perform(get("/api/auth/me").cookie(accessCookie))
                .andExpect(status().isUnauthorized());
    }
}
