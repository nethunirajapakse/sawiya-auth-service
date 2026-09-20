package com.sawiya.auth.controller;

import com.sawiya.auth.dto.MessageResponseDTO;
import com.sawiya.auth.dto.SigninRequestDTO;
import com.sawiya.auth.dto.SignupRequestDTO;
import com.sawiya.auth.dto.UserResponseDTO;
import com.sawiya.auth.exception.UnauthorizedException;
import com.sawiya.auth.security.CookieFactory;
import com.sawiya.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final CookieFactory cookieFactory;

    @PostMapping("/signup")
    public ResponseEntity<MessageResponseDTO> signup(@Valid @RequestBody SignupRequestDTO request) {
        authService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new MessageResponseDTO("Signup successful"));
    }

    @PostMapping("/signin")
    public ResponseEntity<MessageResponseDTO> signin(@Valid @RequestBody SigninRequestDTO request) {
        AuthService.TokenPair tokens = authService.signin(request);
        return withTokenCookies(tokens, new MessageResponseDTO("Login successful"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<MessageResponseDTO> refresh(
            @CookieValue(name = CookieFactory.REFRESH_TOKEN_COOKIE, required = false) String refreshTokenCookie) {
        if (refreshTokenCookie == null) {
            throw new UnauthorizedException("Refresh token missing");
        }
        AuthService.TokenPair tokens = authService.refresh(refreshTokenCookie);
        return withTokenCookies(tokens, new MessageResponseDTO("Token refreshed"));
    }

    @PostMapping("/signout")
    public ResponseEntity<MessageResponseDTO> signout(
            @CookieValue(name = CookieFactory.ACCESS_TOKEN_COOKIE, required = false) String accessTokenCookie,
            @CookieValue(name = CookieFactory.REFRESH_TOKEN_COOKIE, required = false) String refreshTokenCookie) {

        authService.signout(accessTokenCookie, refreshTokenCookie);

        ResponseCookie expiredAccess = cookieFactory.buildExpiredAccessTokenCookie();
        ResponseCookie expiredRefresh = cookieFactory.buildExpiredRefreshTokenCookie();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, expiredAccess.toString())
                .header(HttpHeaders.SET_COOKIE, expiredRefresh.toString())
                .body(new MessageResponseDTO("Logout successful"));
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponseDTO> me(Authentication authentication) {
        UUID userId = (UUID) authentication.getPrincipal();
        return ResponseEntity.ok(authService.getCurrentUser(userId));
    }

    private ResponseEntity<MessageResponseDTO> withTokenCookies(AuthService.TokenPair tokens, MessageResponseDTO body) {
        ResponseCookie accessCookie = cookieFactory.buildAccessTokenCookie(
                tokens.accessToken().token(),
                Duration.between(java.time.Instant.now(), tokens.accessToken().expiresAt()));
        ResponseCookie refreshCookie = cookieFactory.buildRefreshTokenCookie(
                tokens.refreshToken().token(),
                Duration.between(java.time.Instant.now(), tokens.refreshToken().expiresAt()));

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(body);
    }
}
