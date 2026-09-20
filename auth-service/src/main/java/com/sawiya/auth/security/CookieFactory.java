package com.sawiya.auth.security;

import com.sawiya.auth.constants.AppConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class CookieFactory {

    public static final String ACCESS_TOKEN_COOKIE = "access_token";
    public static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    private final CookieProperties cookieProperties;

    public void addAuthCookies(HttpHeaders headers, String accessToken, Duration accessMaxAge,
                               String refreshToken, Duration refreshMaxAge) {
        headers.add(HttpHeaders.SET_COOKIE, buildAccessTokenCookie(accessToken, accessMaxAge).toString());
        headers.add(HttpHeaders.SET_COOKIE, buildRefreshTokenCookie(refreshToken, refreshMaxAge).toString());
    }

    public void addExpiredAuthCookies(HttpHeaders headers) {
        headers.add(HttpHeaders.SET_COOKIE, buildExpiredAccessTokenCookie().toString());
        headers.add(HttpHeaders.SET_COOKIE, buildExpiredRefreshTokenCookie().toString());
    }

    private ResponseCookie buildAccessTokenCookie(String token, Duration maxAge) {
        return build(ACCESS_TOKEN_COOKIE, token, maxAge);
    }

    private ResponseCookie buildRefreshTokenCookie(String token, Duration maxAge) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE, token)
                .httpOnly(true)
                .secure(cookieProperties.isSecure())
                .sameSite(AppConstants.COOKIE_SAME_SITE)
                .path(AppConstants.COOKIE_AUTH_PATH)
                .maxAge(maxAge)
                .build();
    }

    private ResponseCookie buildExpiredAccessTokenCookie() {
        return build(ACCESS_TOKEN_COOKIE, "", Duration.ZERO);
    }

    private ResponseCookie buildExpiredRefreshTokenCookie() {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE, "")
                .httpOnly(true)
                .secure(cookieProperties.isSecure())
                .sameSite(AppConstants.COOKIE_SAME_SITE)
                .path(AppConstants.COOKIE_AUTH_PATH)
                .maxAge(Duration.ZERO)
                .build();
    }

    private ResponseCookie build(String name, String value, Duration maxAge) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(cookieProperties.isSecure())
                .sameSite(AppConstants.COOKIE_SAME_SITE)
                .path(AppConstants.COOKIE_ROOT_PATH)
                .maxAge(maxAge)
                .build();
    }
}
