package com.sawiya.auth.service;

import com.sawiya.auth.dto.SigninRequest;
import com.sawiya.auth.dto.SignupRequest;
import com.sawiya.auth.dto.UserResponse;
import com.sawiya.auth.entity.User;
import com.sawiya.auth.exception.DuplicateEmailException;
import com.sawiya.auth.exception.InvalidCredentialsException;
import com.sawiya.auth.exception.UnauthorizedException;
import com.sawiya.auth.repository.UserRepository;
import com.sawiya.auth.security.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenDenylistService tokenDenylistService;
    private final RefreshTokenStore refreshTokenStore;

    public void signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException("An account with this email already exists");
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);
    }

    /**
     * Verifies credentials and issues a fresh access/refresh token pair.
     * Deliberately returns nothing about the user - the caller must hit /me for that,
     * keeping this, the most-attacked endpoint, minimal in what it reveals.
     */
    public TokenPair signin(SigninRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        return issueTokenPair(user.getId(), user.getEmail());
    }

    /**
     * Validates the refresh token (signature, expiry, and that its jti is still
     * in the live registry) and rotates both tokens - old refresh token is revoked,
     * a new pair is issued. This limits the blast radius if a refresh token is ever replayed.
     */
    public TokenPair refresh(String refreshToken) {
        Claims claims = parseOrThrow(refreshToken);

        String jti = claims.getId();
        if (!refreshTokenStore.isValid(jti)) {
            throw new UnauthorizedException("Refresh token has been revoked or expired");
        }

        UUID userId = UUID.fromString(claims.getSubject());
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("User no longer exists"));

        // Rotate: invalidate the old refresh token before issuing a new pair.
        refreshTokenStore.revoke(jti);

        return issueTokenPair(user.getId(), user.getEmail());
    }

    /**
     * Denylists the current access token (so it stops working immediately, even though it
     * hasn't expired) and revokes the refresh token so it can no longer mint new access tokens.
     */
    public void signout(String accessToken, String refreshToken) {
        if (accessToken != null) {
            try {
                Claims claims = jwtService.parseClaims(accessToken);
                tokenDenylistService.denylist(claims.getId(), claims.getExpiration().toInstant());
            } catch (JwtException ignored) {
                // Already invalid/expired - nothing to denylist.
            }
        }
        if (refreshToken != null) {
            try {
                Claims claims = jwtService.parseClaims(refreshToken);
                refreshTokenStore.revoke(claims.getId());
            } catch (JwtException ignored) {
                // Already invalid/expired - nothing to revoke.
            }
        }
    }

    public UserResponse getCurrentUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("User no longer exists"));
        return new UserResponse(user.getId().toString(), user.getFirstName() + " " + user.getLastName(), user.getEmail());
    }

    private TokenPair issueTokenPair(UUID userId, String email) {
        JwtService.GeneratedToken access = jwtService.generateAccessToken(userId, email);
        JwtService.GeneratedToken refresh = jwtService.generateRefreshToken(userId);

        refreshTokenStore.store(refresh.jti(), userId.toString(), refresh.expiresAt());

        return new TokenPair(access, refresh);
    }

    private Claims parseOrThrow(String token) {
        try {
            return jwtService.parseClaims(token);
        } catch (JwtException e) {
            throw new UnauthorizedException("Invalid or expired refresh token");
        }
    }

    public record TokenPair(JwtService.GeneratedToken accessToken, JwtService.GeneratedToken refreshToken) {
    }
}
