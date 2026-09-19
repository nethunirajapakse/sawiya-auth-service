package com.sawiya.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Handles creation and verification of access/refresh JWTs.
 * <p>
 * Both token types are signed with the same secret but carry a distinct "type" claim
 * and a unique "jti" (JWT ID) which is what the denylist / refresh-token registry key off of.
 */
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;

    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public GeneratedToken generateAccessToken(UUID userId, String email) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(jwtProperties.getAccessTokenExpiryMinutes() * 60);
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .id(jti)
                .subject(userId.toString())
                .claim("email", email)
                .claim("type", TokenType.ACCESS.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(signingKey())
                .compact();

        return new GeneratedToken(token, jti, expiry);
    }

    public GeneratedToken generateRefreshToken(UUID userId) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(jwtProperties.getRefreshTokenExpiryDays() * 24 * 60 * 60);
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .id(jti)
                .subject(userId.toString())
                .claim("type", TokenType.REFRESH.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(signingKey())
                .compact();

        return new GeneratedToken(token, jti, expiry);
    }

    /**
     * Parses and validates a token's signature/expiry.
     * Throws JwtException (or a subclass) if the token is invalid, malformed, or expired -
     * callers should catch this and treat it as "unauthenticated".
     */
    public Claims parseClaims(String token) throws JwtException {
        return Jwts.parser()
                .verifyWith(signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    /**
     * Convenience wrapper so filters don't need to import JJWT exception types directly.
     * ExpiredJwtException is itself a subclass of JwtException, so catching JwtException
     * alone already covers expiry, bad signature, malformed token, etc.
     */
    public boolean isValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public record GeneratedToken(String token, String jti, Instant expiresAt) {
    }
}
