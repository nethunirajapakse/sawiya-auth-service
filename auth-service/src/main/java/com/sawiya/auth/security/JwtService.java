package com.sawiya.auth.security;

import com.sawiya.auth.constants.AppConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;

    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public GeneratedToken generateAccessToken(UUID userId, String email) {
        Instant now = Instant.now();
        Instant expiry = now.plus(Duration.ofMinutes(jwtProperties.getAccessTokenExpiryMinutes()));
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .id(jti)
                .subject(userId.toString())
                .claim(AppConstants.CLAIM_EMAIL, email)
                .claim(AppConstants.CLAIM_TYPE, TokenType.ACCESS.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(signingKey())
                .compact();

        return new GeneratedToken(token, jti, expiry);
    }

    public GeneratedToken generateRefreshToken(UUID userId) {
        Instant now = Instant.now();
        Instant expiry = now.plus(Duration.ofDays(jwtProperties.getRefreshTokenExpiryDays()));
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .id(jti)
                .subject(userId.toString())
                .claim(AppConstants.CLAIM_TYPE, TokenType.REFRESH.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(signingKey())
                .compact();

        return new GeneratedToken(token, jti, expiry);
    }

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

    public record GeneratedToken(String token, String jti, Instant expiresAt) {
    }
}
