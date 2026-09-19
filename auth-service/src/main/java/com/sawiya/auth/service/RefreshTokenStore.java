package com.sawiya.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

/**
 * Tracks live refresh token jtis in Redis as an allow-list (opposite of the access-token
 * denylist): a refresh token is only usable if its jti is still present here.
 * <p>
 * Key: "refresh:{jti}" -> userId
 * TTL: refresh token expiry, so stale entries clean themselves up.
 * <p>
 * On signout (or refresh rotation), the entry is deleted, which immediately revokes that
 * refresh token even though the JWT signature itself is still technically valid until expiry.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenStore {

    private static final String KEY_PREFIX = "refresh:";

    private final StringRedisTemplate redisTemplate;

    public void store(String jti, String userId, Instant expiresAt) {
        long ttlSeconds = Duration.between(Instant.now(), expiresAt).getSeconds();
        if (ttlSeconds <= 0) {
            return;
        }
        redisTemplate.opsForValue().set(KEY_PREFIX + jti, userId, Duration.ofSeconds(ttlSeconds));
    }

    public boolean isValid(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + jti));
    }

    public void revoke(String jti) {
        redisTemplate.delete(KEY_PREFIX + jti);
    }
}
