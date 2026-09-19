package com.sawiya.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

/**
 * Tracks revoked ACCESS token jtis in Redis.
 * <p>
 * Key: "denylist:{jti}" -> "1"
 * TTL: set to the token's remaining lifetime, so Redis expires the entry automatically
 * at (or just after) the moment the token itself would have expired anyway - no cleanup job needed.
 */
@Service
@RequiredArgsConstructor
public class TokenDenylistService {

    private static final String KEY_PREFIX = "denylist:";

    private final StringRedisTemplate redisTemplate;

    public void denylist(String jti, Instant expiresAt) {
        long ttlSeconds = Duration.between(Instant.now(), expiresAt).getSeconds();
        if (ttlSeconds <= 0) {
            return; // already expired, nothing to track
        }
        redisTemplate.opsForValue().set(KEY_PREFIX + jti, "1", Duration.ofSeconds(ttlSeconds));
    }

    public boolean isDenylisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + jti));
    }
}
