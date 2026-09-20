package com.sawiya.auth.service;

import com.sawiya.auth.constants.AppConstants;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenStore.class);
    private static final String KEY_PREFIX = AppConstants.REFRESH_TOKEN_KEY_PREFIX;

    private final StringRedisTemplate redisTemplate;

    @CircuitBreaker(name = AppConstants.REDIS_CIRCUIT_BREAKER_NAME, fallbackMethod = "storeFallback")
    public void store(String jti, String userId, Instant expiresAt) {
        long ttlSeconds = Duration.between(Instant.now(), expiresAt).getSeconds();
        if (ttlSeconds <= 0) {
            return;
        }
        redisTemplate.opsForValue().set(KEY_PREFIX + jti, userId, Duration.ofSeconds(ttlSeconds));
    }

    @SuppressWarnings("unused")
    private void storeFallback(String jti, String userId, Instant expiresAt, Throwable t) {
        log.warn("Could not store refresh token jti={} for user={} - Redis unavailable ({}). " +
                "Signin will still succeed, but this refresh token won't be usable later until " +
                "Redis recovers and a new one is issued.", jti, userId, t.toString());
    }

    @CircuitBreaker(name = AppConstants.REDIS_CIRCUIT_BREAKER_NAME, fallbackMethod = "isValidFallback")
    public boolean isValid(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + jti));
    }

    @SuppressWarnings("unused")
    private boolean isValidFallback(String jti, Throwable t) {
        log.warn("Could not validate refresh token jti={} - Redis unavailable ({}), failing open " +
                "(treating token as valid) so a Redis outage doesn't block every session refresh " +
                "in the app. The JWT's own signature and expiry are still enforced.", jti, t.toString());
        return true;
    }

    @CircuitBreaker(name = AppConstants.REDIS_CIRCUIT_BREAKER_NAME, fallbackMethod = "revokeFallback")
    public void revoke(String jti) {
        redisTemplate.delete(KEY_PREFIX + jti);
    }

    @SuppressWarnings("unused")
    private void revokeFallback(String jti, Throwable t) {
        log.warn("Could not revoke refresh token jti={} - Redis unavailable ({}). Signout will " +
                "still succeed, but this refresh token may remain valid until it naturally " +
                "expires.", jti, t.toString());
    }
}
