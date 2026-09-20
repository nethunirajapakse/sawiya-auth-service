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
public class TokenDenylistService {

    private static final Logger log = LoggerFactory.getLogger(TokenDenylistService.class);
    private static final String KEY_PREFIX = AppConstants.DENYLIST_KEY_PREFIX;

    private final StringRedisTemplate redisTemplate;

    @CircuitBreaker(name = AppConstants.REDIS_CIRCUIT_BREAKER_NAME, fallbackMethod = "denylistFallback")
    public void denylist(String jti, Instant expiresAt) {
        long ttlSeconds = Duration.between(Instant.now(), expiresAt).getSeconds();
        if (ttlSeconds <= 0) {
            return;
        }
        redisTemplate.opsForValue().set(KEY_PREFIX + jti, "1", Duration.ofSeconds(ttlSeconds));
    }

    @SuppressWarnings("unused")
    private void denylistFallback(String jti, Instant expiresAt, Throwable t) {
        log.warn("Could not denylist access token jti={} - Redis unavailable ({}). Signout will " +
                "still succeed (cookies cleared), but this token may remain technically usable " +
                "until it naturally expires.", jti, t.toString());
    }

    @CircuitBreaker(name = AppConstants.REDIS_CIRCUIT_BREAKER_NAME, fallbackMethod = "isDenylistedFallback")
    public boolean isDenylisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + jti));
    }

    @SuppressWarnings("unused")
    private boolean isDenylistedFallback(String jti, Throwable t) {
        log.warn("Could not check denylist for jti={} - Redis unavailable ({}), failing open " +
                "(treating token as not denylisted) so authenticated requests aren't blocked " +
                "by a Redis outage.", jti, t.toString());
        return false;
    }
}
