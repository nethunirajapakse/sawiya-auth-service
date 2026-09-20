package com.sawiya.auth.service;

import com.sawiya.auth.EmbeddedRedisTestBase;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import java.time.Instant;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@SpringBootTest
@ActiveProfiles("test")
class RedisCircuitBreakerTest extends EmbeddedRedisTestBase {

    @Autowired
    private TokenDenylistService tokenDenylistService;

    @Autowired
    private RefreshTokenStore refreshTokenStore;

    @Autowired
    private CircuitBreakerRegistry circuitBreakerRegistry;

    @AfterEach
    void resetCircuitBreaker() {
        CircuitBreaker breaker = circuitBreakerRegistry.circuitBreaker("redis");
        breaker.reset();
    }

    @Test
    void isDenylisted_failsOpenWhenCircuitBreakerIsOpen() {
        circuitBreakerRegistry.circuitBreaker("redis").transitionToOpenState();

        boolean result = tokenDenylistService.isDenylisted("some-jti");

        assertThat(result).isFalse();
    }

    @Test
    void isValid_failsOpenWhenCircuitBreakerIsOpen() {
        circuitBreakerRegistry.circuitBreaker("redis").transitionToOpenState();

        boolean result = refreshTokenStore.isValid("some-jti");

        assertThat(result).isTrue();
    }

    @Test
    void denylist_doesNotThrowWhenCircuitBreakerIsOpen() {
        circuitBreakerRegistry.circuitBreaker("redis").transitionToOpenState();

        assertThatCode(() -> tokenDenylistService.denylist("some-jti", Instant.now().plusSeconds(900)))
                .doesNotThrowAnyException();
    }

    @Test
    void revoke_doesNotThrowWhenCircuitBreakerIsOpen() {
        circuitBreakerRegistry.circuitBreaker("redis").transitionToOpenState();

        assertThatCode(() -> refreshTokenStore.revoke("some-jti"))
                .doesNotThrowAnyException();
    }

    @Test
    void closedCircuitBreaker_stillWorksNormallyAgainstRealRedis() {
        String jti = "closed-circuit-jti";
        tokenDenylistService.denylist(jti, Instant.now().plusSeconds(900));

        assertThat(tokenDenylistService.isDenylisted(jti)).isTrue();
    }
}
