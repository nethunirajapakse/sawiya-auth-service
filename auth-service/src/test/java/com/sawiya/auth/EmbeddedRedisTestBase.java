package com.sawiya.auth;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import redis.embedded.RedisServer;

import java.io.IOException;

/**
 * Starts a real (embedded) Redis instance for the duration of the integration test class,
 * so the denylist / refresh-token-store logic is exercised against actual Redis semantics
 * (TTL expiry, key existence) rather than a mock.
 */
public abstract class EmbeddedRedisTestBase {

    private static RedisServer redisServer;

    @BeforeAll
    static void startRedis() throws IOException {
        redisServer = new RedisServer(6380);
        redisServer.start();
    }

    @AfterAll
    static void stopRedis() throws IOException {
        if (redisServer != null) {
            redisServer.stop();
        }
    }
}
