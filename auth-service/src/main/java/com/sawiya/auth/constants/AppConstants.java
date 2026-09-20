package com.sawiya.auth.constants;

public final class AppConstants {

    private AppConstants() {}

    // --- Cookies ---
    public static final String COOKIE_SAME_SITE = "Strict";
    public static final String COOKIE_ROOT_PATH = "/";
    public static final String COOKIE_AUTH_PATH = "/api/auth";

    // --- CSRF ---
    public static final String CSRF_TOKEN_ATTRIBUTE = "_csrf";

    // --- JWT claims ---
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_TYPE = "type";

    // --- Redis ---
    public static final String REDIS_CIRCUIT_BREAKER_NAME = "redis";
    public static final String DENYLIST_KEY_PREFIX = "denylist:";
    public static final String REFRESH_TOKEN_KEY_PREFIX = "refresh:";

    // --- Password  ---
    public static final int BCRYPT_STRENGTH = 12;
    public static final String PASSWORD_PATTERN =
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#^()_+\\-=]).+$";
}
