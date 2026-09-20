# Sawiya Auth Service

A User Authentication REST API built with Java 17 and Spring Boot 3, submitted for the
Sawiya Backend Developer (Java / Spring Boot) technical assignment.

## Endpoints

| Method | Path                  | Auth required | CSRF required | Description |
|--------|-----------------------|---------------|----------------|--------------|
| POST   | `/api/auth/signup`    | No            | No             | Create a new user account |
| POST   | `/api/auth/signin`    | No            | No             | Verify credentials, issue access + refresh token cookies |
| POST   | `/api/auth/refresh`   | Refresh cookie| Yes            | Rotate the access/refresh token pair |
| POST   | `/api/auth/signout`   | Yes           | Yes            | Revoke both tokens, clear cookies |
| GET    | `/api/auth/me`        | Yes           | No (read-only) | Return the current user's identity |

## Why signin returns only `{ "message": "..." }`

The sign-in endpoint's job is authentication, not identity. It's also the endpoint most
exposed to brute-force/credential-stuffing attempts, so it deliberately returns the minimum
possible information on both success and failure. Anything about *who* the user is lives
behind `/me`, which is called separately (using the cookie that's already set) once the
client needs it. This keeps the two concerns — "did the login succeed" and "who is this
user" — independently testable and independently securable.

## Authentication design

- **Access token**: short-lived JWT (15 min default), sent as an `httpOnly`, `Secure`,
  `SameSite=Strict` cookie (`access_token`), scoped to `/`.
- **Refresh token**: longer-lived JWT (7 days default), its own `httpOnly` cookie
  (`refresh_token`), scoped to `/api/auth` (not just `/api/auth/refresh`) so it also reaches
  `/signout`, which needs to read and revoke it — a narrower scope would mean the browser
  never sends this cookie to `/signout` at all, and the refresh token would silently never
  get revoked on logout.
- Both tokens carry a unique `jti` claim, which is what the revocation logic keys off of.

### Why not an ID token?

ID tokens are an OpenID Connect concept: a signed claim about *who the user is*, meant for
a **third-party client app** to consume (e.g. "Login with Sawiya" used by someone else's
service). That distinction only matters when this service acts as an identity provider for
other applications. Here, there's a single first-party backend authenticating directly
against its own user store, so a single access/refresh token pair is sufficient — adding an
ID token would add OIDC-shaped complexity with no consumer for the distinction it creates.

## Token invalidation (signout)

JWTs are stateless by design, so simply deleting the cookie on logout would leave a copied
token valid until it naturally expires. Two Redis-backed structures close that gap:

- **Access token denylist** — `denylist:{jti}` → `"1"`, TTL = the token's remaining
  lifetime. The `JwtAuthenticationFilter` checks this on every request; a hit means "reject
  even though the signature is valid." Redis expires the entry automatically once the token
  itself would have expired, so no cleanup job is needed.
- **Refresh token registry (allow-list)** — `refresh:{jti}` → `userId`, TTL = refresh token
  expiry. A refresh token is only honored if its `jti` is still present here. Signout (and
  refresh-token rotation on every `/refresh` call) deletes the entry, immediately revoking
  that token regardless of its signature validity.

**Trade-off considered**: a simpler alternative is a `tokenVersion` counter on the `User`
row, embedded as a JWT claim and bumped on logout — no Redis lookup needed at all. It's
simpler, but it invalidates *every* session for that user at once, not just the one being
logged out. The denylist/registry approach was chosen because it supports per-session
logout, which is the more common expectation ("log out this device" vs. "log out
everywhere").

**Why Redis and not a DB table**: checking a relational table on every authenticated
request reintroduces a stateful hot path into an otherwise stateless JWT design — a DB
round-trip per request is the first thing to fall over under load. Redis gives O(1) lookups,
native TTL-based expiry (matching the token's own expiry with no scheduled cleanup), and
scales horizontally far more easily than adding read replicas for what is otherwise a tiny
lookup table.

## CSRF protection

Because auth state lives in cookies (not an `Authorization` header), the API is protected
against CSRF using Spring Security's double-submit cookie pattern
(`CookieCsrfTokenRepository`): the server sets a readable `XSRF-TOKEN` cookie, and the
client must echo its value back in an `X-XSRF-TOKEN` header on state-changing requests.

Spring Security 6's CSRF token is lazily generated — it's only actually written to the
`XSRF-TOKEN` cookie if something in the request resolves it, so a plain `GET /me` would
never hand a client a usable token. A small filter (`csrfCookieFilter` in `SecurityConfig`)
forces that resolution on every request so the cookie is reliably present for any client.

CSRF is **not** required on:
- `/signup` and `/signin` — no session/cookie exists yet at that point; these are
  credential-based requests, not cookie-authenticated ones.
- `GET /me` — CSRF only protects against attacker-triggered *state changes*; a read-only
  GET has nothing for CSRF to protect.

It **is** required on `/refresh` and `/signout`, since both act on the caller's existing
cookie-based session. In Postman/curl, this means every state-changing call needs an
`X-XSRF-TOKEN` header carrying the value of the `XSRF-TOKEN` cookie — the cookie alone is
not enough (that's the entire point of CSRF protection).

## Password policy

Enforced via Bean Validation on signup:
- Minimum 8 characters
- At least one uppercase letter, one lowercase letter, one digit, and one special character
  (`@$!%*?&#^()_+-=`)

Passwords are hashed with BCrypt at a work factor of **12** — a deliberate CPU-cost/security
trade-off (higher than the library default of 10) chosen to slow down offline brute-force
attempts on a leaked hash while remaining fast enough for normal login latency.

## Resilience: what happens if Redis goes down

Redis backs the access-token denylist and refresh-token registry, but it's a hardening
layer on top of JWT signature/expiry checks, not the only line of defense. Every Redis call
in `TokenDenylistService` and `RefreshTokenStore` is wrapped with a Resilience4j circuit
breaker (instance name `redis`, configured in `application.properties`):

- While **CLOSED**, calls go to Redis as normal.
- If enough calls fail (default: 50% of the last 10, after a minimum of 5 calls), the
  breaker **OPENs** — every subsequent call short-circuits immediately to a fallback,
  instead of waiting on a connection timeout on every single request.
- After a cooldown (`10s` default), it allows a few trial calls through (**HALF_OPEN**) to
  check whether Redis has recovered.

**Fallback behavior is deliberately asymmetric**, chosen per-method based on what's safer to
get wrong during an outage:
- `isDenylisted` fails **open** (treats the token as not denylisted) — a Redis outage
  shouldn't lock every authenticated user out of the app. The risk window is bounded by the
  access token's own short expiry (15 min default).
- `isValid` (refresh token check) fails **open** the same way, for the same reason — the
  JWT's own signature/expiry is still enforced regardless.
- `denylist`, `store`, and `revoke` (all writes) fail **soft** — they log a warning and
  return normally rather than turning a best-effort Redis write into a 500 for the user.
  Signin/signout still succeed even if Redis can't be reached.

All of this is exercised by `RedisCircuitBreakerTest`, which forces the breaker open via
Resilience4j's `transitionToOpenState()` and asserts the fallback behavior directly, without
needing to physically bring Redis down.

## Logging

Every exception handled by `GlobalExceptionHandler` is logged, not just the generic 500
case — validation failures, duplicate signups, and invalid-credentials attempts are all
`WARN`-level, so they're visible for debugging and for spotting patterns (e.g. repeated
`InvalidCredentialsException` log lines is exactly the signal that flags a brute-force
attempt). Genuinely unexpected errors are `ERROR` with a full stack trace. Two spots that
previously discarded exceptions silently (`AuthService.signout()` handling an
already-expired token, `JwtAuthenticationFilter` handling a malformed cookie) now log at
`DEBUG` instead — these are expected, non-actionable outcomes so they shouldn't be noisy at
`WARN`, but they're no longer invisible if you're diagnosing a specific report. `DEBUG` is
already enabled for `com.sawiya.auth` in `application.properties`.

## Scalability notes

- The core auth flow is stateless (JWT + Redis lookups only), so the API can scale
  horizontally behind a load balancer with no sticky sessions required.
- The one deliberately-not-built-here improvement beyond the circuit breaker: at very high
  request volumes, even a healthy Redis denylist check is an extra network hop per request.
  A further optimization would be a local in-memory cache (e.g. Caffeine) of recently-seen
  denylisted `jti`s in front of Redis, invalidated via Redis pub/sub — not implemented here
  to keep the assignment's scope proportionate to a 7-day take-home.

## Running locally

### Local secrets (required — several values have no built-in default)

`JWT_SECRET`, `DB_URL`, `DB_USERNAME`, and `DB_PASSWORD` have **no default** in
`application.properties` on purpose — the app refuses to start without them rather than
silently running with a baked-in placeholder secret. Supply real values without ever
committing them:

```powershell
copy src\main\resources\application-secrets.properties.example src\main\resources\application-secrets.properties
# edit application-secrets.properties with real values
mvn spring-boot:run "-Dspring-boot.run.profiles=secrets"
```

`application-secrets.properties` is gitignored — only the `.example` template (with
placeholder values) is committed, so anyone cloning the repo knows what to fill in without
ever seeing a real secret. This is a profile-specific override (Spring only loads
`application-secrets.properties` when the `secrets` profile is active), so its values take
precedence over `application.properties` regardless of what environment variables are set.
The key names in it must match the `${...}` placeholder names in `application.properties`
exactly (e.g. `DB_PASSWORD`, `JWT_SECRET`) — a key that doesn't match any placeholder is
silently ignored rather than causing an error, so double-check spelling if an override
doesn't seem to take effect.

If you'd rather use plain environment variables instead of a profile file (e.g. in CI or a
container), the same names are already wired up — see the Configuration table below.

### Prerequisites
- Java 17+
- Maven 3.9+
- PostgreSQL and Redis — the easiest way is the included `docker-compose.yml`:
  ```bash
  docker compose up -d
  ```
  This starts Postgres (`sawiya_auth_db` DB, `postgres`/`postgres`) on `5432` and Redis on
  `6379`. No manual DB setup needed — Hibernate creates the `users` table automatically
  (`ddl-auto: update`) on first run. Set `DB_URL` in your secrets file to
  `jdbc:postgresql://localhost:5432/sawiya_auth_db` to match.

  Already running Postgres or Redis another way (native install, another container)? Just
  point `DB_URL`/`REDIS_HOST`/`REDIS_PORT` at your own instances instead — `docker compose`
  is a convenience, not a requirement. If a container name collides with one you already
  have running (e.g. a `redis` container from another project already listening on 6379),
  either stop it first or just reuse it — the app doesn't care which container is answering
  on that port.

### Run

```bash
mvn spring-boot:run "-Dspring-boot.run.profiles=secrets"
```

The API starts on `http://localhost:8080`. Tests don't need Postgres or Redis running — the
test profile uses in-memory H2 and spins up an embedded Redis automatically.

### Run tests

```bash
mvn clean test
```

17 tests total: 6 unit tests (`AuthServiceTest`, Mockito-based), 6 integration tests
(`AuthControllerIntegrationTest`, full signup → signin → refresh → signout → `/me` flow via
`MockMvc`), and 5 resilience tests (`RedisCircuitBreakerTest`, proving the fail-open/fail-soft
behavior above). Integration and resilience tests spin up an embedded Redis instance
automatically (via `embedded-redis`), so no external Redis is required just to run the suite.

### Manual walkthrough (curl)

```bash
# 1. Sign up
curl -i -c cookies.txt -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"firstName":"Nethuni","lastName":"Rajapakse","email":"nethuni@example.com","password":"Password@123"}'

# 2. Sign in (cookies saved to cookies.txt)
curl -i -c cookies.txt -b cookies.txt -X POST http://localhost:8080/api/auth/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"nethuni@example.com","password":"Password@123"}'

# 3. Who am I (uses the access_token cookie)
curl -i -b cookies.txt http://localhost:8080/api/auth/me

# 4. Get a CSRF token (any prior response already set the XSRF-TOKEN cookie)
CSRF=$(grep XSRF-TOKEN cookies.txt | awk '{print $7}')

# 5. Sign out (needs the CSRF header - the cookie alone is not enough, by design)
curl -i -b cookies.txt -c cookies.txt -X POST http://localhost:8080/api/auth/signout \
  -H "X-XSRF-TOKEN: $CSRF"

# 6. Confirm the old access token no longer works
curl -i -b cookies.txt http://localhost:8080/api/auth/me   # -> 401
```

### Configuration

All security-sensitive and tunable values are environment-variable driven (see
`src/main/resources/application.properties`):

| Variable | Default | Purpose |
|---|---|---|
| `JWT_SECRET` | **required, no default** | HMAC signing key |
| `DB_URL` | **required, no default** | Full JDBC URL, e.g. `jdbc:postgresql://localhost:5432/sawiya_auth_db` |
| `DB_USERNAME` | **required, no default** | PostgreSQL username |
| `DB_PASSWORD` | **required, no default** | PostgreSQL password |
| `ACCESS_TOKEN_EXPIRY_MIN` | 15 | Access token lifetime (minutes) |
| `REFRESH_TOKEN_EXPIRY_DAYS` | 7 | Refresh token lifetime (days) |
| `COOKIE_SECURE` | false | Set `true` in production (HTTPS-only cookies) |
| `REDIS_HOST` / `REDIS_PORT` | localhost / 6379 | Redis connection |
| `CB_SLIDING_WINDOW_SIZE` | 10 | Circuit breaker: how many recent Redis calls it evaluates |
| `CB_MINIMUM_CALLS` | 5 | Circuit breaker: calls needed before it can open |
| `CB_FAILURE_RATE_THRESHOLD` | 50 | Circuit breaker: failure % that triggers OPEN |
| `CB_WAIT_DURATION_OPEN` | 10s | Circuit breaker: cooldown before a trial call |
| `CB_HALF_OPEN_CALLS` | 3 | Circuit breaker: trial calls allowed in HALF_OPEN |
| `CB_AUTO_TRANSITION_HALF_OPEN` | true | Circuit breaker: auto-retry after cooldown vs. staying OPEN |

## Project structure

```
src/main/java/com/sawiya/auth/
├── config/          # Security (SecurityConfig) & Redis configuration
├── constants/        # AppConstants - shared literals (cookie/CSRF/JWT-claim/Redis names,
│                      BCrypt strength, password policy) that are risky to duplicate
├── controller/       # REST endpoints
├── dto/              # Request/response payloads
├── entity/           # JPA entities
├── exception/        # Custom exceptions + global handler
├── filter/           # JWT authentication filter
├── repository/       # Spring Data JPA repositories
├── security/         # JWT service, cookie factory, config properties
└── service/          # Business logic (AuthService, token stores with circuit-breaker fallbacks)
```

## Design decisions at a glance

- **Signin returns a bare message, not user data** — minimizes what's exposed at the
  most brute-forced endpoint; identity lives behind `/me`.
- **No ID token** — this isn't an identity provider for third parties; a single
  access/refresh pair is enough for a first-party API.
- **Access-token denylist + refresh-token allow-list in Redis**, not a `tokenVersion`
  counter — supports per-session logout, not just "log out everywhere."
- **Refresh cookie scoped to `/api/auth`**, not `/` or `/api/auth/refresh` — reaches
  `/signout` (which must revoke it) without leaking it to non-auth endpoints.
- **CSRF via double-submit cookie**, with an explicit filter forcing Spring Security 6's
  lazy token to actually reach the client.
- **BCrypt work factor 12** — a deliberate CPU-cost/security trade-off above the library
  default.
- **Resilience4j circuit breaker around every Redis call** — fails open on reads (denylist
  and refresh-token checks) so an outage doesn't lock users out, fails soft on writes so
  signin/signout keep working; proven by a dedicated test that forces the breaker open.
