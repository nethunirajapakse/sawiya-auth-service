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
  (`refresh_token`), scoped to `/api/auth/refresh` only, so it isn't sent on every request.
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

CSRF is **not** required on:
- `/signup` and `/signin` — no session/cookie exists yet at that point; these are
  credential-based requests, not cookie-authenticated ones.
- `GET /me` — CSRF only protects against attacker-triggered *state changes*; a read-only
  GET has nothing for CSRF to protect.

It **is** required on `/refresh` and `/signout`, since both act on the caller's existing
cookie-based session.

## Password policy

Enforced via Bean Validation on signup:
- Minimum 8 characters
- At least one uppercase letter, one lowercase letter, one digit, and one special character
  (`@$!%*?&#^()_+-=`)

Passwords are hashed with BCrypt at a work factor of **12** — a deliberate CPU-cost/security
trade-off (higher than the library default of 10) chosen to slow down offline brute-force
attempts on a leaked hash while remaining fast enough for normal login latency.

## Scalability notes

- The core auth flow is stateless (JWT + Redis lookups only), so the API can scale
  horizontally behind a load balancer with no sticky sessions required.
- The one deliberately-not-built-here improvement: at very high request volumes, even the
  Redis denylist check is an extra network hop per request. A further optimization would be
  a local in-memory cache (e.g. Caffeine) of recently-seen denylisted `jti`s in front of
  Redis, invalidated via Redis pub/sub — not implemented here to keep the assignment's scope
  proportionate to a 7-day take-home.

## Running locally

### Local secrets (recommended over relying on the dev-only defaults)

`application.properties` falls back to hardcoded dev values (e.g. `JWT_SECRET` defaults to
a placeholder) so the project runs out of the box, but you shouldn't rely on that beyond
local testing. To use real secrets without ever committing them:

```powershell
copy src\main\resources\application-secrets.properties.example src\main\resources\application-secrets.properties
# edit application-secrets.properties with a real JWT secret and DB password
mvn spring-boot:run "-Dspring-boot.run.profiles=secrets"
```

`application-secrets.properties` is gitignored — only the `.example` template (with
placeholder values) is committed, so anyone cloning the repo knows what to fill in without
ever seeing a real secret. This is a profile-specific override (Spring only loads
`application-secrets.properties` when the `secrets` profile is active), so its values take
precedence over the defaults in `application.properties` regardless of what environment
variables are set. The key names in it must match the `${...}` placeholder names used in
`application.properties` exactly (e.g. `DB_PASSWORD`, `JWT_SECRET`) — a key that doesn't
match any placeholder is silently ignored rather than causing an error, so double-check
spelling if an override doesn't seem to take effect.

If you'd rather use plain environment variables instead of a profile file (e.g. in CI or a
container), the same properties are already wired to `JWT_SECRET`, `DB_USERNAME`,
`DB_PASSWORD`, etc. — see the Configuration table below.

### Prerequisites
- Java 17+
- Maven 3.9+
- PostgreSQL and Redis — the easiest way is the included `docker-compose.yml`:
  ```bash
  docker compose up -d
  ```
  This starts Postgres (`sawiya_auth` DB, `postgres`/`postgres`) on `5432` and Redis on
  `6379`. No manual DB setup needed — Hibernate creates the `users` table automatically
  (`ddl-auto: update`) on first run.

  Prefer to run Postgres/Redis yourself instead of Docker? Just set the env vars below to
  point at your own instances.

### Run

```bash
mvn spring-boot:run
```

The API starts on `http://localhost:8080` and connects to Postgres/Redis using the
`DB_*`/`REDIS_*` environment variables described below (defaulting to the docker-compose
values). Tests don't need Postgres or Redis running — the test profile uses in-memory H2
and spins up an embedded Redis automatically.

### Run tests

```bash
mvn test
```

Integration tests spin up an embedded Redis instance automatically (via
`embedded-redis`), so no external Redis is required just to run the test suite.

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

# 4. Get a CSRF token (GET requests set the XSRF-TOKEN cookie)
CSRF=$(grep XSRF-TOKEN cookies.txt | awk '{print $7}')

# 5. Sign out (needs the CSRF header)
curl -i -b cookies.txt -c cookies.txt -X POST http://localhost:8080/api/auth/signout \
  -H "X-XSRF-TOKEN: $CSRF"

# 6. Confirm the old access token no longer works
curl -i -b cookies.txt http://localhost:8080/api/auth/me   # -> 401
```

### Configuration

All security-sensitive values are environment-variable driven (see
`src/main/resources/application.properties`):

| Variable | Default | Purpose |
|---|---|---|
| `JWT_SECRET` | dev-only placeholder | HMAC signing key — **must** be overridden in any real deployment |
| `ACCESS_TOKEN_EXPIRY_MIN` | 15 | Access token lifetime (minutes) |
| `REFRESH_TOKEN_EXPIRY_DAYS` | 7 | Refresh token lifetime (days) |
| `COOKIE_SECURE` | false | Set `true` in production (HTTPS-only cookies) |
| `DB_HOST` / `DB_PORT` / `DB_NAME` | localhost / 5432 / sawiya_auth | PostgreSQL connection |
| `DB_USERNAME` / `DB_PASSWORD` | postgres / postgres | PostgreSQL credentials |
| `REDIS_HOST` / `REDIS_PORT` | localhost / 6379 | Redis connection |

## Project structure

```
src/main/java/com/sawiya/auth/
├── config/          # Security & Redis configuration
├── controller/       # REST endpoints
├── dto/              # Request/response payloads
├── entity/           # JPA entities
├── exception/        # Custom exceptions + global handler
├── filter/           # JWT authentication filter
├── repository/       # Spring Data JPA repositories
├── security/         # JWT service, cookie factory, config properties
└── service/          # Business logic (AuthService, token stores)
```

## Note on this submission's environment

This project was scaffolded in a sandboxed environment without access to Maven Central, so
`mvn compile`/`mvn test` could not be executed here to verify a clean build end-to-end.
Please run `mvn clean test` locally as a first step — happy to fix anything that surfaces.
