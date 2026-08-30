# HomeSense Auth — Client Integration Guide

Reference for any client (React, React Native, native iOS/Android) integrating
with this backend's auth. All endpoints return/accept JSON — no cookies, no
platform-specific mechanism. Base path assumed: `/auth`.

## Token model

- **Access token** — JWT, 15 minute expiry. Send on every authenticated
  request as `Authorization: Bearer <access_token>`.
- **Refresh token** — JWT, 7 day expiry, also tracked server-side so it can
  be revoked. Used only to obtain a new token pair via `/auth/refresh`.
- **Rotation**: every call to `/auth/refresh` invalidates the refresh token
  that was used and returns a brand new access + refresh pair. The old
  refresh token cannot be reused — always store whatever refresh token you
  most recently received, discarding the previous one.
- Both tokens are returned together, from the same two endpoints
  (`/auth/signin` and `/auth/refresh`) — there is no separate "get a refresh
  token" step.

## Endpoints

### `POST /auth/signup`

Create an account. Does **not** log the user in — no tokens returned, call
`/auth/signin` after.

Request:
```json
{ "email": "user@example.com", "password": "..." }
```

Response `200`:
```json
{ "id": 1, "email": "user@example.com" }
```

Response `400`: `{ "detail": "Email already registered" }`

### `POST /auth/signin`

Verify credentials, issue a token pair.

Request:
```json
{ "email": "user@example.com", "password": "..." }
```

Response `200`:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

Response `400`: `{ "detail": "Invalid email or password" }` — returned
identically whether the email doesn't exist or the password is wrong. Don't
try to distinguish these cases in the UI beyond a single generic message.

### `GET /auth/me`

Any protected route follows this same pattern. Requires:
```
Authorization: Bearer <access_token>
```

Response `200`:
```json
{ "id": 1, "email": "user@example.com" }
```

Response `401`: token missing, malformed, expired, or the user no longer
exists. Treat any 401 here as "the access token is no longer usable" — see
the refresh flow below.

### `POST /auth/refresh`

Exchange a refresh token for a new pair.

Request:
```json
{ "refresh_token": "eyJ..." }
```

Response `200`: same shape as `/auth/signin` — a **new** `access_token` and
`refresh_token`. Overwrite whatever you had stored with both new values.

Response `401`: `{ "detail": "Invalid or expired refresh token" }` — the
refresh token was expired, already used (rotation), or explicitly revoked
(logout). This means the session is over: clear stored tokens and send the
user back to sign in. Do not retry.

### `POST /auth/logout`

Revoke a refresh token server-side.

Request:
```json
{ "refresh_token": "eyJ..." }
```

Response `200`: `{ "detail": "Logged out" }` — always succeeds regardless of
whether the token was already invalid. After calling this, discard all
locally stored tokens; the access token will keep working until it naturally
expires (max 15 minutes) since it isn't itself revocable, only the refresh
token is.

## The client-side flow

1. Sign up, then sign in → store `access_token` and `refresh_token`.
2. Attach `access_token` to every authenticated request.
3. On a `401` from any protected endpoint, attempt `POST /auth/refresh` with
   the stored `refresh_token`:
   - Success → replace both stored tokens with the new pair, retry the
     original request once.
   - Failure (`401`) → clear stored tokens, redirect to sign in. This is the
     "session truly expired" case.
4. On explicit logout, call `POST /auth/logout` with the current
   `refresh_token`, then clear local storage regardless of the response.

This same sequence is identical across every platform — the only thing that
differs per platform is *where* tokens are stored (see below).

## Storing tokens — per platform

Tokens are bearer credentials: anyone holding one can act as that user until
it expires or is revoked. Store them somewhere other apps/scripts on the
device can't casually read.

| Platform | Store tokens in |
|---|---|
| iOS (native or RN) | Keychain (`expo-secure-store` on Expo/RN, native Keychain APIs on Swift) |
| Android (native or RN) | Keystore-backed encrypted storage (`expo-secure-store` on RN, `EncryptedSharedPreferences` on Kotlin) |
| Web (React) | In-memory (a variable/store, lost on refresh) is safest; if persistence across reloads is required, `sessionStorage` is a smaller blast radius than `localStorage`, but neither is XSS-proof — this is a real tradeoff, not a solved problem |

Never store tokens in plain `localStorage`/`AsyncStorage` without encryption
if avoidable — those are readable by any JS/code running in the same
context, which is the exact thing an XSS or malicious-dependency
vulnerability would exploit.

## What the client never needs to do

- Never construct or decode a JWT's signature — that's entirely server-side.
  Decoding the payload just to read `exp` client-side (e.g. to preemptively
  refresh) is fine and common, but never trust a client-side decode as proof
  of anything; the server always re-verifies.
- Never send the refresh token on ordinary API requests — only to
  `/auth/refresh` and `/auth/logout`.
