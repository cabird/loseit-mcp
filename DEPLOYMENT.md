# Deploying as a hosted MCP server

This service can run as a container behind Azure App Service (or any container
host), serving many Lose It! accounts from one instance over streamable HTTP.

> ⚠️ This proxies a **private, reverse-engineered API** using **users' real
> passwords**. Everything below assumes TLS-only exposure and a trusted
> operator. Do not run it on an untrusted network.

## Authentication model

The tricky part of hosting this is that Lose It has no OAuth, no API keys, and
no delegated-access story at all — the only credential is the account password.
So the client has to supply credentials, and the design question is what the
server does with them.

There are two ways in. Pick based on what your MCP client can do.

| | Request headers | Enrollment URL |
| --- | --- | --- |
| Client requirement | Must support custom headers | Only needs a URL |
| Password at rest on server | No | Yes, encrypted |
| Revocable without changing password | n/a | Yes |
| Credential visible in logs | Rarely (`Authorization` is usually redacted) | Yes — the URL path |

### Option 1 — request headers

Each request carries the caller's credentials, in either form:

```
Authorization: Basic base64(email:password)
```
```
X-LoseIt-Email: user@example.com
X-LoseIt-Password: ...
```

Claude.ai supports this via the **Request headers** field on a custom
connector, though at the time of writing that is a beta feature being rolled
out gradually — check whether your account has it before relying on it. Note
its allowlist of header names, so prefer `Authorization` and set the timezone
with `LOSEIT_HOURS_FROM_GMT` rather than a custom header.

### Option 2 — enrollment URL

For clients that can only be pointed at a URL. Enroll once:

```console
curl -X POST https://<host>/enroll \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"...","hours_from_gmt":-7,"ttl_days":90}'
```

```json
{
  "url": "https://<host>/u/<token>/mcp",
  "expires_in_days": 90,
  "note": "This URL is a credential and is shown only once. ..."
}
```

Point the client at that URL. Revoke it at any time:

```console
curl -X POST https://<host>/revoke -d '{"token":"<token>"}'
```

Revoking invalidates the URL and leaves your Lose It! password untouched.

#### The token is also the decryption key

The token is not your credentials — it is 256 bits of randomness. What gets
persisted is:

```
token T   (returned once, never stored)
  ├── lookup id  = HMAC(server_secret, T)      ← stored
  └── enc key    = HKDF(T, salt)               ← never stored
                   ciphertext = AES-GCM(credentials, key)   ← stored
```

The server can only decrypt a user's credentials while it is holding a request
that carries their token, so a stolen enrollment file is inert on its own.
Verified: the stored record contains no email, no password, and no token — only
an HMAC, a salt, a nonce, and ciphertext.

#### What this costs you

**The URL becomes a bearer credential, and URLs get logged** — Azure access
logs, Application Insights, any gateway in front. Anyone who reads that path
can act as you until the token is revoked. Mitigate by:

- treating the URL as a secret (no screenshots, issues, or chat logs)
- scrubbing or disabling request-path logging for `/u/*`
- keeping the default 90-day `ttl_days` so a leaked URL dies on its own
- revoking immediately if it leaks

Set `LOSEIT_ENROLL_SECRET` to require an `X-Enroll-Secret` header on `/enroll`,
so a public deployment isn't an open enrollment endpoint.

### Session caching (both options)

The server exchanges credentials for a `liauth` JWT once, then reuses it. The
JWT lasts 14 days, so a returning client costs no login at all — measured
against the running container, a cached call is ~10x faster than the first
(0.1s vs 1.0s). **You never re-enroll on that cycle**: when the JWT expires the
server re-logs-in from the credentials it already holds.

#### The cache key must include the password

This is the part worth getting right. The obvious design — cache the token
keyed by email — is an **authentication bypass**: anyone who knows an email
address would be handed that user's live session by sending any password.

So the key is `HMAC-SHA256(server_secret, email + "\0" + password)`. A wrong
password produces a different key, misses the cache, and falls through to a
real login, which then fails. This is verified against the running container:
requests with a wrong password are rejected even when a valid session for that
same email is already cached.

Passwords are never stored in the cache — only the HMAC and the resulting JWT.

### What is retained

| Value | Where | Lifetime |
| --- | --- | --- |
| HMAC of email+password | Process memory | Until eviction/restart |
| `liauth` JWT | Process memory | The JWT's own `exp` (~2 weeks) |
| Encrypted credentials | Enrollment store (URL mode only) | Until revoked or `ttl_days` |
| Password in plaintext | Never stored | — |

The session cache is bounded (default 1000 entries) so a hostile caller cannot
grow it without limit, and evicts expired entries first.

### Deliberate limits of this model

- **The server sees plaintext passwords.** Unavoidable given Lose It's API, but
  it means the operator is fully trusted. TLS is mandatory, not optional.
- **Session cache is per-instance and in-memory.** Scaling out means each
  instance authenticates independently. Setting `LOSEIT_CACHE_SECRET` keeps
  keys stable across instances, which is what a shared backend (Redis / Azure
  Cache) would need; the `TokenCache` interface is small enough to swap out.
- **No rate limiting.** A public deployment should sit behind a gateway that
  provides it, both to protect the instance and to avoid hammering Lose It.
- **Credentials in headers can land in access logs.** Prefer `Authorization`
  (commonly redacted) over the `X-LoseIt-*` headers, and make sure request
  logging does not capture headers.

## Local build and test

```console
docker build -t loseit-mcp:test .
docker run -d --name loseit-test -p 8900:8000 \
  -v loseit-data:/data \
  -e LOSEIT_CACHE_SECRET=<secret> \
  -e LOSEIT_ENROLLMENT=1 \
  -e LOSEIT_ENROLL_SECRET=<secret> \
  loseit-mcp:test
curl http://127.0.0.1:8900/healthz     # {"status":"ok"}
```

Or with compose:

```console
docker compose up --build
```

The image:

- is a two-stage build; the runtime carries no build tooling or package cache
- runs as an unprivileged `app` user
- contains **no credentials** — it starts fine with none configured
- writes enrollments to `/data`, declared as a volume so they outlive the
  container. Verified: an issued URL still works after `docker restart`.
- exposes `/healthz` for platform probes, which reports process liveness only
  (not Lose It reachability, so an upstream outage doesn't get healthy
  instances killed)
- fails fast at startup if the enrollment path is unwritable, rather than
  reporting healthy and then 500-ing on the first enrollment

Dependency resolution is layered ahead of the source copy, so editing code
skips the expensive step (cloning the git-sourced SDK and building wheels).
Measured: **3.3s** for a source-only rebuild versus 22.8s from cold.

## Azure App Service

Push the image to a registry, then point a Linux container Web App at it.

```console
az acr build --registry <registry> --image loseit-mcp:v1 .

az webapp create \
  --resource-group <rg> \
  --plan <plan> \
  --name <app-name> \
  --deployment-container-image-name <registry>.azurecr.io/loseit-mcp:v1

az webapp config appsettings set \
  --resource-group <rg> --name <app-name> \
  --settings LOSEIT_MULTI_TENANT=1 \
             WEBSITES_PORT=8000 \
             LOSEIT_CACHE_SECRET=<generated-secret> \
             LOSEIT_ENROLLMENT=1 \
             LOSEIT_ENROLL_SECRET=<generated-secret> \
             LOSEIT_ENROLLMENT_PATH=/home/loseit/enrollments.json \
             WEBSITES_ENABLE_APP_SERVICE_STORAGE=true \
             LOSEIT_HOURS_FROM_GMT=-7
```

Notes specific to App Service:

- `WEBSITES_PORT` must match the container's port; the app also honours `PORT`.
- `WEBSITES_ENABLE_APP_SERVICE_STORAGE=true` makes `/home` a persistent share.
  Point `LOSEIT_ENROLLMENT_PATH` there — the container filesystem is ephemeral,
  and every restart would otherwise orphan all issued URLs.
- Store `LOSEIT_CACHE_SECRET` and `LOSEIT_ENROLL_SECRET` in Key Vault and
  reference them, rather than inlining them in app settings.
- Enable **HTTPS Only** and set the minimum TLS version to 1.2. Credentials
  travel in headers or the URL path, so plaintext HTTP is not an acceptable
  fallback.
- Keep the app on a single instance unless a shared cache backend is added;
  otherwise each instance re-authenticates independently.
- Set **Always On** to avoid cold starts wiping the session cache.
- Scrub or disable request-path logging: enrollment tokens ride in the path.
  The app redacts its own logs, but Azure's platform logging is separate.

## Client configuration

With request headers:

```json
{
  "mcpServers": {
    "loseit": {
      "type": "http",
      "url": "https://<app-name>.azurewebsites.net/mcp",
      "headers": {
        "Authorization": "Basic <base64 of email:password>"
      }
    }
  }
}
```

With an enrollment URL (no headers needed):

```json
{
  "mcpServers": {
    "loseit": {
      "type": "http",
      "url": "https://<app-name>.azurewebsites.net/u/<token>/mcp"
    }
  }
}
```

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOSEIT_MULTI_TENANT` | `1` in the image | Take credentials from each request |
| `LOSEIT_ENROLLMENT` | unset | Enable `/u/<token>/mcp` URLs and `/enroll` |
| `LOSEIT_CACHE_SECRET` | random per process | HMAC secret; **required** for enrollment |
| `LOSEIT_ENROLLMENT_PATH` | `~/.config/loseit-mcp/enrollments.json` | Enrollment store location |
| `LOSEIT_ENROLL_SECRET` | unset | Require `X-Enroll-Secret` on `/enroll` |
| `PORT` | `8000` | Listen port |
| `LOSEIT_HOURS_FROM_GMT` | auto-detected | Default account UTC offset |
| `LOSEIT_STRONG_NAME` | current build | GWT permutation, if Lose It redeploys |
| `LOSEIT_POLICY_HASH` | current build | GWT policy hash, if Lose It redeploys |

`LOSEIT_CACHE_SECRET` is load-bearing for enrollment: it keys the lookup ids, so
changing it orphans every issued URL. Store it in Key Vault and treat it as
permanent. The server refuses to start enrollment without it, rather than
silently generating a random one that would break on restart.

The enrollment store must live somewhere persistent. On App Service that means
`/home` with `WEBSITES_ENABLE_APP_SERVICE_STORAGE=true`; the container
filesystem alone is ephemeral and users would have to re-enroll after every
restart.

## Per-user timezones

Containers run in UTC, so relative dates (`today` / `yesterday`) would
otherwise resolve against the container's clock rather than the caller's —
which logs food to the wrong day near midnight. Clients should send their
offset alongside their credentials:

```
X-LoseIt-Hours-From-GMT: -7
```

It falls back to `LOSEIT_HOURS_FROM_GMT`, then to the host clock. Setting the
env var is the right default for a single-timezone deployment; the header is
what makes a multi-region one correct.
