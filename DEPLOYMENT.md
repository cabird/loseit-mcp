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

### How it works

Each request carries the caller's credentials, in either form:

```
Authorization: Basic base64(email:password)
```
```
X-LoseIt-Email: user@example.com
X-LoseIt-Password: ...
```

The server exchanges those for a `liauth` JWT once, then reuses it. The JWT is
valid for roughly two weeks, so a returning client costs no login at all —
measured against the running container, a cached call is ~10x faster than the
first (0.1s vs 1.0s).

### The cache key must include the password

This is the part worth getting right. The obvious design — cache the token
keyed by email — is an **authentication bypass**: anyone who knows an email
address would be handed that user's live session by sending any password.

So the key is `HMAC-SHA256(server_secret, email + "\0" + password)`. A wrong
password produces a different key, misses the cache, and falls through to a
real login, which then fails. This is verified by a test in the container run:
requests with a wrong password are rejected even when a valid session for that
same email is already cached.

Passwords are never stored — only the HMAC and the resulting JWT.

### What is retained

| Value | Where | Lifetime |
| --- | --- | --- |
| HMAC of email+password | Process memory | Until eviction/restart |
| `liauth` JWT | Process memory | The JWT's own `exp` (~2 weeks) |
| Password | Never stored | — |

The cache is bounded (default 1000 entries) so a hostile caller cannot grow it
without limit, and evicts expired entries first.

### Deliberate limits of this model

- **The server sees plaintext passwords.** Unavoidable given Lose It's API, but
  it means the operator is fully trusted. TLS is mandatory, not optional.
- **Cache is per-instance and in-memory.** Scaling out means each instance
  authenticates independently. Setting `LOSEIT_CACHE_SECRET` keeps keys stable
  across instances, which is what a shared backend (Redis / Azure Cache) would
  need; the `TokenCache` interface is small enough to swap out.
- **No rate limiting.** A public deployment should sit behind a gateway that
  provides it, both to protect the instance and to avoid hammering Lose It.
- **Credentials in headers can land in access logs.** Prefer `Authorization`
  (commonly redacted) over the `X-LoseIt-*` headers, and make sure request
  logging does not capture headers.

## Local build and test

```console
docker build -t loseit-mcp:test .
docker run -d --name loseit-test -p 8900:8000 loseit-mcp:test
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
- exposes `/healthz` for platform probes, which reports process liveness only
  (not Lose It reachability, so an upstream outage doesn't get healthy
  instances killed)

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
             LOSEIT_CACHE_SECRET=<generated-secret>
```

Notes specific to App Service:

- `WEBSITES_PORT` must match the container's port; the app also honours `PORT`.
- Store `LOSEIT_CACHE_SECRET` in Key Vault and reference it, rather than
  inlining it in app settings.
- Enable **HTTPS Only** and set the minimum TLS version to 1.2. Credentials
  travel in headers, so plaintext HTTP is not an acceptable fallback.
- Keep the app on a single instance unless a shared cache backend is added;
  otherwise each instance re-authenticates independently.
- Set **Always On** to avoid cold starts wiping the token cache.

## Client configuration

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

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOSEIT_MULTI_TENANT` | `1` in the image | Take credentials from request headers |
| `PORT` | `8000` | Listen port |
| `LOSEIT_CACHE_SECRET` | random per process | Pins cache keys across restarts |
| `LOSEIT_HOURS_FROM_GMT` | auto-detected | Default account UTC offset |
| `LOSEIT_STRONG_NAME` | current build | GWT permutation, if Lose It redeploys |
| `LOSEIT_POLICY_HASH` | current build | GWT policy hash, if Lose It redeploys |

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
