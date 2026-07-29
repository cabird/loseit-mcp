# Deploying as a hosted MCP server

This service runs as a container behind Azure App Service, serving one or more
Lose It! accounts over streamable HTTP. It writes nothing to disk.

> ⚠️ This proxies a **private, reverse-engineered API** using **users' real
> passwords**. Everything below assumes TLS-only exposure and a trusted
> operator. Do not run it on an untrusted network.

## Authentication

Lose It has no OAuth, no API keys, and no delegated access — the only
credential is the account password. So the client has to supply credentials,
and the design question is what the server does with them.

There are two ways in. Pick based on what your MCP client can do.

| | Request headers | Credential URL |
| --- | --- | --- |
| Client requirement | Must support custom headers | Only needs a URL |
| Credential visible in logs | Rarely (`Authorization` is usually redacted) | Yes — the URL path |
| Individually revocable | n/a (change the header) | No — see below |
| Server-side storage | None | None |

### Option 1 — request headers

Each request carries the caller's credentials:

```
Authorization: Basic base64(email:password)
```
```
X-LoseIt-Email: user@example.com
X-LoseIt-Password: ...
```

Claude.ai supports this via the **Request headers** field on a custom
connector, though that is a beta feature being rolled out gradually — check
whether your account has it before relying on it. It also restricts header
names to an allowlist, so prefer `Authorization` and set the timezone with
`LOSEIT_HOURS_FROM_GMT` rather than a custom header.

### Option 2 — credential URL

For clients that can only be pointed at a URL. Generate a server secret once:

```console
loseit-mcp gen-secret        # 43-char random value for LOSEIT_URL_SECRET
```

Then, from your machine, ask the server for a URL:

```console
loseit-mcp enroll https://<host>
```

It prompts for your Lose It! email and password and the server's
`LOSEIT_ENROLL_SECRET` — none of which are accepted as command-line flags,
since argv lands in shell history and process listings. Set `LOSEIT_EMAIL`,
`LOSEIT_PASSWORD`, or `LOSEIT_ENROLL_SECRET` in the environment to skip a
prompt.

```
Add this to your MCP client configuration:

  https://<host>/u/<sealed>/mcp

It stops working in 365 days.
```

The equivalent raw request, if you'd rather not use the CLI:

```console
curl -X POST https://<host>/enroll \
  -H 'x-enroll-secret: <LOSEIT_ENROLL_SECRET>' \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"...","hours_from_gmt":-7}'
```

Nothing is stored to produce the URL.

#### The URL carries the credentials, encrypted

```
key      = HKDF-SHA256(LOSEIT_URL_SECRET, info="loseit-mcp/sealed-url/v1")
sealed   = base64url( version || nonce || AES-GCM(key, {email, password, tz, expiry}) )
```

The server decrypts the URL on each request. There is **no database, no file,
and nothing to persist** — which means enrollments survive restarts and
redeploys for free, and the container filesystem can stay read-only.

The expiry lives *inside* the ciphertext, so it cannot be edited or extended
without the secret.

#### What this costs you

**Revocation is all-or-nothing.** There is no per-URL record to delete, so an
individual URL cannot be invalidated. Rotating `LOSEIT_URL_SECRET` invalidates
every issued URL at once, and everyone re-enrolls. For a personal deployment
that is a reasonable trade for deleting the entire storage layer; for a
multi-user one, it is not.

When a URL stops working — after a rotation or once it expires — tools return a
message telling the user to re-run `loseit-mcp enroll` and replace the URL in
their client config, rather than a bare decryption error.

`LOSEIT_URL_SECRET` must be a random value of at least 40 characters. It is the
key protecting every enrolled user's password, and because any sealed URL can
be tested against a guess offline, a memorable passphrase is not sufficient.
`loseit-mcp gen-secret` produces a suitable one; the server refuses to start
with anything weaker.

**The URL is a bearer credential, and URLs get logged** — Azure access logs,
Application Insights, any gateway in front. The app redacts `/u/<sealed>` from
its own logs, but Azure's platform logging is separate. Mitigate by:

- treating the URL as a secret (no screenshots, issues, or chat logs)
- scrubbing or disabling request-path logging for `/u/*`
- keeping a bounded `ttl_days` so a leaked URL dies on its own
- rotating `LOSEIT_URL_SECRET` if one leaks

`LOSEIT_ENROLL_SECRET` is required: an open `/enroll` on a public host lets
anyone mint working URLs for any account whose password they already have.

### Session caching (both options)

The server exchanges credentials for a `liauth` JWT once, then reuses it from
memory. The JWT lasts 14 days, so a returning client costs no login at all —
measured against the running container, a cached call is ~10x faster than the
first (0.1s vs 1.0s). **You never re-enroll on that cycle**: when the JWT
expires the server re-logs-in from the credentials it already holds. After a
restart the first request pays one login and the cache refills.

#### The cache key must include the password

The obvious design — cache the JWT keyed by email — is an **authentication
bypass**: anyone who knows an email address would be handed that user's live
session by sending any password.

So the key is `HMAC-SHA256(secret, email + "\0" + password)`. A wrong password
produces a different key, misses the cache, and falls through to a real login,
which then fails. Verified against the running container.

### What is retained

| Value | Where | Lifetime |
| --- | --- | --- |
| HMAC of email+password | Process memory | Until eviction/restart |
| `liauth` JWT | Process memory | The JWT's own `exp` (~2 weeks) |
| Credentials | **Nowhere** — only inside issued URLs | — |

The session cache is bounded (default 1000 entries) so a hostile caller cannot
grow it without limit, and evicts expired entries first.

### Deliberate limits

- **The server sees plaintext passwords.** Unavoidable given Lose It's API, but
  it means the operator is fully trusted. TLS is mandatory, not optional.
- **No per-URL revocation** (above).
- **No rate limiting.** A public deployment should sit behind a gateway that
  provides it, both to protect the instance and to avoid hammering Lose It.
- **Single instance assumed.** Scaling out works — the sealer is stateless — but
  each instance keeps its own session cache and authenticates independently.

## Local build and test

```console
docker build -t loseit-mcp:test .
docker run -d --name loseit-test -p 8900:8000 \
  -e LOSEIT_ENROLLMENT=1 \
  -e LOSEIT_URL_SECRET=<secret> \
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
- runs as an unprivileged `app` user and needs no writable filesystem
- contains **no credentials** — it starts fine with none configured
- exposes `/healthz` for platform probes, reporting process liveness only (not
  Lose It reachability, so an upstream outage doesn't get healthy instances
  killed)

Dependency resolution is layered ahead of the source copy, so editing code
skips the expensive step (cloning the git-sourced SDK and building wheels).
Measured: **3.3s** for a source-only rebuild versus 22.8s from cold.

## Azure App Service

Cheapest tier with Always On is **Linux B1** (~$13/month).

```console
az acr build --registry <registry> --image loseit-mcp:v1 .

az webapp create \
  --resource-group <rg> \
  --plan <plan> \
  --name loseit-mcp \
  --deployment-container-image-name <registry>.azurecr.io/loseit-mcp:v1

az webapp config appsettings set \
  --resource-group <rg> --name loseit-mcp \
  --settings LOSEIT_MULTI_TENANT=1 \
             WEBSITES_PORT=8000 \
             LOSEIT_ENROLLMENT=1 \
             LOSEIT_URL_SECRET=<generated-secret> \
             LOSEIT_ENROLL_SECRET=<generated-secret> \
             LOSEIT_HOURS_FROM_GMT=-7
```

Generate the secrets with:

```console
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Notes specific to App Service:

- `WEBSITES_PORT` must match the container's port; the app also honours `PORT`.
- **No persistent storage is needed.** Nothing is written to disk.
- Store both secrets in Key Vault and reference them rather than inlining them
  in app settings. `LOSEIT_URL_SECRET` is permanent: changing it invalidates
  every issued URL.
- Enable **HTTPS Only** and set the minimum TLS version to 1.2. Credentials
  travel in headers or the URL path, so plaintext HTTP is not an acceptable
  fallback.
- Set **Always On** so the session cache isn't wiped by idle shutdowns.
- Keep the *unique default hostname* option enabled — it makes the endpoint
  harder to stumble onto. It is not a security control; the credential is.
- Scrub or disable request-path logging: credential URLs ride in the path. The
  app redacts its own logs, but Azure's platform logging is separate.

## Client configuration

With request headers:

```json
{
  "mcpServers": {
    "loseit": {
      "type": "http",
      "url": "https://loseit-mcp.azurewebsites.net/mcp",
      "headers": {
        "Authorization": "Basic <base64 of email:password>"
      }
    }
  }
}
```

With a credential URL (no headers needed):

```json
{
  "mcpServers": {
    "loseit": {
      "type": "http",
      "url": "https://loseit-mcp.azurewebsites.net/u/<sealed>/mcp"
    }
  }
}
```

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOSEIT_MULTI_TENANT` | `1` in the image | Take credentials from each request |
| `LOSEIT_ENROLLMENT` | unset | Enable credential URLs and `POST /enroll` |
| `LOSEIT_URL_SECRET` | — | Seals/opens credential URLs. **Required** for enrollment |
| `LOSEIT_ENROLL_SECRET` | — | Required to call `/enroll`. **Required** for enrollment |
| `LOSEIT_CACHE_SECRET` | random per process | Session-cache key material |
| `PORT` | `8000` | Listen port |
| `LOSEIT_HOURS_FROM_GMT` | auto-detected | Default account UTC offset |
| `LOSEIT_STRONG_NAME` | current build | GWT permutation, if Lose It redeploys |
| `LOSEIT_POLICY_HASH` | current build | GWT policy hash, if Lose It redeploys |

## Per-user timezones

Containers run in UTC, so relative dates (`today` / `yesterday`) would otherwise
resolve against the container's clock rather than the caller's — logging food to
the wrong day near midnight. Set `LOSEIT_HOURS_FROM_GMT` for a single-timezone
deployment, seal `hours_from_gmt` into the URL at enrollment, or send:

```
X-LoseIt-Hours-From-GMT: -7
```

The header wins over the sealed value, which wins over the environment default.

## When Lose It changes their API

The upstream protocol is reverse-engineered and can change without notice. When
it does, tools return an explanation naming the likely cause and the settings an
operator needs to refresh (`LOSEIT_STRONG_NAME`, `LOSEIT_POLICY_HASH`), rather
than a decoder traceback — see `src/loseit_mcp/errors.py`.
