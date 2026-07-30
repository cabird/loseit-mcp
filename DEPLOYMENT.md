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

It prompts for your Lose It! email and password — neither is accepted as a
command-line flag, since argv lands in shell history and process listings. Set
`LOSEIT_EMAIL` or `LOSEIT_PASSWORD` in the environment to skip a prompt.

```
Add this to your MCP client configuration:

  https://<host>/u/<sealed>/mcp

It stops working in 365 days.
```

The equivalent raw request, if you'd rather not use the CLI:

```console
curl -X POST https://<host>/enroll \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"...","hours_from_gmt":-7}'
```

Nothing is stored to produce the URL.

#### The enrollment page

`GET /` serves a self-service page where someone enters their Lose It! email
and password and gets their MCP URL back. It is a single self-contained
document — no external stylesheets, fonts, or scripts. That is a privacy
property rather than a style preference: a third-party asset here would hand a
CDN a request log tied to a person about to type their password.

It is served under a strict CSP (`default-src 'none'`), which forbids remote
loading outright so a later edit cannot quietly reintroduce it. Two directives
are load-bearing and easy to get wrong:

- `connect-src 'self'` — the form submits with `fetch()`. Without it the
  browser blocks the request and the page silently does nothing.
- `form-action 'none'` — the form must never fall back to a native navigation,
  which would put the password in the URL and therefore in every access log
  between the browser and here.

A nonce whitelists `<style>` elements but *not* `style="..."` attributes, so
the page carries none; adding one gets it silently dropped.

#### Enrollment is open, and credentials are checked

Anyone can enroll, because being able to enroll grants nothing: a sealed URL is
worthless without a working Lose It! account, so minting one gives the caller
no access they didn't already have.

Credentials **are** verified before a URL is issued. Skipping that check makes
for a genuinely baffling failure — the link looks fine and every tool call
fails, with nothing pointing at the typo that caused it.

The cost of verifying is that `/enroll` reports whether a password is valid.
That is mitigated, not ignored:

| Bucket | Default | Why |
| --- | --- | --- |
| per email address | 8 per 15 min | A targeted guesser rotates source addresses far more easily than the one account they care about, so this is the bucket that matters. |
| per client address | 5 per hour | Catches untargeted spraying across many accounts. |

The budget is spent *before* Lose It is contacted, so a throttled attempt never
reaches upstream. With both limits in place, guessing here is slower than
guessing against Lose It's own public login form — so this adds no capability
an attacker did not already have. Override the first with `LOSEIT_VERIFY_RATE`.

Lose It answers a bad email *or* a bad password with HTTP 404 and an
OAuth-style `invalid_grant` body — not the 401 you would expect — so the body,
not the status, decides whether a rejection is reported. Both cases are
byte-identical upstream, so enrollment cannot be used to discover whether an
account exists. A failure to *reach* Lose It is reported as 502, never as a
rejection: telling someone their password is wrong during an outage sends them
off to reset a password that was fine.

Set `LOSEIT_ENROLL_SECRET` to lock an instance down anyway; clients then send
it as an `X-Enroll-Secret` header. That is a reasonable choice for a private
deployment, but it is not what protects users' data — the URL secret is.

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

## Throttling

Requests are rate-limited with token buckets: a burst is allowed, then requests
are admitted at the refill rate. Every request is limited by client address, and
requests carrying a credential are limited by that too — both applicable budgets
must allow the request.

| Scope | Key | Default |
| --- | --- | --- |
| `/enroll` | address | 5 per hour |
| `/enroll` | email address | 8 per 15 minutes |
| tool calls | address | 120 per minute |
| tool calls | credential | 200 per minute |
| `/healthz` | — | exempt |

Enrollment is rare in normal use, so a tight budget costs nobody anything. Tool
calls are chatty during a conversation but a session-cache miss triggers an
upstream Lose It login, so that budget is generous rather than open.

**Why two keys.** An address is a weak identity: a client whose egress rotates
across a NAT pool gets one budget per address. This is not hypothetical — twelve
requests from one machine to this service arrived from six different addresses.
The credential a request carries does not rotate, so it gives a limit that
follows the *user* rather than the connection. The credential budget is set
above the address one so it acts as a backstop rather than a second ceiling a
normal client would notice. Credential keys are SHA-256 hashes; the credential
itself never enters the bucket store.

Override with `LOSEIT_ENROLL_RATE`, `LOSEIT_MCP_RATE`, and
`LOSEIT_CREDENTIAL_RATE`, written as `capacity/seconds` (e.g. `10/3600`).
Rejections return 429 with `Retry-After`.

Behind a proxy, the address comes from `X-Forwarded-For`, which accumulates left
to right — so the **rightmost** entries were added by infrastructure we control,
and the leftmost is whatever the client claimed. Reading the leftmost would let
anyone mint unlimited budget by sending a header, so the server counts back from
the right by `LOSEIT_TRUSTED_PROXIES` (default 1, correct for App Service).
Setting it to `0` means nothing is in front of the app, so the header is
entirely client-supplied and is ignored in favour of the socket address.

Throttling is applied to the path *after* sealed-URL rewriting, so
`/u/<sealed>/enroll` is charged the enrollment budget rather than the much
larger tool budget. This matters: the two layers previously disagreed, which
made the enrollment limit bypassable.

State is in memory and bounded to 10,000 tracked clients per bucket, evicting
idle entries first, so the throttle cannot itself be used to exhaust memory.
Scaling past one instance would want a shared store; the `Throttle` class is
small enough to swap.

This is not a DDoS defence — it protects a small instance from casual abuse and
keeps us from hammering Lose It. Genuinely hostile load belongs behind a gateway
or WAF.

## Checking what is deployed

`/healthz` reports the running build and how the server resolved the caller's
address:

```console
curl https://<host>/healthz
```

```json
{
  "status": "ok",
  "build": {
    "version": "0.3.6",
    "commit": "2e39845",
    "built_at": "2026-07-29T14:56:02Z",
    "image_tag": "v4"
  },
  "client": { "resolved": "203.0.113.7", "trusted_proxies": 1 }
}
```

The build stamp makes "is my change actually live?" answerable from outside the
box instead of inferred from logs. The `client` block exposes the one piece of
state that behaves differently behind a proxy and is otherwise invisible — it is
what rate limiting keys on.

Stamp the values at build time:

```console
docker build \
  --build-arg BUILD_COMMIT=$(git rev-parse --short HEAD) \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --build-arg BUILD_TAG=v5 \
  -t <registry>.azurecr.io/loseit-mcp:v5 .
```

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
- **Throttling is not a DDoS defence.** It protects a small instance from
  casual abuse and keeps us from hammering Lose It; genuinely hostile load
  belongs behind a gateway.
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

Cheapest tier with Always On is **Linux B1** (~$13/month). A container registry
(~$5) and Key Vault (~$0.03) bring the total to roughly **$18/month**.

The walkthrough below uses placeholder names — substitute your own. Registry
names must be globally unique and alphanumeric only; Key Vault names must be
globally unique.

### 1. Resource group

```console
az group create --name loseit-mcp-rg --location westus
```

> **Check your B1 quota first.** Some subscriptions have zero App Service quota
> in a given region — the plan creation below fails with a quota message rather
> than anything obviously region-related. If that happens, try another region;
> nothing here is region-specific.

### 2. Container registry, and push the image

```console
az acr create --resource-group loseit-mcp-rg --name <registry> \
  --sku Basic --admin-enabled true

az acr login --name <registry>
docker build -t <registry>.azurecr.io/loseit-mcp:v1 .
docker push <registry>.azurecr.io/loseit-mcp:v1
```

> **Build locally, not with `az acr build`.** ACR's classic build agent has no
> BuildKit, so the `--mount=type=cache` directives in the Dockerfile fail there.

### 3. App Service plan and web app

```console
az appservice plan create --name loseit-mcp-plan \
  --resource-group loseit-mcp-rg --location westus --is-linux --sku B1

az webapp create \
  --resource-group loseit-mcp-rg \
  --plan loseit-mcp-plan \
  --name <app-name> \
  --container-image-name <registry>.azurecr.io/loseit-mcp:v1 \
  --container-registry-url https://<registry>.azurecr.io \
  --assign-identity '[system]'
```

> **Verify the image name afterwards.** Some CLI versions prepend the registry
> to an already-qualified image, producing
> `<registry>.azurecr.io/<registry>.azurecr.io/loseit-mcp:v1` and a 503 that
> looks like an app failure. Check and correct with:
>
> ```console
> az webapp config container show --resource-group loseit-mcp-rg --name <app-name>
> az webapp config container set --resource-group loseit-mcp-rg --name <app-name> \
>   --container-image-name <registry>.azurecr.io/loseit-mcp:v1 \
>   --container-registry-url https://<registry>.azurecr.io
> ```

Let the app pull from the registry with its identity, rather than storing admin
credentials:

```console
az role assignment create \
  --assignee $(az webapp identity show --name <app-name> \
      --resource-group loseit-mcp-rg --query principalId -o tsv) \
  --scope $(az acr show --name <registry> --query id -o tsv) \
  --role AcrPull
```

### 4. Secrets in Key Vault

```console
loseit-mcp gen-secret        # run once for the URL secret

az keyvault create --name <vault> --resource-group loseit-mcp-rg \
  --location westus --enable-rbac-authorization true

az role assignment create --assignee <your-user-object-id> \
  --scope $(az keyvault show --name <vault> --query id -o tsv) \
  --role "Key Vault Secrets Officer"

az keyvault secret set --vault-name <vault> --name loseit-url-secret --value <secret>

az role assignment create \
  --assignee $(az webapp identity show --name <app-name> \
      --resource-group loseit-mcp-rg --query principalId -o tsv) \
  --scope $(az keyvault show --name <vault> --query id -o tsv) \
  --role "Key Vault Secrets User"
```

Add a second secret for `LOSEIT_ENROLL_SECRET` only if you want to restrict who
may enroll; it is optional.

### 5. App settings

```console
az webapp config appsettings set \
  --resource-group loseit-mcp-rg --name <app-name> \
  --settings LOSEIT_MULTI_TENANT=1 \
             LOSEIT_ENROLLMENT=1 \
             WEBSITES_PORT=8000 \
             LOSEIT_HOURS_FROM_GMT=-7 \
             LOSEIT_ALLOWED_HOSTS=<app-name>.azurewebsites.net \
             "LOSEIT_URL_SECRET=@Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/loseit-url-secret/)"
```

> **`LOSEIT_ALLOWED_HOSTS` is not optional.** The MCP transport validates the
> `Host` header against an allowlist that defaults to localhost, so without it
> every MCP request returns `421 Invalid Host header`. The app reads
> `WEBSITE_HOSTNAME` automatically, which covers App Service — set this
> explicitly if you use a custom domain, or to be certain.
>
> This failure is easy to misdiagnose: `/healthz` and `/enroll` keep working
> because they are plain Starlette routes. Only the MCP endpoint fails.

### 6. Harden and start

```console
az webapp config set --resource-group loseit-mcp-rg --name <app-name> \
  --always-on true --min-tls-version 1.2 --http20-enabled true
az webapp update --resource-group loseit-mcp-rg --name <app-name> --https-only true
az webapp restart --resource-group loseit-mcp-rg --name <app-name>
```

### 7. Verify

```console
curl https://<app-name>.azurewebsites.net/healthz          # {"status":"ok"}
curl -X POST https://<app-name>.azurewebsites.net/enroll \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"..."}'        # 201 with a URL
```

Then get a URL and use it:

```console
loseit-mcp enroll https://<app-name>.azurewebsites.net --tz -7
```

The first request after a restart takes a few seconds (container start plus a
Lose It login); subsequent ones are fast.

### Redeploying

```console
docker build -t <registry>.azurecr.io/loseit-mcp:v2 .
docker push <registry>.azurecr.io/loseit-mcp:v2
az webapp config container set --resource-group loseit-mcp-rg --name <app-name> \
  --container-image-name <registry>.azurecr.io/loseit-mcp:v2 \
  --container-registry-url https://<registry>.azurecr.io
az webapp restart --resource-group loseit-mcp-rg --name <app-name>
```

Rolling the image tag rather than reusing `:latest` makes it obvious which
build is live and lets you point back at the previous tag to roll back.

### Other notes

- **No persistent storage is required.** Nothing is written to disk, so the
  container filesystem can stay read-only.
- Keep the *unique default hostname* option enabled — it makes the endpoint
  harder to stumble onto. It is not a security control; the credential is.
- Scrub or disable request-path logging: credential URLs ride in the path. The
  app redacts its own logs, but Azure's platform logging is separate.
- Teardown is `az group delete --name loseit-mcp-rg --yes`. Key Vault
  soft-delete keeps the vault name reserved for 90 days afterwards.

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

With a credential URL (no headers needed):

```json
{
  "mcpServers": {
    "loseit": {
      "type": "http",
      "url": "https://<app-name>.azurewebsites.net/u/<sealed>/mcp"
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
| `LOSEIT_ENROLL_SECRET` | unset | Optional. Restricts `/enroll` to holders of this value |
| `LOSEIT_ENROLL_RATE` | `5/3600` | `/enroll` budget per address, as `capacity/seconds` |
| `LOSEIT_VERIFY_RATE` | `8/900` | Sign-in attempts per email address during enrollment |
| `LOSEIT_MCP_RATE` | `120/60` | Tool-call budget per address |
| `LOSEIT_CREDENTIAL_RATE` | `200/60` | Tool-call budget per credential |
| `LOSEIT_TRUSTED_PROXIES` | `1` | Proxies in front of the app, for client-IP resolution |
| `LOSEIT_CACHE_SECRET` | random per process | Session-cache key material |
| `LOSEIT_ALLOWED_HOSTS` | `WEBSITE_HOSTNAME`, else localhost | Comma-separated hostnames the MCP endpoint will answer on |
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
