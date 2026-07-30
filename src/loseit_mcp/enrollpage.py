"""The self-service enrollment page.

Served as a single self-contained document: no external stylesheets, fonts, or
scripts. That is a privacy property, not a style preference — a third-party
asset on this page would hand a CDN a request log tied to someone about to type
their Lose It! password, and the whole point of the page is that nothing but
Lose It sees those credentials.

The page is static except for a per-request CSP nonce, so it carries no user
input and has nothing to escape. It is still served under a strict policy that
forbids remote loading outright, which is what keeps a future edit from quietly
introducing one.
"""

from __future__ import annotations

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "style-src 'nonce-{nonce}'; "
    "script-src 'nonce-{nonce}'; "
    "connect-src 'self'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

# `connect-src 'self'` is load-bearing: the form submits with fetch(), and
# without it `default-src 'none'` blocks the request and the page silently does
# nothing at all.
#
# `form-action 'none'` is equally deliberate: the form must never fall back to a
# native navigation, which would put the password in the URL — and therefore in
# every access log between here and the browser.
#
# Note also that a nonce does not whitelist inline `style="..."` attributes, only
# `<style>` elements. The page therefore carries no style attributes; adding one
# gets it silently dropped.

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Connect Lose It! to your AI assistant</title>
<style nonce="{nonce}">
  :root {{
    color-scheme: light dark;
    --bg: #fbfaf8; --card: #fff; --ink: #1a1a1a; --muted: #5c5c5c;
    --line: #e3e0da; --accent: #2f7d4f; --accent-ink: #fff;
    --warn-bg: #fff8e6; --warn-line: #e8d9a8; --warn-ink: #6b4e00;
    --err-bg: #fdeeee; --err-line: #f0c4c4; --err-ink: #8c2020;
    --code-bg: #f4f2ee;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #16171a; --card: #1e2024; --ink: #e9e8e6; --muted: #a3a19d;
      --line: #33363c; --accent: #4aa570; --accent-ink: #0d0f11;
      --warn-bg: #2a2413; --warn-line: #4d431f; --warn-ink: #e8d29a;
      --err-bg: #2c1a1a; --err-line: #522c2c; --err-ink: #f0b4b4;
      --code-bg: #14161a;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 2rem 1rem 4rem; background: var(--bg); color: var(--ink);
    font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }}
  main {{ max-width: 43rem; margin: 0 auto; }}
  h1 {{ font-size: 1.6rem; line-height: 1.25; margin: 0 0 .4rem; letter-spacing: -.01em; }}
  h2 {{ font-size: 1.05rem; margin: 2.2rem 0 .6rem; letter-spacing: -.005em; }}
  .sub {{ color: var(--muted); margin: 0 0 1.8rem; }}
  .card {{
    background: var(--card); border: 1px solid var(--line); border-radius: 12px;
    padding: 1.4rem;
  }}
  label {{ display: block; font-weight: 600; font-size: .92rem; margin: 0 0 .35rem; }}
  input {{
    width: 100%; padding: .65rem .75rem; font: inherit; color: var(--ink);
    background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
  }}
  input:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 1px; }}
  .field {{ margin-bottom: 1rem; }}
  .hint {{ color: var(--muted); font-size: .85rem; margin: .35rem 0 0; }}
  button {{
    font: inherit; font-weight: 600; padding: .7rem 1.2rem; border-radius: 8px;
    border: 1px solid transparent; background: var(--accent); color: var(--accent-ink);
    cursor: pointer;
  }}
  button[disabled] {{ opacity: .6; cursor: progress; }}
  button.secondary {{
    background: transparent; color: var(--ink); border-color: var(--line);
    font-weight: 500; padding: .45rem .8rem; font-size: .88rem;
  }}
  details {{ margin-top: 1rem; }}
  summary {{ cursor: pointer; font-size: .9rem; color: var(--muted); }}
  details .field {{ margin-top: .9rem; }}
  .note {{
    border: 1px solid var(--warn-line); background: var(--warn-bg); color: var(--warn-ink);
    border-radius: 10px; padding: .85rem 1rem; font-size: .9rem;
  }}
  .error {{
    border: 1px solid var(--err-line); background: var(--err-bg); color: var(--err-ink);
    border-radius: 10px; padding: .85rem 1rem; font-size: .92rem; margin-bottom: 1rem;
  }}
  code, .url {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .86rem;
  }}
  .url {{
    display: block; width: 100%; background: var(--code-bg); border: 1px solid var(--line);
    border-radius: 8px; padding: .8rem; word-break: break-all; color: var(--ink);
    margin: 0 0 .8rem;
  }}
  ul {{ padding-left: 1.15rem; }}
  li {{ margin: .35rem 0; }}
  .privacy li {{ margin: .55rem 0; }}
  .privacy strong {{ font-weight: 650; }}
  footer {{ margin-top: 2.5rem; color: var(--muted); font-size: .85rem; }}
  a {{ color: var(--accent); }}
  .flush {{ margin-top: 0; }}
  .spaced {{ margin-top: 1.1rem; }}
  [hidden] {{ display: none !important; }}
</style>
</head>
<body>
<main>
  <h1>Connect Lose It! to your AI assistant</h1>
  <p class="sub">
    Get a private link that lets Claude, ChatGPT, or any MCP client log your
    food and weight in Lose It!
  </p>

  <div class="card" id="form-card">
    <div class="error" id="error" hidden role="alert"></div>
    <form id="form" novalidate>
      <div class="field">
        <label for="email">Lose It! email</label>
        <input id="email" name="email" type="email" autocomplete="username"
               required autocapitalize="none" spellcheck="false">
      </div>
      <div class="field">
        <label for="password">Lose It! password</label>
        <input id="password" name="password" type="password"
               autocomplete="current-password" required>
        <p class="hint">
          Used once, right now, to check the login works — then discarded.
          See <a href="#privacy">what happens to it</a>.
        </p>
      </div>

      <details>
        <summary>Options</summary>
        <div class="field">
          <label for="ttl">Link expires after (days)</label>
          <input id="ttl" name="ttl_days" type="number" min="1" max="3650" value="{default_ttl}">
          <p class="hint">A shorter life limits the damage if the link leaks.</p>
        </div>
        <div class="field">
          <label for="tz">UTC offset in hours</label>
          <input id="tz" name="hours_from_gmt" type="number" min="-12" max="14"
                 placeholder="detected automatically">
          <p class="hint">Decides which day &ldquo;today&rdquo; means when logging.</p>
        </div>
      </details>

      <button type="submit" id="submit">Create my link</button>
    </form>
  </div>

  <div class="card" id="result" hidden>
    <h2 class="flush">Your private link</h2>
    <code class="url" id="url"></code>
    <button class="secondary" type="button" id="copy">Copy link</button>
    <button class="secondary" type="button" id="again">Start over</button>
    <p class="note spaced">
      <strong>Treat this link like a password.</strong> Anyone who has it can
      read and change your Lose It! diary. Paste it only into your AI client's
      settings, and don't post it anywhere. It expires in
      <span id="expiry"></span> days.
    </p>

    <h2>Add it to your client</h2>
    <ul>
      <li><strong>Claude</strong> &mdash; Settings &rarr; Connectors &rarr; Add
          custom connector, and paste the link.</li>
      <li><strong>ChatGPT</strong> &mdash; Settings &rarr; Connectors &rarr; add
          an MCP server, and paste the link.</li>
      <li><strong>Claude Code / other MCP clients</strong> &mdash; add it as a
          streamable-HTTP MCP server.</li>
    </ul>
    <p class="hint">
      No extra credentials to configure: the link authenticates by itself.
      Then try asking your assistant &ldquo;what did I eat today?&rdquo;
    </p>
  </div>

  <h2 id="privacy">What happens to your password</h2>
  <div class="card privacy">
    <ul>
      <li><strong>It is never saved on this server.</strong> It is used once, in
          memory, to confirm Lose It! accepts it &mdash; then it is gone. Nothing
          is written to any database or disk here, because there is no database.</li>
      <li><strong>It is encrypted into your link.</strong> This is the part worth
          understanding: your link contains your credentials, encrypted with a key
          only this server holds. That is how it works without an account system.
          The server can open it while serving your request; anyone who sees the
          link cannot. This also means <em>the link itself is as sensitive as your
          password</em>.</li>
      <li><strong>Your login token is never stored either.</strong> The token Lose
          It! returns is kept in memory only, so it can be reused for a few minutes
          instead of logging in on every request, and it disappears when the server
          restarts.</li>
      <li><strong>It never appears in logs.</strong> Request logs would normally
          record the full URL, so the credential-carrying part is stripped out
          before anything is written. The password is never logged in any form.</li>
      <li><strong>Nothing is shared with anyone.</strong> Your credentials go to
          Lose It! and nowhere else. This page loads no outside code, so no
          analytics or CDN sees you here.</li>
      <li><strong>To revoke a link,</strong> change your Lose It! password. That
          invalidates every link ever issued for your account.</li>
    </ul>
    <p class="hint spaced">
      Lose It! has no official API and no &ldquo;sign in with Lose It&rdquo;
      button, so a password is unfortunately the only way in. This project is
      open source &mdash; you can read exactly what it does, or run your own copy.
    </p>
  </div>

  <footer>
    <span id="version"></span>
    &middot; not affiliated with, or endorsed by, FitNow or Lose It!
  </footer>
</main>

<script nonce="{nonce}">
(function () {{
  var form = document.getElementById('form');
  var errorBox = document.getElementById('error');
  var submit = document.getElementById('submit');

  function showError(message) {{
    errorBox.textContent = message;
    errorBox.hidden = false;
  }}

  function numeric(id) {{
    var raw = document.getElementById(id).value.trim();
    if (raw === '') return null;
    var n = Number(raw);
    return Number.isFinite(n) ? n : null;
  }}

  form.addEventListener('submit', function (event) {{
    event.preventDefault();
    errorBox.hidden = true;

    var email = document.getElementById('email').value.trim();
    var password = document.getElementById('password').value;
    if (!email || !password) {{
      showError('Enter both your Lose It! email and password.');
      return;
    }}

    var body = {{ email: email, password: password }};
    var ttl = numeric('ttl');
    if (ttl !== null) body.ttl_days = ttl;
    var tz = numeric('tz');
    if (tz !== null) body.hours_from_gmt = tz;

    submit.disabled = true;
    submit.textContent = 'Checking your login\\u2026';

    fetch('enroll', {{
      method: 'POST',
      headers: {{ 'content-type': 'application/json' }},
      body: JSON.stringify(body)
    }}).then(function (response) {{
      return response.json().then(function (data) {{
        return {{ ok: response.ok, status: response.status, data: data }};
      }}).catch(function () {{
        return {{ ok: false, status: response.status, data: {{}} }};
      }});
    }}).then(function (result) {{
      if (!result.ok) {{
        showError(result.data.error || 'Something went wrong. Please try again.');
        return;
      }}
      // Drop the password from memory as soon as it has served its purpose.
      document.getElementById('password').value = '';
      form.reset();
      document.getElementById('url').textContent = result.data.url;
      document.getElementById('expiry').textContent = result.data.expires_in_days;
      document.getElementById('form-card').hidden = true;
      document.getElementById('result').hidden = false;
    }}).catch(function () {{
      showError('Could not reach the server. Check your connection and try again.');
    }}).then(function () {{
      submit.disabled = false;
      submit.textContent = 'Create my link';
    }});
  }});

  document.getElementById('copy').addEventListener('click', function () {{
    var button = this;
    var text = document.getElementById('url').textContent;
    var done = function () {{
      button.textContent = 'Copied';
      setTimeout(function () {{ button.textContent = 'Copy link'; }}, 1600);
    }};
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(text).then(done, function () {{
        button.textContent = 'Press Ctrl+C to copy';
      }});
    }} else {{
      button.textContent = 'Select the link and copy it';
    }}
  }});

  document.getElementById('again').addEventListener('click', function () {{
    document.getElementById('url').textContent = '';
    document.getElementById('result').hidden = true;
    document.getElementById('form-card').hidden = false;
  }});

  fetch('healthz').then(function (r) {{ return r.json(); }}).then(function (data) {{
    if (data && data.build && data.build.version) {{
      document.getElementById('version').textContent = 'v' + data.build.version;
    }}
  }}).catch(function () {{}});
}})();
</script>
</body>
</html>
"""


def render(nonce: str, default_ttl: int) -> str:
    """Render the page for one request."""
    return PAGE.format(nonce=nonce, default_ttl=default_ttl)
