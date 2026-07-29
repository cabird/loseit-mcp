# loseit-mcp

An MCP server and CLI for logging food to [Lose It!](https://www.loseit.com/).

> ⚠️ **Unofficial.** Lose It! publishes no public API. This talks to the private
> GWT-RPC endpoint used by the Lose It! web app, so it can break whenever they
> ship a new web build.

## Tools

| Tool | Description |
| --- | --- |
| `search_food` | Search the food database; returns `food_id`s |
| `describe_food` | Full nutrition and serving detail for one food |
| `get_diary` | A day's entries with calories and macros, plus totals |
| `log_food` | Log a database food to a meal |
| `log_custom_food` | Log arbitrary calories/macros with no database match |
| `log_weight` | Record a weigh-in |
| `get_weight_history` | Read weigh-ins over a range, with min/max/change |
| `delete_entry` | Delete a diary entry |
| `whoami` | Show the authenticated account |

`log_custom_food` exists because `updateFoodLogEntry` carries the food's name,
brand, and nutrient map inline — so an entry can describe a food the database
has never heard of. Use it for restaurant meals, homemade dishes, or any
portion where forcing a database match would distort the numbers.

## Setup

```console
uv sync
cp .env.example .env   # then fill in your credentials
```

## Configuration

Settings resolve in priority order: **CLI flags → environment → `.env` → JSON
config file → defaults**.

| Variable | Required | Description |
| --- | --- | --- |
| `LOSEIT_EMAIL` | yes\* | Lose It! account email |
| `LOSEIT_PASSWORD` | yes\* | Lose It! account password |
| `LOSEIT_TOKEN` | no | A `liauth` JWT, used instead of email/password |
| `LOSEIT_HOURS_FROM_GMT` | no | UTC offset in whole hours; auto-detected |
| `LOSEIT_STRONG_NAME` | no | GWT permutation, if Lose It ships a new build |
| `LOSEIT_POLICY_HASH` | no | GWT policy hash, if Lose It ships a new build |

\* Not required if `LOSEIT_TOKEN` is set.

`.env` is gitignored. The session token is cached at
`~/.config/loseit-mcp/session.json` with owner-only permissions and refreshes
automatically when it expires.

## Running the server

```console
loseit-mcp serve                                  # stdio (default)
loseit-mcp serve --transport streamable-http --port 8000
```

Register the stdio server with an MCP client:

```json
{
  "mcpServers": {
    "loseit": {
      "command": "uv",
      "args": ["run", "loseit-mcp", "serve"],
      "cwd": "/absolute/path/to/loseit-mcp"
    }
  }
}
```

To host one server for multiple accounts, see [DEPLOYMENT.md](DEPLOYMENT.md).

## CLI

The same operations are available directly, which is the easiest way to test:

```console
loseit-mcp search "greek yogurt" -n 5
loseit-mcp describe <food_id>
loseit-mcp diary 2026-07-25
loseit-mcp log <food_id> -m lunch -a 120 -u g
loseit-mcp log-custom "Caesar Salad" 620 -m lunch -b "Gastrohub" -p 46 -c 18 -f 40
loseit-mcp weigh 199.2
loseit-mcp weights -n 14
loseit-mcp delete <entry_id> -d 2026-07-25
```

Add `--dry-run` to either log command to preview the math without writing, and
`--json` for machine-readable output.

Two more, for hosted deployments:

```console
loseit-mcp gen-secret                      # a secret for LOSEIT_URL_SECRET
loseit-mcp enroll https://<host>           # get a credential URL for a client
```

## Notes

- Deleting writes a recoverable copy to local trash before the wire call.
- When Lose It changes their private API, tools return an explanation of what
  broke and what the operator needs to refresh, rather than a decoder
  traceback — see `errors.py`.
- Hosted deployments rate-limit per client address *and* per credential, since
  an address alone is a weak identity behind a NAT pool.
- `/healthz` reports the running version and commit, so you can tell what is
  actually deployed without reading logs.
- Weights carry no unit over the wire; the number is interpreted in whatever
  unit the account displays (lb or kg).
- **`saturated_fat_g` is not recorded.** The upstream SDK's payload builder
  filters that nutrient ordinal out, so `log_custom_food` reports it in an
  `ignored_nutrients` field rather than claiming to have logged it. Every other
  macro goes through.
- Weight history is fetched in windows and bisected further when a response is
  too large for the SDK decoder — an unchunked year-long query would otherwise
  silently return "no weigh-ins".
- Relative dates (`today` / `yesterday`) resolve in the *account's* timezone,
  not the host's, so a server in another region doesn't log to the wrong day.
- Fractional portions of database foods can display a misleading unit (half a
  banana rendering as "1/4 Each") because the server's canonical serving count
  differs from the food's native unit. Calories stay correct, but `log-custom`
  is the more predictable route for odd portions.

## Architecture

The GWT-RPC wire format is handled by the
[`phitoduck/lose-it`](https://github.com/phitoduck/lose-it) SDK. This project
adds email/password authentication (the SDK expects you to supply a JWT
yourself, and its browser-cookie import does not support Windows), the
custom-food logging path, weight recording via `saveRecordedWeight` (captured
from the web app's weigh-in widget), and the MCP server and CLI layers.

## License

[0BSD](LICENSE) — the BSD Zero Clause License. Use it, change it, ship it,
sell it. No attribution, no notice, no conditions of any kind.

This is deliberate. **If FitNow (the makers of Lose It!) want any part of this,
they should take it and treat it as their own** — no permission needed, nothing
to negotiate, no obligation to credit me. The same goes for anyone else.

Two things a license cannot do, stated plainly:

- **Trademark is separate.** "Lose It!" is a registered trademark of FitNow,
  Inc. This project is unofficial and unaffiliated; the license grants no rights
  in their marks.
- **Dependencies keep their own terms.** They are all permissive (MIT, BSD-3,
  Apache-2.0), but the `lose-it` SDK is MIT and asks that its copyright notice
  be preserved. Anyone vendoring this code should either keep that notice or
  replace the dependency.
