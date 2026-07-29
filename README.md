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

## CLI

The same operations are available directly, which is the easiest way to test:

```console
loseit-mcp search "greek yogurt" -n 5
loseit-mcp describe <food_id>
loseit-mcp diary 2026-07-25
loseit-mcp log <food_id> -m lunch -a 120 -u g
loseit-mcp log-custom "Caesar Salad" 620 -m lunch -b "Gastrohub" -p 46 -c 18 -f 40
loseit-mcp weigh 199.2
loseit-mcp delete <entry_id> -d 2026-07-25
```

Add `--dry-run` to either log command to preview the math without writing, and
`--json` for machine-readable output.

## Notes

- Deleting writes a recoverable copy to local trash before the wire call.
- Weights carry no unit over the wire; the number is interpreted in whatever
  unit the account displays (lb or kg).
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
