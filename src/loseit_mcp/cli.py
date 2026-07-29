"""Command-line interface.

Two roles:

- ``loseit-mcp serve`` runs the MCP server over stdio (default) or
  streamable HTTP.
- The remaining commands (``search``, ``diary``, ``log``, ``delete``, …) call
  the same service layer directly, so you can exercise every operation without
  an MCP client in the loop.

Credentials resolve from CLI flags, then environment, then ``.env``, then a
JSON config file — see :mod:`loseit_mcp.config`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from .config import ConfigError, Settings, load_settings
from .sealed import UrlSealer
from .service import LoseItService


def _add_credential_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("credentials")
    group.add_argument("--email", help="Lose It! account email.")
    group.add_argument("--password", help="Lose It! account password.")
    group.add_argument("--token", help="A liauth JWT, used instead of email/password.")
    group.add_argument("--config", type=Path, help="Path to a JSON config file.")
    group.add_argument("--env-file", type=Path, help="Path to a .env file.")
    group.add_argument(
        "--hours-from-gmt",
        type=int,
        help="UTC offset in whole hours (auto-detected by default).",
    )


def _settings_from_args(args: argparse.Namespace) -> Settings:
    return load_settings(
        config_file=getattr(args, "config", None),
        env_file=getattr(args, "env_file", None),
        email=getattr(args, "email", None),
        password=getattr(args, "password", None),
        token=getattr(args, "token", None),
        hours_from_gmt=getattr(args, "hours_from_gmt", None),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loseit-mcp",
        description="MCP server and CLI for the Lose It! food diary.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit raw JSON instead of formatted text.",
    )
    _add_credential_flags(parser)

    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the MCP server.")
    serve.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "sse"),
        default="stdio",
        help="Transport to serve on (default: stdio).",
    )
    serve.add_argument("--host", default="127.0.0.1", help="Bind host for HTTP transports.")
    serve.add_argument("--port", type=int, default=8000, help="Bind port for HTTP transports.")
    serve.add_argument("--path", default="/mcp", help="URL path for streamable HTTP.")
    serve.add_argument(
        "--multi-tenant",
        action="store_true",
        default=os.environ.get("LOSEIT_MULTI_TENANT", "").lower() in ("1", "true", "yes"),
        help=(
            "Take Lose It! credentials from each request's headers instead of the "
            "environment. Required for hosting one server for multiple accounts."
        ),
    )

    sub.add_parser("whoami", help="Show the authenticated account.")

    search = sub.add_parser("search", help="Search the food database.")
    search.add_argument("query", help="Food name to search for.")
    search.add_argument("-n", "--limit", type=int, default=10, help="Max results.")

    describe = sub.add_parser("describe", help="Show nutrition detail for a food.")
    describe.add_argument("food_id", help="32-character hex food ID.")

    diary = sub.add_parser("diary", help="Show the food log for a day.")
    diary.add_argument(
        "date",
        nargs="?",
        help="YYYY-MM-DD, 'today', or 'yesterday' (default: today).",
    )

    log = sub.add_parser("log", help="Log a food to a meal.")
    log.add_argument("food_id", help="32-character hex food ID.")
    log.add_argument(
        "-m",
        "--meal",
        default="snacks",
        choices=("breakfast", "lunch", "dinner", "snacks", "snack"),
        help="Meal to log to (default: snacks).",
    )
    log.add_argument("-s", "--servings", type=float, help="Multiplier of the default serving.")
    log.add_argument("-a", "--amount", type=float, help="Quantity, paired with --unit.")
    log.add_argument("-u", "--unit", help="Unit for --amount, e.g. g, mL, cup, oz.")
    log.add_argument("-d", "--date", help="Day to log to (default: today).")
    log.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the calorie math without writing.",
    )

    custom = sub.add_parser(
        "log-custom",
        help="Log a food by its nutrition values, with no database lookup.",
    )
    custom.add_argument("name", help="Food name as it should appear in the diary.")
    custom.add_argument("calories", type=float, help="Calories per serving.")
    custom.add_argument(
        "-m",
        "--meal",
        default="snacks",
        choices=("breakfast", "lunch", "dinner", "snacks", "snack"),
        help="Meal to log to (default: snacks).",
    )
    custom.add_argument("-b", "--brand", default="", help="Brand or restaurant.")
    custom.add_argument("-p", "--protein", type=float, help="Protein (g).")
    custom.add_argument("-c", "--carbs", type=float, help="Carbohydrate (g).")
    custom.add_argument("-f", "--fat", type=float, help="Total fat (g).")
    custom.add_argument("--sat-fat", type=float, help="Saturated fat (g).")
    custom.add_argument("--fiber", type=float, help="Fiber (g).")
    custom.add_argument("--sugar", type=float, help="Sugar (g).")
    custom.add_argument("--sodium", type=float, help="Sodium (mg).")
    custom.add_argument("--cholesterol", type=float, help="Cholesterol (mg).")
    custom.add_argument("-s", "--servings", type=float, default=1.0, help="Servings.")
    custom.add_argument("-d", "--date", help="Day to log to (default: today).")
    custom.add_argument("--dry-run", action="store_true", help="Preview without writing.")

    weigh = sub.add_parser("weigh", help="Record a weigh-in.")
    weigh.add_argument("weight", type=float, help="Body weight in the account's unit.")
    weigh.add_argument("-d", "--date", help="Day to record (default: today).")
    weigh.add_argument("--dry-run", action="store_true", help="Preview without writing.")

    weights = sub.add_parser("weights", help="Show weigh-in history.")
    weights.add_argument("-s", "--start", help="First day (YYYY-MM-DD).")
    weights.add_argument("-e", "--end", help="Last day (YYYY-MM-DD, default: today).")
    weights.add_argument("-n", "--days", type=int, default=30, help="Window size.")

    enroll = sub.add_parser(
        "enroll",
        help="Get a credential URL from a hosted server.",
        description=(
            "Asks a hosted loseit-mcp server to seal your credentials into a "
            "URL you can hand to an MCP client. Secrets are read from the "
            "environment or prompted for — never passed on the command line, "
            "where they would land in shell history and process listings."
        ),
    )
    enroll.add_argument(
        "server",
        help="Base URL of the hosted server, e.g. https://loseit-mcp.azurewebsites.net",
    )
    enroll.add_argument("--email", help="Lose It! account email (prompted if omitted).")
    enroll.add_argument(
        "--ttl-days",
        type=int,
        help="Days before the URL stops working (server default: 365).",
    )
    enroll.add_argument(
        "--tz",
        type=int,
        dest="tz_offset",
        help="Your UTC offset in whole hours, e.g. -7. Defaults to this machine's.",
    )
    enroll.add_argument(
        "--insecure",
        action="store_true",
        help="Allow a plain-http server URL. Only for local testing.",
    )

    sub.add_parser(
        "gen-secret",
        help="Print a random secret suitable for LOSEIT_URL_SECRET.",
    )

    delete = sub.add_parser("delete", help="Delete a diary entry.")
    delete.add_argument("entry_id", help="entry_id from the diary command.")
    delete.add_argument("-d", "--date", help="Day the entry is on (default: today).")

    return parser


# ── Output formatting ───────────────────────────────────────────────────


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _print_search(results: list[dict[str, Any]]) -> None:
    if not results:
        print("No foods found.")
        return
    for r in results:
        brand = f"  [{r['brand']}]" if r.get("brand") else ""
        print(f"{r.get('food_id')}  {r.get('name')}{brand}")


def _print_diary(day: dict[str, Any]) -> None:
    print(f"{day['date']} — {day['entry_count']} entries, {day['total_calories']:g} cal")
    if not day["entries"]:
        return
    by_meal: dict[str, list[dict[str, Any]]] = {}
    for entry in day["entries"]:
        by_meal.setdefault(entry["meal"], []).append(entry)

    for meal in ("breakfast", "lunch", "dinner", "snacks"):
        items = by_meal.get(meal)
        if not items:
            continue
        subtotal = sum(i.get("calories") or 0 for i in items)
        print(f"\n{meal.upper()} ({subtotal:.0f} cal)")
        for i in items:
            brand = f" [{i['food_brand']}]" if i.get("food_brand") else ""
            amount = i.get("amount")
            portion = f"{amount:g} {i.get('unit') or ''}".strip()
            print(
                f"  {i.get('calories') or 0:>7.1f} cal  {portion:<16} "
                f"{i.get('food_name')}{brand}"
            )
            print(f"  {'':>7}       {i.get('entry_id')}")


def _print_logged(result: dict[str, Any]) -> None:
    prefix = "DRY RUN — would log" if result.get("dry_run") else "Logged"
    food = result.get("food") or {}
    # Calories are None for foods that carry no calorie data (raw produce,
    # condiments); the write has already happened by now, so never crash here.
    calories = result.get("calories")
    suffix = f" ({calories:.0f} cal)" if isinstance(calories, int | float) else ""
    print(
        f"{prefix}: {food.get('name')} — {result.get('portion_size')} "
        f"{result.get('measure_unit')} to {result.get('meal')} on {result.get('date')}"
        f"{suffix}"
    )


# ── Dispatch ────────────────────────────────────────────────────────────


def _build_sealer(settings: Settings) -> UrlSealer | None:
    """Build the URL sealer when credential URLs are enabled.

    Stateless by design: the secret is the only thing that needs to persist, so
    there is no store to configure, no volume to mount, and nothing to lose on
    restart.
    """
    if os.environ.get("LOSEIT_ENROLLMENT", "").lower() not in ("1", "true", "yes"):
        return None

    secret = os.environ.get("LOSEIT_URL_SECRET")
    if not secret:
        raise ConfigError(
            "LOSEIT_ENROLLMENT requires LOSEIT_URL_SECRET — it is the key that "
            "seals and opens credential URLs. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    if not os.environ.get("LOSEIT_ENROLL_SECRET"):
        raise ConfigError(
            "LOSEIT_ENROLLMENT requires LOSEIT_ENROLL_SECRET. An open /enroll "
            "endpoint lets anyone mint working credential URLs. Set it and send "
            "it as the X-Enroll-Secret header."
        )
    return UrlSealer(secret.encode("utf-8"))


def _transport_security() -> Any:
    """Configure the transport's DNS-rebinding protection.

    The MCP transport validates the Host header against an allowlist that
    defaults to localhost, so a hosted deployment must declare its own hostname
    or every request is rejected with "Invalid Host header".

    ``LOSEIT_ALLOWED_HOSTS`` takes a comma-separated list. On Azure App Service
    the site's hostnames are discoverable from the environment, so the common
    case needs no configuration at all.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    hosts: list[str] = []
    configured = os.environ.get("LOSEIT_ALLOWED_HOSTS", "")
    hosts.extend(h.strip() for h in configured.split(",") if h.strip())

    # WEBSITE_HOSTNAME is set by App Service; include it and any custom
    # hostnames bound to the site.
    for name in ("WEBSITE_HOSTNAME", "HTTP_HOST"):
        value = os.environ.get(name)
        if value:
            hosts.append(value)

    if not hosts:
        return None  # keep the library's localhost-only default

    # Origins must carry a scheme; hosts must not.
    origins = [f"https://{h}" for h in hosts] + [f"http://{h}" for h in hosts]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=origins,
    )


def _run_serve(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn

    from .server import build_server
    from .webapp import PathTokenMiddleware, add_enrollment_route, install_log_redaction

    multi_tenant = getattr(args, "multi_tenant", False)
    sealer = _build_sealer(settings) if multi_tenant else None

    # In multi-tenant mode credentials come from each request, so the process
    # itself needs none — and shouldn't be started with any.
    if not multi_tenant:
        settings.require_credentials()

    if args.transport == "stdio":
        if multi_tenant:
            print(
                "error: --multi-tenant needs per-request context, which stdio "
                "has none of. Use --transport streamable-http.",
                file=sys.stderr,
            )
            return 2
        build_server(settings).run("stdio")
        return 0

    mcp = build_server(settings, multi_tenant=multi_tenant, sealer=sealer)
    _add_health_route(mcp)
    if sealer is not None:
        add_enrollment_route(
            mcp,
            sealer,
            mount_path=args.path,
            enroll_secret=os.environ.get("LOSEIT_ENROLL_SECRET"),
        )

    mode = "multi-tenant" if multi_tenant else "single-account"
    if sealer is not None:
        mode += " + credential URLs"

    if args.transport == "sse":
        print(f"Serving MCP ({mode}) over SSE at http://{args.host}:{args.port}", file=sys.stderr)
        mcp.run("sse", host=args.host, port=args.port)
        return 0

    app = mcp.streamable_http_app(
        streamable_http_path=args.path,
        transport_security=_transport_security(),
    )
    if sealer is not None:
        app = PathTokenMiddleware(app, mount_path=args.path)

    print(
        f"Serving MCP ({mode}) over streamable HTTP at "
        f"http://{args.host}:{args.port}{args.path}",
        file=sys.stderr,
    )

    if sealer is None:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    # Own the logging config so redaction survives: uvicorn's own dictConfig
    # replaces handlers during startup, which would drop filters installed
    # beforehand. Sealed URLs are credentials, so this has to be reliable.
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(message)s", force=True)
    install_log_redaction()
    uvicorn.run(app, host=args.host, port=args.port, log_config=None)
    return 0


def _add_health_route(mcp: Any) -> None:
    """Expose ``/healthz`` for container and platform health probes.

    Deliberately unauthenticated and dependency-free: it reports that the
    process is serving, not that Lose It! is reachable, so a Lose It outage
    doesn't cause the platform to kill otherwise-healthy instances.
    """
    from starlette.responses import JSONResponse

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Any) -> JSONResponse:
        return JSONResponse({"status": "ok"})


def _run_command(args: argparse.Namespace, settings: Settings) -> int:
    as_json = args.json

    with LoseItService(settings) as svc:
        if args.command == "whoami":
            _print_json(svc.whoami())

        elif args.command == "search":
            results = svc.search_food(args.query, limit=args.limit)
            _print_json(results) if as_json else _print_search(results)

        elif args.command == "describe":
            _print_json(svc.describe_food(args.food_id))

        elif args.command == "diary":
            day = svc.get_diary(args.date)
            _print_json(day) if as_json else _print_diary(day)

        elif args.command == "log":
            result = svc.log_food(
                args.food_id,
                meal=args.meal,
                servings=args.servings,
                serving_amount=args.amount,
                serving_unit=args.unit,
                when=args.date,
                dry_run=args.dry_run,
            )
            _print_json(result) if as_json else _print_logged(result)

        elif args.command == "log-custom":
            result = svc.log_custom_food(
                name=args.name,
                calories=args.calories,
                meal=args.meal,
                brand=args.brand,
                protein_g=args.protein,
                carb_g=args.carbs,
                fat_g=args.fat,
                saturated_fat_g=args.sat_fat,
                fiber_g=args.fiber,
                sugar_g=args.sugar,
                sodium_mg=args.sodium,
                cholesterol_mg=args.cholesterol,
                servings=args.servings,
                when=args.date,
                dry_run=args.dry_run,
            )
            if as_json:
                _print_json(result)
            else:
                prefix = "DRY RUN — would log" if result["dry_run"] else "Logged"
                food = result["food"]
                brand = f" [{food['brand']}]" if food["brand"] else ""
                print(
                    f"{prefix}: {food['name']}{brand} to {result['meal']} "
                    f"on {result['date']} ({result['calories']:g} cal)"
                )
                if result.get("warning"):
                    print(f"  warning: {result['warning']}")

        elif args.command == "weigh":
            result = svc.log_weight(args.weight, when=args.date, dry_run=args.dry_run)
            if as_json:
                _print_json(result)
            else:
                prefix = "DRY RUN — would record" if result["dry_run"] else "Recorded"
                print(f"{prefix}: {result['weight']:g} on {result['date']}")

        elif args.command == "weights":
            hist = svc.get_weight_history(start=args.start, end=args.end, days=args.days)
            if as_json:
                _print_json(hist)
            else:
                print(f"{hist['start']} to {hist['end']} — {hist['count']} weigh-ins")
                for e in hist["entries"]:
                    print(f"  {e['date']}  {e['weight']:g}")
                if hist["count"]:
                    print(
                        f"\nlatest {hist['latest']:g} | min {hist['min']:g} | "
                        f"max {hist['max']:g} | change {hist['change']:+g}"
                    )

        elif args.command == "delete":
            result = svc.delete_entry(args.entry_id, when=args.date)
            if as_json:
                _print_json(result)
            else:
                entry = result.get("entry") or {}
                print(f"Deleted: {entry.get('food_name')} ({entry.get('meal')})")

    return 0


def _run_enroll(args: argparse.Namespace) -> int:
    """Fetch a credential URL from a hosted server and print it."""
    from .enroll_client import EnrollClientError, enroll

    try:
        result = enroll(
            args.server,
            email=args.email,
            ttl_days=args.ttl_days,
            tz_offset=args.tz_offset,
            allow_insecure=args.insecure,
        )
    except EnrollClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        _print_json(result)
        return 0

    print("\nAdd this to your MCP client configuration:\n")
    print(f"  {result['url']}\n")
    ttl = result.get("expires_in_days")
    if ttl:
        print(f"It stops working in {ttl} days.")
    print(
        "Treat this URL as a password: it grants access to your Lose It! "
        "account.\nIt cannot be revoked individually — if it leaks, the server "
        "operator must\nrotate LOSEIT_URL_SECRET, which invalidates every "
        "issued URL."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to a legacy code page, which mangles em-dashes
    # and any non-ASCII food name (e.g. "Häagen-Dazs").
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass

    args = build_parser().parse_args(argv)
    try:
        settings = _settings_from_args(args)
        if args.command == "serve":
            return _run_serve(args, settings)
        if args.command == "enroll":
            return _run_enroll(args)
        if args.command == "gen-secret":
            import secrets

            print(secrets.token_urlsafe(32))
            return 0
        return _run_command(args, settings)
    except (ConfigError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
