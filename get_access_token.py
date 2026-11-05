#!/usr/bin/env python3
"""
Get a Shopify Admin API access token for any store, via the OAuth
authorization-code flow with a local callback on http://localhost:3000/callback.

Usage:
  python get_access_token.py          -> picks the env (prompts if several are set)
  python get_access_token.py prod     -> uses SHOPIFY_STORE_PROD
  python get_access_token.py stage    -> uses SHOPIFY_STORE_STAGE (any NAME works)

.env keys read (next to this script):
  SHOPIFY_CLIENT_ID / SHOPIFY_CLIENT_SECRET   shared; optional *_<NAME> overrides
  SHOPIFY_STORE_<NAME>                        one per environment, e.g. _PROD, _STAGE
  SHOPIFY_SCOPES                              optional, comma-separated
  SHOPIFY_REDIRECT_URI                        optional, default http://localhost:3000/callback

.env keys written:
  SHOPIFY_ACCESS_TOKEN_<NAME>                 per-environment token
  SHOPIFY_STORE / SHOPIFY_ACCESS_TOKEN        "active" pointer to the env just authorized

Standard library only.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parent / ".env"
SHOP_RE = r"^[a-z0-9][a-z0-9-]*\.myshopify\.com$"
STORE_KEY_RE = re.compile(r"^SHOPIFY_STORE_([A-Z0-9_]+)$")

# Common read/write set. Gated scopes (read_all_orders, protected customer data
# beyond read_customers, etc.) are left out: requesting an unapproved gated scope
# fails the authorize step. Override per project with SHOPIFY_SCOPES in .env.
# Apps on Shopify managed installation ignore this and use the app's config.
DEFAULT_SCOPES = [
    "read_products", "write_products", "read_product_listings",
    "read_orders", "read_draft_orders", "read_customers",
    "read_inventory", "write_inventory", "read_locations",
    "read_themes", "write_themes",
    "read_content", "write_content", "read_files", "write_files",
    "read_metaobject_definitions", "write_metaobject_definitions",
    "read_metaobjects", "write_metaobjects",
    "read_online_store_pages", "write_online_store_pages",
    "read_online_store_navigation", "write_online_store_navigation",
    "read_discounts", "write_discounts", "read_price_rules",
    "read_locales", "read_translations", "write_translations", "read_markets",
    "read_shipping", "read_fulfillments",
    "read_analytics", "read_reports",
]

CONFIG = {"state": secrets.token_hex(16)}  # rest filled in by main()


# ---------- .env ----------
def load_dotenv(path=ENV_PATH):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        os.environ.setdefault(key, val)


def update_env(updates, path=ENV_PATH):
    """Replace existing keys in place, append new ones, keep comments/blank lines."""
    lines, seen = [], set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines(keepends=True):
            key = line.split("=", 1)[0].strip() if "=" in line else None
            if key in updates:
                lines.append(key + "=" + updates[key] + "\n")
                seen.add(key)
            else:
                lines.append(line)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines += [k + "=" + v + "\n" for k, v in updates.items() if k not in seen]
    path.write_text("".join(lines), encoding="utf-8", newline="\n")
    return path


# ---------- config ----------
def normalize_shop(raw):
    shop = raw.strip()
    for prefix in ("https://", "http://"):
        if shop.lower().startswith(prefix):
            shop = shop[len(prefix):]
    shop = shop.split("/")[0].lower()
    if not re.match(SHOP_RE, shop):
        sys.exit("Store must look like my-store.myshopify.com (got: " + raw + ")")
    return shop


def environments(env=os.environ):
    """{NAME: store} for every non-empty SHOPIFY_STORE_<NAME>."""
    found = {}
    for key, val in env.items():
        m = STORE_KEY_RE.match(key)
        if m and val.strip():
            found[m.group(1)] = val.strip()
    return dict(sorted(found.items()))


def choose_environment(envs):
    if not envs:
        sys.exit("No store set. Add e.g. SHOPIFY_STORE_PROD=my-store.myshopify.com to .env")
    if len(sys.argv) > 1:
        name = sys.argv[1].strip().upper()
        if name in envs:
            return name
        print("Unknown environment " + sys.argv[1] + ". Choose one below.\n")
    names = list(envs)
    if len(names) == 1:
        return names[0]
    while True:
        for i, n in enumerate(names, 1):
            print("  [" + str(i) + "] " + n.ljust(8) + envs[n])
        choice = input("Pick an environment: ").strip().upper()
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]
        if choice in envs:
            return choice
        print("Invalid choice.\n")


def credentials(name):
    cid = os.getenv("SHOPIFY_CLIENT_ID_" + name) or os.getenv("SHOPIFY_CLIENT_ID")
    secret = os.getenv("SHOPIFY_CLIENT_SECRET_" + name) or os.getenv("SHOPIFY_CLIENT_SECRET")
    if not cid or not secret:
        sys.exit("Missing SHOPIFY_CLIENT_ID / SHOPIFY_CLIENT_SECRET in " + str(ENV_PATH))
    return cid.strip(), secret.strip()


def install_url():
    params = {
        "client_id": CONFIG["client_id"],
        "scope": ",".join(CONFIG["scopes"]),
        "redirect_uri": CONFIG["redirect_uri"],
        "state": CONFIG["state"],
    }
    return "https://" + CONFIG["store"] + "/admin/oauth/authorize?" + urllib.parse.urlencode(params)


# ---------- oauth ----------
def valid_hmac(params, secret):
    """Drop hmac/signature, sort the rest, join k=v&..., HMAC-SHA256 with the app secret."""
    received = params.get("hmac", [""])[0]
    message = "&".join(
        k + "=" + v[0] for k, v in sorted(params.items()) if k not in ("hmac", "signature")
    )
    digest = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, received)


def missing_scopes(requested, granted):
    """Shopify omits read_X from the granted list when write_X is granted."""
    have = set(granted.split(","))
    have |= {"read_" + s[len("write_"):] for s in have if s.startswith("write_")}
    return [s for s in requested if s not in have]


def exchange_code(shop, code):
    body = json.dumps({
        "client_id": CONFIG["client_id"],
        "client_secret": CONFIG["client_secret"],
        "code": code,
    }).encode()
    req = urllib.request.Request(
        "https://" + shop + "/admin/oauth/access_token",
        data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError("Token exchange failed " + str(e.code) + ": "
                           + e.read().decode(errors="replace")) from None


class Handler(BaseHTTPRequestHandler):
    done = False

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/plain"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/":
            self.send_response(302)
            self.send_header("Location", install_url())
            self.end_headers()
            return
        if url.path != CONFIG["callback_path"]:
            self._send(404, "Not found")
            return

        params = urllib.parse.parse_qs(url.query, keep_blank_values=True)
        try:
            if params.get("state", [""])[0] != CONFIG["state"]:
                raise ValueError("state mismatch (CSRF check failed)")
            shop = params.get("shop", [""])[0]
            if shop != CONFIG["store"]:
                raise ValueError("callback shop " + shop + " != selected store " + CONFIG["store"])
            if not valid_hmac(params, CONFIG["client_secret"]):
                raise ValueError("HMAC verification failed")
            code = params.get("code", [""])[0]
            if not code:
                raise ValueError("no code in callback")

            token = exchange_code(shop, code)
            access_token = token.get("access_token")
            if not access_token:
                raise ValueError("no access_token in response: " + json.dumps(token))
            granted = token.get("scope", "")
            token_key = "SHOPIFY_ACCESS_TOKEN_" + CONFIG["env"]
            update_env({token_key: access_token, "SHOPIFY_STORE": shop,
                        "SHOPIFY_ACCESS_TOKEN": access_token})

            print("\n=== ACCESS TOKEN ===")
            print("environment: " + CONFIG["env"])
            print("store:       " + shop)
            print("token:       " + access_token[:10] + "... (full value in .env)")
            print("granted:     " + granted)
            print("written to:  " + str(ENV_PATH) + "  [" + token_key
                  + ", SHOPIFY_STORE, SHOPIFY_ACCESS_TOKEN]\n")
            missing = missing_scopes(CONFIG["scopes"], granted)
            if missing:
                print("Requested but NOT granted: " + ", ".join(missing) + "\n")

            self._send(200, "<h1>Success</h1><p>Token written to .env. Check your terminal.</p>",
                       "text/html")
            Handler.done = True
        except Exception as err:  # noqa: BLE001
            print("OAuth callback error: " + str(err))
            self._send(400, "OAuth error: " + str(err))


def main():
    load_dotenv()
    envs = environments()
    name = choose_environment(envs)
    cid, secret = credentials(name)
    redirect = os.getenv("SHOPIFY_REDIRECT_URI") or "http://localhost:3000/callback"
    parsed = urllib.parse.urlparse(redirect)
    scopes = [s.strip() for s in (os.getenv("SHOPIFY_SCOPES") or "").split(",") if s.strip()]

    CONFIG.update(
        env=name, store=normalize_shop(envs[name]), client_id=cid, client_secret=secret,
        redirect_uri=redirect, callback_path=parsed.path or "/callback",
        scopes=scopes or DEFAULT_SCOPES,
    )
    url = install_url()
    print("\nEnvironment: " + name)
    print("Store:       " + CONFIG["store"])
    print("Callback:    " + redirect + "   (must be in the app's Allowed redirection URLs)")
    print("Scopes:      " + str(len(CONFIG["scopes"])) + " requested")
    print("\nOpening the browser. If it does not open, paste this:\n\n" + url + "\n")

    server = HTTPServer((parsed.hostname or "localhost", parsed.port or 80), Handler)
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass
    try:
        while not Handler.done:
            server.handle_request()
    except KeyboardInterrupt:
        print("\nCancelled.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
