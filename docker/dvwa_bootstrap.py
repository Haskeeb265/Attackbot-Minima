#!/usr/bin/env python3
"""Bootstrap DVWA for an engine run: database, login, security=low, cookies.

One-off operator script (not engine code): it performs exactly the steps a
pentester performs in a browser before pointing a tool at DVWA, and prints the
Cookie header value the engine's --cookie flag consumes. The engine itself
never logs in — session identity is the operator's declared input, which is
the same boundary as declaring a surface.

Troubleshooting, from the first live bootstrap: every DVWA form — including
the setup button — carries a CSRF ``user_token``; posting without it silently
bounces and the schema is never built, which looks like "login always
redirects to setup.php". On a fresh container the shipped ``app``/``vulnerables``
MySQL account works as-is; the MariaDB ``root`` unix_socket auth is irrelevant
because the app never uses root.
"""

from __future__ import annotations

import re
import sys

import httpx

BASE = "http://127.0.0.1:4280"


def _token(html: str) -> str:
    match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", html)
    return match.group(1) if match else ""


def main() -> int:
    client = httpx.Client(base_url=BASE, follow_redirects=True, timeout=15.0)

    # 1. The database is usually uninitialised on first boot; the setup page
    #    offers a "Create / Reset Database" button. The POST carries a CSRF
    #    token like every other DVWA form — without it the handler silently
    #    bounces and the schema is never built (the failure mode that looks
    #    like "login always redirects to setup.php").
    setup = client.get("/setup.php")
    client.post(
        "/setup.php",
        data={"create_db": "Create / Reset Database", "user_token": _token(setup.text)},
    )

    # 2. Login as the default admin, pulling the fresh CSRF token off the form.
    login_page = client.get("/login.php")
    response = client.post(
        "/login.php",
        data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": _token(login_page.text),
        },
    )
    if "Login failed" in response.text or "logout" not in response.text.lower():
        print("login failed — check credentials (or the database was not created)", file=sys.stderr)
        return 1

    # 3. Security to low (impossible would be the control, not the target).
    security_page = client.get("/security.php")
    client.post(
        "/security.php",
        data={
            "security": "low",
            "secvar_submit": "Submit",
            "user_token": _token(security_page.text),
        },
    )

    # 4. Prove the session works on a target page, then hand out the cookies.
    #    xss_r's form submits via its Submit button, so the param pair is
    #    name + Submit — exactly what the engine's grammar will send.
    probe = client.get("/vulnerabilities/sqli_blind/?id=1&Submit=Submit")
    check = client.get("/vulnerabilities/xss_r/?name=probe&Submit=Submit")
    if "/login.php" in str(probe.url) or "/login.php" in str(check.url):
        print("session did not stick — target pages redirected to login", file=sys.stderr)
        return 1
    reflected = "probe" in check.text
    cookie_header = "; ".join(f"{name}={value}" for name, value in client.cookies.items())
    print(f"cookie header: {cookie_header}")
    print(f"sqli_blind reachable: {probe.status_code}; xss_r echoes param: {reflected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
