import base64
import hashlib
import hmac
import html
import logging
import os
import secrets
import time
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from oauth_store import SQLiteMapping

logger = logging.getLogger(__name__)


def public_base_url() -> str:
    return (
        os.environ.get("PUBLIC_BASE_URL")
        or os.environ.get("RENDER_EXTERNAL_URL")
        or "https://tunnel-8fvo.onrender.com"
    ).rstrip("/")


def install_oauth(app: FastAPI) -> dict[str, dict]:
    base_url = public_base_url()
    issuer = base_url
    resource = base_url + "/t/mcp/nexa"
    resource_metadata_url = base_url + "/.well-known/oauth-protected-resource/t/mcp/nexa"
    default_target = os.environ.get("DEFAULT_LOCAL_TARGET", "default").strip() or "default"
    configured_targets = os.environ.get("OAUTH_ALLOWED_TARGETS", "default")
    allowed_targets = sorted(set([default_target, "dynamic-ports"] + [item.strip() for item in configured_targets.split(",") if item.strip()]))
    if any(not target or len(target) > 64 or any(not (ch.isalnum() or ch in "-_.") for ch in target) for target in allowed_targets):
        raise RuntimeError("OAUTH_ALLOWED_TARGETS must be comma-separated target names (letters, numbers, dot, underscore, hyphen).")
    username = os.environ.get("OAUTH_USERNAME", "")
    password = os.environ.get("OAUTH_PASSWORD", "")
    static_client_id = os.environ.get("OAUTH_CLIENT_ID", "")
    static_client_secret = os.environ.get("OAUTH_CLIENT_SECRET", "")
    static_redirect_uris = os.environ.get("OAUTH_REDIRECT_URIS", "")
    database_path = os.environ.get("OAUTH_DB_PATH", "oauth.sqlite3").strip()
    if not database_path:
        raise RuntimeError("OAUTH_DB_PATH must name a persistent SQLite file.")
    clients = SQLiteMapping(database_path, "clients")
    codes = SQLiteMapping(database_path, "codes")
    tokens = SQLiteMapping(database_path, "tokens")
    refresh_tokens = SQLiteMapping(database_path, "refresh_tokens")
    transactions = SQLiteMapping(database_path, "transactions")
    failures: dict[str, tuple[int, float]] = {}

    def error(name: str, status: int = 400) -> JSONResponse:
        return JSONResponse({"error": name}, status_code=status, headers={"Cache-Control": "no-store"})

    def constant_equal(first: str, second: str) -> bool:
        return bool(second) and hmac.compare_digest(first, second)

    def allowed_redirect(uri: str) -> bool:
        parsed = urlsplit(uri)
        if parsed.fragment or parsed.username or parsed.password or not parsed.hostname:
            return False
        if parsed.scheme == "https":
            return True
        return parsed.scheme == "http" and parsed.hostname.lower() in {
            "localhost", "127.0.0.1", "::1"
        }

    configured_redirects = [
        uri.strip() for uri in static_redirect_uris.splitlines() if uri.strip()
    ]
    if configured_redirects and (
        any(not allowed_redirect(uri) for uri in configured_redirects)
        or len(set(configured_redirects)) != len(configured_redirects)
    ):
        raise RuntimeError("OAUTH_REDIRECT_URIS must contain unique valid callback URLs.")

    static_client_configured = bool(static_client_id and configured_redirects)
    if static_client_configured:
        static_client = {
            "client_id": static_client_id,
            "redirect_uris": configured_redirects,
            "client_name": "ChatGPT",
            "token_endpoint_auth_method": (
                "client_secret_post" if static_client_secret else "none"
            ),
        }
        if static_client_secret:
            static_client["client_secret"] = static_client_secret
        clients[static_client_id] = static_client
        logger.info(
            "OAuth static client loaded (redirect_count=%d, auth_method=%s)",
            len(configured_redirects),
            static_client["token_endpoint_auth_method"],
        )
    elif any((static_client_id, static_client_secret, static_redirect_uris)):
        logger.warning(
            "OAuth static client unavailable (client_id_set=%s, redirect_uris_set=%s)",
            bool(static_client_id),
            bool(static_redirect_uris),
        )

    def login_page(transaction_id: str, csrf: str, message: str = "") -> HTMLResponse:
        content = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Authorize NEXA</title>
<style>body{{font:16px system-ui;max-width:28rem;margin:10vh auto;padding:0 1rem;color:#202124}}label{{display:block;margin:1rem 0 .3rem}}input{{box-sizing:border-box;width:100%;padding:.7rem}}button{{margin-top:1rem;padding:.7rem 1rem}}.error{{color:#b3261e}}</style>
<h1>Authorize NEXA</h1><p>Sign in to connect ChatGPT to your NEXA tools.</p>
<p class="error">{html.escape(message)}</p><form method="post" action="/oauth/authorize/consent">
<input type="hidden" name="transaction_id" value="{html.escape(transaction_id, quote=True)}">
<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<label><input style="width:auto" type="checkbox" name="approve" value="yes" required> Allow ChatGPT to use NEXA tools</label>
<button type="submit">Authorize</button></form></html>"""
        return HTMLResponse(content, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})

    async def read_form(request: Request) -> dict[str, str]:
        from urllib.parse import parse_qs

        parsed = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
        return {key: values[-1] for key, values in parsed.items()}

    @app.get("/.well-known/oauth-protected-resource")
    @app.get("/.well-known/oauth-protected-resource/t/mcp/nexa")
    async def protected_resource_metadata():
        return {
            "resource": resource,
            "authorization_servers": [issuer],
            "scopes_supported": ["mcp"],
            "bearer_methods_supported": ["header"],
            "tunnel_targets": allowed_targets,
        }

    @app.get("/.well-known/oauth-authorization-server")
    @app.get("/.well-known/oauth-authorization-server/t/mcp/nexa")
    async def authorization_server_metadata():
        return {
            "issuer": issuer,
            "authorization_endpoint": base_url + "/oauth/authorize",
            "token_endpoint": base_url + "/oauth/token",
            "registration_endpoint": base_url + "/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "none", "client_secret_basic", "client_secret_post"
            ],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["mcp"],
            "client_id_metadata_document_supported": False,
            "tunnel_targets": allowed_targets,
        }

    @app.post("/oauth/register")
    async def register_client(request: Request):
        try:
            metadata = await request.json()
        except (ValueError, UnicodeDecodeError):
            return error("invalid_client_metadata")
        redirects = metadata.get("redirect_uris") if isinstance(metadata, dict) else None
        if not isinstance(redirects, list) or not redirects or any(
            not isinstance(uri, str) or not allowed_redirect(uri) for uri in redirects
        ):
            return error("invalid_redirect_uri")
        if len(redirects) > 20 or len(set(redirects)) != len(redirects):
            return error("invalid_client_metadata")
        client_name = str(metadata.get("client_name", "MCP client"))[:120]
        client_id = secrets.token_urlsafe(24)
        client = {
            "client_id": client_id,
            "redirect_uris": redirects,
            "client_name": client_name,
            "token_endpoint_auth_method": "none",
        }
        clients[client_id] = client
        response_client = {
            key: value for key, value in client.items() if key != "client_secret"
        }
        return JSONResponse(
            {
                **response_client,
                "client_id_issued_at": int(time.time()),
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
            status_code=201,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/oauth/authorize")
    async def authorize(request: Request):
        if not username or not password:
            return Response("OAuth credentials are not configured", status_code=503)
        params = request.query_params
        requested_client_id = params.get("client_id", "")
        client = clients.get(requested_client_id)
        redirect_uri = params.get("redirect_uri", "")
        if client is None:
            if (
                requested_client_id
                and len(requested_client_id) <= 128
                and all(0x21 <= ord(char) <= 0x7E for char in requested_client_id)
                and redirect_uri in configured_redirects
            ):
                client = {
                    "client_id": requested_client_id,
                    "redirect_uris": configured_redirects,
                    "client_name": "Recovered public client",
                    "token_endpoint_auth_method": "none",
                }
                clients[requested_client_id] = client
                logger.info(
                    "OAuth public client restored from configured redirect URI"
                )
        if client is None:
            matches_static_client = bool(static_client_id) and hmac.compare_digest(
                requested_client_id, static_client_id
            )
            logger.warning(
                "OAuth authorization rejected: unknown client id "
                "(matches_static_client=%s, static_configured=%s)",
                matches_static_client,
                static_client_configured,
            )
            return error("invalid_client")
        if redirect_uri not in client["redirect_uris"]:
            logger.warning("OAuth authorization rejected: redirect URI mismatch")
            return error("invalid_request")
        if params.get("response_type") != "code":
            return error("unsupported_response_type")
        if params.get("resource") != resource:
            return error("invalid_target")
        if params.get("scope", "mcp") not in {"mcp", ""}:
            return error("invalid_scope")
        if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
            return error("invalid_request")
        transaction_id = secrets.token_urlsafe(24)
        csrf = secrets.token_urlsafe(24)
        transactions[transaction_id] = {
            "params": dict(params),
            "csrf": csrf,
            "expires_at": time.time() + 600,
        }
        return login_page(transaction_id, csrf)

    @app.post("/oauth/authorize/consent")
    async def authorize_consent(request: Request):
        form = await read_form(request)
        transaction_id = form.get("transaction_id", "")
        transaction = transactions.get(transaction_id)
        if transaction is None or transaction["expires_at"] < time.time():
            transactions.pop(transaction_id, None)
            return Response("Authorization request expired", status_code=400)
        if not constant_equal(form.get("csrf", ""), transaction["csrf"]):
            return Response("Invalid authorization request", status_code=400)
        client_ip = request.client.host if request.client else "unknown"
        failure_count, blocked_until = failures.get(client_ip, (0, 0.0))
        if blocked_until > time.time():
            return Response("Too many sign-in attempts", status_code=429)
        if not (
            constant_equal(form.get("username", ""), username)
            and constant_equal(form.get("password", ""), password)
        ):
            failure_count += 1
            blocked_until = time.time() + 600 if failure_count >= 8 else 0.0
            failures[client_ip] = (failure_count, blocked_until)
            return login_page(transaction_id, transaction["csrf"], "Sign-in failed.")
        if form.get("approve") != "yes":
            return Response("Consent is required", status_code=400)
        failures.pop(client_ip, None)
        params = transaction["params"]
        if not transactions.delete_if_matches(transaction_id, transaction):
            return Response("Authorization request expired", status_code=400)
        code = secrets.token_urlsafe(32)
        codes[code] = {
            "client_id": params["client_id"],
            "redirect_uri": params["redirect_uri"],
            "challenge": params["code_challenge"],
            "resource": resource,
            "expires_at": time.time() + 300,
        }
        parsed = urlsplit(params["redirect_uri"])
        query = parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("code", code))
        if "state" in params:
            query.append(("state", params["state"]))
        return Response(
            status_code=302,
            headers={
                "Location": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")),
                "Cache-Control": "no-store",
            },
        )

    @app.post("/oauth/token")
    async def token(request: Request):
        form = await read_form(request)

        def authenticate_client(expected_client_id: str) -> bool:
            client = clients.get(expected_client_id)
            if client is None:
                logger.warning("OAuth token request rejected: unknown client id")
                return False
            authorization = request.headers.get("authorization", "")
            basic_client_id = ""
            basic_secret = ""
            has_basic = authorization.lower().startswith("basic ")
            if authorization.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
                    basic_client_id, separator, basic_secret = decoded.partition(":")
                    if not separator:
                        logger.warning("OAuth token request rejected: client authentication failed")
                        return False
                    basic_client_id = unquote_plus(basic_client_id)
                    basic_secret = unquote_plus(basic_secret)
                except (ValueError, UnicodeDecodeError):
                    logger.warning("OAuth token request rejected: client authentication failed")
                    return False
            auth_method = client["token_endpoint_auth_method"]
            if auth_method == "none":
                authenticated = (
                    not authorization
                    and form.get("client_id", "") == expected_client_id
                    and not form.get("client_secret")
                )
            elif auth_method == "client_secret_post":
                supplied_secret = form.get("client_secret", "")
                authenticated = (
                    not authorization
                    and form.get("client_id", "") == expected_client_id
                    and bool(supplied_secret)
                    and hmac.compare_digest(
                        supplied_secret, client.get("client_secret", "")
                    )
                )
            elif auth_method == "client_secret_basic":
                authenticated = (
                    has_basic
                    and not form.get("client_secret")
                    and basic_client_id == expected_client_id
                    and bool(basic_secret)
                    and hmac.compare_digest(
                        basic_secret, client.get("client_secret", "")
                    )
                )
            else:
                authenticated = False
            if not authenticated:
                logger.warning("OAuth token request rejected: client authentication failed")
            return authenticated

        grant_type = form.get("grant_type")
        if grant_type == "refresh_token":
            old_refresh = form.get("refresh_token", "")
            record = refresh_tokens.get(old_refresh)
            if record is None or record["expires_at"] < time.time():
                logger.warning("OAuth token request rejected: invalid or expired refresh token")
                return error("invalid_grant")
            if not authenticate_client(record["client_id"]):
                return error("invalid_client", status=401)
            if form.get("resource") != record["resource"]:
                return error("invalid_grant")
            if not refresh_tokens.delete_if_matches(old_refresh, record):
                logger.warning("OAuth token request rejected: invalid or expired refresh token")
                return error("invalid_grant")
            family_id = record["family_id"]
        elif grant_type == "authorization_code":
            code = form.get("code", "")
            record = codes.get(code)
            if record is None or record["expires_at"] < time.time():
                logger.warning("OAuth token request rejected: invalid or expired authorization code")
                return error("invalid_grant")
            if not authenticate_client(record["client_id"]):
                return error("invalid_client", status=401)
            verifier = form.get("code_verifier", "")
            if (
                form.get("redirect_uri") != record["redirect_uri"]
                or form.get("resource") != record["resource"]
                or not 43 <= len(verifier) <= 128
            ):
                return error("invalid_grant")
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii", "ignore")).digest()).rstrip(b"=").decode("ascii")
            if not hmac.compare_digest(challenge, record["challenge"]):
                return error("invalid_grant")
            if not codes.delete_if_matches(code, record):
                logger.warning("OAuth token request rejected: invalid or expired authorization code")
                return error("invalid_grant")
            family_id = secrets.token_urlsafe(18)
        else:
            return error("unsupported_grant_type")

        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(48)
        client_id = record["client_id"]
        tokens[access_token] = {
            "resource": resource,
            "scope": "mcp",
            "targets": list(allowed_targets),
            "expires_at": time.time() + 3600,
            "family_id": family_id,
        }
        refresh_tokens[refresh_token] = {
            "resource": resource,
            "client_id": client_id,
            "family_id": family_id,
            "targets": list(allowed_targets),
            "expires_at": time.time() + 30 * 24 * 3600,
        }
        return JSONResponse(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "mcp",
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    return tokens