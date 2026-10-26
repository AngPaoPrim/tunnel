
import asyncio
import base64
import html
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from oauth import install_oauth, public_base_url
from oauth_store import SQLiteMapping

render_env_file = Path("/etc/secrets/.env")
if render_env_file.is_file():
    load_dotenv(render_env_file, override=True)
load_dotenv(override=False)

app = FastAPI(title="PAO Tunnel Relay")

AGENT_TOKEN = os.environ.get("TUNNEL_AGENT_TOKEN", "")
PUBLIC_BASE_URL = public_base_url()
RESOURCE_URL = PUBLIC_BASE_URL + "/t/mcp/nexa"
RESOURCE_METADATA_URL = PUBLIC_BASE_URL + "/.well-known/oauth-protected-resource/t/mcp/nexa"
DEFAULT_TARGET = os.environ.get("DEFAULT_LOCAL_TARGET", "default").strip() or "default"
OAUTH_USERNAME = os.environ.get("OAUTH_USERNAME", "")
OAUTH_PASSWORD = os.environ.get("OAUTH_PASSWORD", "")
OAUTH_DB_PATH = os.environ.get("OAUTH_DB_PATH", "oauth.sqlite3").strip()
browser_login_states = SQLiteMapping(OAUTH_DB_PATH, "browser_login_states")
browser_login_failures = {}
access_tokens = install_oauth(app)

MAX_BODY = 2 * 1024 * 1024
REQUEST_TIMEOUT = 120
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
}

agent_ws = None
agent_public_access = False
agent_lock = asyncio.Lock()
request_queue = asyncio.Queue(maxsize=100)
pending = {}


def authorized(value, expected):
    return bool(expected) and hmac.compare_digest(value, expected)


def bearer(request):
    value = request.headers.get("authorization", "")
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return ""


def safe_tunnel_path(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme
        or parsed.netloc
        or not parsed.path.startswith("/t/")
        or parsed.path.startswith("/t/login")
        or parsed.path.startswith("//")
        or "\\" in value
    ):
        return "/t/port/3737"
    return urlunsplit(("", "", parsed.path, parsed.query, ""))


def browser_login_response(state, csrf, next_path, message=""):
    content = f"""<!doctype html><html lang="th"><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Sign in</title>
<style>body{{font:16px system-ui;max-width:24rem;margin:12vh auto;padding:0 1rem;color:#202124}}label{{display:block;margin:1rem 0 .35rem}}input{{box-sizing:border-box;width:100%;padding:.75rem;border:1px solid #9aa0a6;border-radius:4px}}button{{margin-top:1.2rem;padding:.7rem 1.1rem}}.error{{color:#b3261e}}</style>
<h1>เข้าสู่ระบบ</h1><p class="error">{html.escape(message)}</p>
<form method="post" action="/t/login">
<input type="hidden" name="state" value="{html.escape(state, quote=True)}">
<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">
<input type="hidden" name="next" value="{html.escape(next_path, quote=True)}">
<label for="username">ชื่อผู้ใช้</label><input id="username" name="username" autocomplete="username" required>
<label for="password">รหัสผ่าน</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">เข้าสู่ระบบ</button></form></html>"""
    return HTMLResponse(
        content,
        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"},
    )


@app.get("/t/login")
async def browser_login_page(request: Request):
    if not OAUTH_USERNAME or not OAUTH_PASSWORD:
        return Response("Browser login is not configured", status_code=503)
    next_path = safe_tunnel_path(request.query_params.get("next", ""))
    state = secrets.token_urlsafe(24)
    csrf = secrets.token_urlsafe(24)
    browser_login_states[state] = {
        "csrf": csrf,
        "next": next_path,
        "expires_at": time.time() + 300,
    }
    return browser_login_response(state, csrf, next_path)


@app.post("/t/login")
async def browser_login(request: Request):
    if not OAUTH_USERNAME or not OAUTH_PASSWORD:
        return Response("Browser login is not configured", status_code=503)
    expected_origin = urlsplit(PUBLIC_BASE_URL)
    expected_origin = f"{expected_origin.scheme}://{expected_origin.netloc}"
    origin = request.headers.get("origin", "")
    if not hmac.compare_digest(origin, expected_origin):
        return Response("Invalid login origin", status_code=403)
    try:
        parsed = parse_qs(
            (await request.body()).decode("utf-8"), keep_blank_values=True
        )
    except UnicodeDecodeError:
        return Response("Invalid login request", status_code=400)
    form = {key: values[-1] for key, values in parsed.items()}
    state = form.get("state", "")
    login_state = browser_login_states.get(state)
    if login_state is None or login_state["expires_at"] < time.time():
        browser_login_states.pop(state, None)
        return Response("Login request expired", status_code=400)
    if not hmac.compare_digest(form.get("csrf", ""), login_state["csrf"]):
        return Response("Invalid login request", status_code=400)

    client_ip = request.client.host if request.client else "unknown"
    failure_count, blocked_until = browser_login_failures.get(client_ip, (0, 0.0))
    if blocked_until > time.time():
        return Response("Too many sign-in attempts", status_code=429)
    if not (
        hmac.compare_digest(form.get("username", ""), OAUTH_USERNAME)
        and hmac.compare_digest(form.get("password", ""), OAUTH_PASSWORD)
    ):
        failure_count += 1
        blocked_until = time.time() + 600 if failure_count >= 8 else 0.0
        browser_login_failures[client_ip] = (failure_count, blocked_until)
        return browser_login_response(
            state, login_state["csrf"], login_state["next"], "เข้าสู่ระบบไม่สำเร็จ"
        )
    if not browser_login_states.delete_if_matches(state, login_state):
        return Response("Login request expired", status_code=400)

    browser_login_failures.pop(client_ip, None)
    session_token = secrets.token_urlsafe(32)
    configured_targets = os.environ.get("OAUTH_ALLOWED_TARGETS", "default")
    targets = sorted(
        set(
            [DEFAULT_TARGET, "dynamic-ports"]
            + [item.strip() for item in configured_targets.split(",") if item.strip()]
        )
    )
    access_tokens[session_token] = {
        "resource": RESOURCE_URL,
        "scope": "mcp",
        "targets": targets,
        "expires_at": time.time() + 3600,
    }
    response = RedirectResponse(login_state["next"], status_code=303)
    response.set_cookie(
        "nexa_browser_session",
        session_token,
        max_age=3600,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/t",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
async def health():
    connected = agent_ws is not None
    return {
        "status": "ok",
        "agent_connected": connected,
        "public_access": connected and agent_public_access,
        "pending_requests": len(pending),
    }


def public_access_requested(ws: WebSocket) -> bool:
    return (
        ws.headers.get("x-tunnel-public-access", "").lower() == "true"
        or ws.query_params.get("public_access", "").lower() == "true"
    )


def resolve_tunnel_target(path: str) -> tuple[str, str]:
    if path == "mcp/nexa":
        return DEFAULT_TARGET, "/mcp/nexa"
    if path.startswith("port/"):
        parts = path.split("/", 2)
        if len(parts) < 2 or not parts[1].isdigit() or not 1 <= int(parts[1]) <= 65535:
            raise HTTPException(status_code=404, detail="Unknown tunnel port")
        return "port" + parts[1], "/" + parts[2] if len(parts) == 3 and parts[2] else "/"
    if path.startswith("ports/"):
        parts = path.split("/", 2)
        if len(parts) < 2 or not parts[1] or any(
            not (ch.isalnum() or ch in "-_.") for ch in parts[1]
        ):
            raise HTTPException(status_code=404, detail="Unknown tunnel target")
        return parts[1], "/" + parts[2] if len(parts) == 3 and parts[2] else "/"
    raise HTTPException(status_code=404, detail="Unknown tunnel resource")


def target_is_permitted(target: str, token_record: dict) -> bool:
    permitted_targets = token_record.get("targets", [DEFAULT_TARGET])
    dynamic_port_target = (
        "dynamic-ports" in permitted_targets
        and target.startswith("port")
        and target[4:].isdigit()
        and 1 <= int(target[4:]) <= 65535
    )
    return target in permitted_targets or dynamic_port_target


def websocket_access_token(path: str, websocket: WebSocket):
    bearer_token = websocket.headers.get("authorization", "")
    if bearer_token.lower().startswith("bearer "):
        bearer_token = bearer_token[7:].strip()
    if agent_public_access and not bearer_token and path != "mcp/nexa":
        configured_targets = os.environ.get("OAUTH_ALLOWED_TARGETS", "default")
        return {
            "resource": RESOURCE_URL,
            "scope": "mcp",
            "targets": sorted(
                set(
                    [DEFAULT_TARGET, "dynamic-ports"]
                    + [item.strip() for item in configured_targets.split(",") if item.strip()]
                )
            ),
            "expires_at": time.time() + 3600,
        }
    return access_tokens.get(
        bearer_token or websocket.cookies.get("nexa_browser_session", "")
    )


@app.websocket("/_tunnel/agent")
async def agent_endpoint(ws: WebSocket):
    global agent_ws, agent_public_access

    token = ws.headers.get("authorization", "")
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    if not authorized(token, AGENT_TOKEN):
        await ws.close(code=1008, reason="Unauthorized")
        return

    await ws.accept()
    async with agent_lock:
        if agent_ws is not None:
            await ws.close(code=1013, reason="Tunnel agent already connected")
            return
        agent_ws = ws
        agent_public_access = public_access_requested(ws)

    async def sender():
        while True:
            item = await request_queue.get()
            try:
                if (
                    item["id"] not in pending
                    and item.get("type") != "websocket_close"
                ):
                    continue
                await ws.send_text(json.dumps(item))
            finally:
                request_queue.task_done()

    send_task = asyncio.create_task(sender())

    try:
        while True:
            message = json.loads(await ws.receive_text())
            request_id = message.get("id")
            response_queue = pending.get(request_id)
            if response_queue is not None:
                await response_queue.put(message)

    except (WebSocketDisconnect, ValueError, RuntimeError):
        pass
    finally:
        send_task.cancel()
        try:
            await send_task
        except asyncio.CancelledError:
            pass

        async with agent_lock:
            if agent_ws is ws:
                agent_ws = None
                agent_public_access = False


@app.websocket("/t/{path:path}")
async def tunnel_websocket(websocket: WebSocket, path: str):
    token_record = websocket_access_token(path, websocket)
    if (
        token_record is None
        or token_record["expires_at"] < time.time()
        or token_record["resource"] != RESOURCE_URL
        or token_record["scope"] != "mcp"
    ):
        await websocket.close(code=1008, reason="Unauthorized")
        return
    try:
        target, local_path = resolve_tunnel_target(path)
    except HTTPException as exc:
        await websocket.close(code=1008, reason=exc.detail)
        return
    if not target_is_permitted(target, token_record):
        await websocket.close(code=1008, reason="Target not permitted")
        return
    if agent_ws is None:
        await websocket.close(code=1013, reason="Tunnel client offline")
        return

    request_id = uuid.uuid4().hex
    response_queue = asyncio.Queue(maxsize=32)
    pending[request_id] = response_queue
    blocked = HOP_HEADERS | {"host", "authorization", "cookie", "proxy-authorization"}
    forwarded_headers = [
        [name.decode("latin-1"), value.decode("latin-1")]
        for name, value in websocket.headers.raw
        if name.decode("latin-1").lower() not in blocked
    ]
    try:
        request_queue.put_nowait(
            {
                "id": request_id,
                "type": "websocket_open",
                "target": target,
                "path": local_path,
                "query": str(websocket.url.query),
                "headers": forwarded_headers,
                "subprotocols": websocket.scope.get("subprotocols", []),
            }
        )
    except asyncio.QueueFull:
        pending.pop(request_id, None)
        await websocket.close(code=1013, reason="Tunnel queue full")
        return

    try:
        opened = await asyncio.wait_for(response_queue.get(), timeout=15)
        if opened.get("type") != "websocket_opened":
            await websocket.close(code=1011, reason="Local WebSocket connection failed")
            return
        await websocket.accept(subprotocol=opened.get("subprotocol"))

        while True:
            browser_receive = asyncio.create_task(websocket.receive())
            agent_receive = asyncio.create_task(response_queue.get())
            done, waiting = await asyncio.wait(
                {browser_receive, agent_receive},
                timeout=REQUEST_TIMEOUT,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in waiting:
                task.cancel()
            if waiting:
                await asyncio.gather(*waiting, return_exceptions=True)
            if not done:
                raise asyncio.TimeoutError
            if agent_receive in done:
                result = agent_receive.result()
                if result.get("type") == "websocket_frame":
                    if "binary" in result:
                        await websocket.send_bytes(
                            base64.b64decode(result["binary"], validate=True)
                        )
                    else:
                        await websocket.send_text(result.get("text", ""))
                elif result.get("type") == "websocket_close":
                    await websocket.close(
                        code=int(result.get("code", 1000)),
                        reason=str(result.get("reason", ""))[:123],
                    )
                    break
            if browser_receive in done:
                message = browser_receive.result()
                if message["type"] == "websocket.disconnect":
                    break
                if message.get("text") is not None:
                    if len(message["text"].encode("utf-8")) > 2 * 1024 * 1024:
                        await websocket.close(
                            code=1009, reason="WebSocket frame too large"
                        )
                        break
                    item = {
                        "id": request_id,
                        "type": "websocket_frame",
                        "text": message["text"],
                    }
                elif message.get("bytes") is not None:
                    if len(message["bytes"]) > 2 * 1024 * 1024:
                        await websocket.close(
                            code=1009, reason="WebSocket frame too large"
                        )
                        break
                    item = {
                        "id": request_id,
                        "type": "websocket_frame",
                        "binary": base64.b64encode(message["bytes"]).decode("ascii"),
                    }
                else:
                    continue
                try:
                    request_queue.put_nowait(item)
                except asyncio.QueueFull:
                    await websocket.close(code=1013, reason="Tunnel queue full")
                    break
    except asyncio.TimeoutError:
        await websocket.close(code=1011, reason="Local WebSocket timed out")
    finally:
        pending.pop(request_id, None)
        if agent_ws is not None:
            try:
                request_queue.put_nowait(
                    {"id": request_id, "type": "websocket_close", "code": 1000}
                )
            except asyncio.QueueFull:
                pass


@app.api_route("/t", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.api_route("/t/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def tunnel(request: Request, path: str = ""):
    bearer_token = bearer(request)
    public_site_access = (
        agent_public_access
        and not bearer_token
        and path != "mcp/nexa"
    )
    if public_site_access:
        configured_targets = os.environ.get("OAUTH_ALLOWED_TARGETS", "default")
        token_record = {
            "resource": RESOURCE_URL,
            "scope": "mcp",
            "targets": sorted(
                set(
                    [DEFAULT_TARGET, "dynamic-ports"]
                    + [
                        item.strip()
                        for item in configured_targets.split(",")
                        if item.strip()
                    ]
                )
            ),
            "expires_at": time.time() + 3600,
        }
    else:
        credential = bearer_token or request.cookies.get(
            "nexa_browser_session", ""
        )
        token_record = access_tokens.get(credential)
    if (
        token_record is None
        or token_record["expires_at"] < time.time()
        or token_record["resource"] != RESOURCE_URL
        or token_record["scope"] != "mcp"
    ):
        if (
            not bearer_token
            and request.method in {"GET", "HEAD"}
            and "text/html" in request.headers.get("accept", "")
        ):
            next_path = request.url.path
            if request.url.query:
                next_path += "?" + request.url.query
            return RedirectResponse(
                "/t/login?" + urlencode({"next": safe_tunnel_path(next_path)}),
                status_code=303,
                headers={"Cache-Control": "no-store"},
            )
        return Response(
            "Unauthorized",
            status_code=401,
            headers={
                "WWW-Authenticate": f'Bearer resource_metadata="{RESOURCE_METADATA_URL}", scope="mcp"',
                "Cache-Control": "no-store",
            },
        )
    target, local_path = resolve_tunnel_target(path)
    if path.startswith("port/") and path.count("/") == 1 and request.method in {"GET", "HEAD"}:
        location = request.url.path + "/"
        if request.url.query:
            location += "?" + request.url.query
        return RedirectResponse(location, status_code=307)
    if not target_is_permitted(target, token_record):
        raise HTTPException(status_code=403, detail="Target not permitted for this OAuth token")

    if agent_ws is None:
        raise HTTPException(status_code=503, detail="Tunnel client offline")

    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Body too large (2 MiB max)")

    request_id = uuid.uuid4().hex
    response_queue = asyncio.Queue(maxsize=32)
    pending[request_id] = response_queue

    forwarded_headers = []
    blocked = HOP_HEADERS | {"host", "authorization", "cookie", "proxy-authorization"}
    for raw_name, raw_value in request.headers.raw:
        name = raw_name.decode("latin-1")
        value = raw_value.decode("latin-1")
        if name.lower() not in blocked:
            forwarded_headers.append((name, value))

    item = {
        "id": request_id,
        "method": request.method,
        "target": target,
        "path": local_path,
        "query": str(request.url.query),
        "headers": forwarded_headers,
        "body": base64.b64encode(body).decode("ascii"),
    }

    try:
        request_queue.put_nowait(item)
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="Tunnel queue full")

    try:
        first = await asyncio.wait_for(response_queue.get(), timeout=REQUEST_TIMEOUT)
    except asyncio.TimeoutError:
        pending.pop(request_id, None)
        raise HTTPException(status_code=504, detail="Local service timeout")

    if first.get("type") != "start":
        pending.pop(request_id, None)
        raise HTTPException(status_code=502, detail="Invalid tunnel response")

    status = int(first.get("status", 502))
    if status < 100 or status > 599:
        status = 502

    safe_headers = {}
    headers = first.get("headers", [])
    if isinstance(headers, dict):
        headers = headers.items()
    for name, value in headers:
        if name.lower() not in HOP_HEADERS | {"set-cookie"}:
            safe_headers[name] = value

    async def stream_response():
        try:
            while True:
                result = await asyncio.wait_for(
                    response_queue.get(), timeout=REQUEST_TIMEOUT
                )
                if result.get("type") == "end":
                    break
                if result.get("type") == "chunk":
                    yield base64.b64decode(result.get("body", ""), validate=True)
        finally:
            pending.pop(request_id, None)

    return StreamingResponse(stream_response(), status_code=status, headers=safe_headers)
