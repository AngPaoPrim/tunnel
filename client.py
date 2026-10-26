import asyncio
import base64
import json
import os
import sys
from urllib.parse import urlsplit

import httpx
import websockets

TUNNEL_URL = os.environ.get("TUNNEL_URL", "https://ang.pao.run.place").rstrip("/")
AGENT_TOKEN = os.environ.get("TUNNEL_AGENT_TOKEN", "")
LOCAL_TARGET = os.environ.get("LOCAL_TARGET", "http://127.0.0.1:5000").rstrip("/")
LOCAL_TARGETS_RAW = os.environ.get("LOCAL_TARGETS", "")
PUBLIC_ACCESS = False
if sys.stdin.isatty():
    while True:
        try:
            password_choice = input(
                "Require a password to access the website? (Y/N) [Y]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            password_choice = "y"
        if password_choice in {"", "y", "yes"}:
            break
        if password_choice in {"n", "no"}:
            PUBLIC_ACCESS = True
            break
        print("Please enter Y or N.")

# Interactive port selection: enter local ports as comma-separated numbers.
# These are mapped only to localhost, never to caller-supplied remote URLs.
if sys.stdin.isatty():
    try:
        extra_ports = input("Add local ports to tunnel (comma-separated, e.g. 3737; Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        extra_ports = ""
    if extra_ports:
        try:
            extra_targets = json.loads(LOCAL_TARGETS_RAW) if LOCAL_TARGETS_RAW.strip() else {}
            if not isinstance(extra_targets, dict):
                raise ValueError("LOCAL_TARGETS must be a JSON object")
            for raw_port in extra_ports.replace(";", ",").split(","):
                raw_port = raw_port.strip()
                if not raw_port:
                    continue
                if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
                    print(f"Skipping invalid port: {raw_port}")
                    continue
                port = int(raw_port)
                extra_targets[f"port{port}"] = f"http://127.0.0.1:{port}"
            LOCAL_TARGETS_RAW = json.dumps(extra_targets)
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"Could not parse additional ports: {exc}")
            raise SystemExit(2)
DEFAULT_TARGET = os.environ.get("DEFAULT_LOCAL_TARGET", "default").strip() or "default"

MAX_BODY = 2 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
MAX_WEBSOCKET_FRAME = 2 * 1024 * 1024
send_lock = asyncio.Lock()
websocket_sessions = {}


class TargetSelectionError(Exception):
    """The relay requested a target that is not explicitly allow-listed."""


def validate_local_target(name, url):
    if not isinstance(name, str) or not name or len(name) > 64:
        raise RuntimeError("LOCAL_TARGETS keys must be non-empty strings (max 64 chars)")
    if not isinstance(url, str):
        raise RuntimeError(f"Target {name!r} must have a URL string")

    url = url.rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError(f"Target {name!r} must be an http:// or https:// URL")

    # Keep the agent from becoming an arbitrary network proxy. Local ports only.
    if parsed.hostname.lower() not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError(
            f"Target {name!r} must point to localhost (127.0.0.1, localhost, or ::1)"
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError(f"Target {name!r} must not include credentials, query, or fragment")
    return url


def load_local_targets():
    targets = {DEFAULT_TARGET: validate_local_target(DEFAULT_TARGET, LOCAL_TARGET)}
    if not LOCAL_TARGETS_RAW.strip():
        return targets

    try:
        configured = json.loads(LOCAL_TARGETS_RAW)
    except json.JSONDecodeError as exc:
        raise RuntimeError("LOCAL_TARGETS must be a JSON object mapping target names to URLs") from exc

    if not isinstance(configured, dict):
        raise RuntimeError("LOCAL_TARGETS must be a JSON object mapping target names to URLs")

    for name, url in configured.items():
        targets[name] = validate_local_target(name, url)
    return targets


LOCAL_TARGETS = load_local_targets()


def resolve_target(item):
    # Render should send a logical target key, not an arbitrary URL.
    # 'port' is supported for simple port-based routing when its value is
    # explicitly present as a key in LOCAL_TARGETS (for example, "8000").
    target = item.get("target", item.get("target_id", item.get("port", DEFAULT_TARGET)))
    if isinstance(target, int):
        target = str(target)
    if (
        isinstance(target, str)
        and target not in LOCAL_TARGETS
        and target.startswith("port")
        and target[4:].isdigit()
        and target[4:] in LOCAL_TARGETS
    ):
        target = target[4:]
    if not isinstance(target, str) or target not in LOCAL_TARGETS:
        raise TargetSelectionError(
            "Unknown local target. Configure it in LOCAL_TARGETS and send its key as 'target'."
        )
    return LOCAL_TARGETS[target]


async def send_message(ws, message):
    async with send_lock:
        await ws.send(json.dumps(message))


async def handle_request(ws, client, item):
    if item.get("type") == "websocket_open":
        await handle_websocket_request(ws, item)
        return

    request_id = item.get("id", "")
    response_started = False

    try:
        target_url = resolve_target(item)
        body = base64.b64decode(item.get("body", ""), validate=True)
        if len(body) > MAX_BODY:
            raise ValueError("Request body too large")

        method = item.get("method", "GET").upper()
        allowed = {
            "GET", "POST", "PUT", "PATCH",
            "DELETE", "OPTIONS", "HEAD",
        }
        if method not in allowed:
            raise ValueError("Unsupported method")

        path = item.get("path", "/")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Invalid path")

        query = item.get("query", "")
        if not isinstance(query, str) or query.startswith("//"):
            raise ValueError("Invalid query")

        url = target_url + path
        if query:
            url += "?" + query

        headers = []
        blocked = {
            "host", "authorization", "cookie", "connection",
            "content-length", "transfer-encoding", "upgrade",
            "proxy-authorization", "proxy-connection",
        }

        item_headers = item.get("headers", [])
        if isinstance(item_headers, dict):
            item_headers = item_headers.items()
        for name, value in item_headers:
            if isinstance(name, str) and name.lower() not in blocked:
                headers.append((name, value))

        async with client.stream(
            method,
            url,
            headers=headers,
            content=body,
            follow_redirects=False,
        ) as response:
            response_headers = [
                [name, value] for name, value in response.headers.multi_items()
                if name.lower() not in {
                    "connection", "transfer-encoding", "content-length",
                    "set-cookie", "keep-alive", "upgrade",
                }
            ]
            await send_message(ws, {
                "id": request_id,
                "type": "start",
                "status": response.status_code,
                "headers": response_headers,
            })
            response_started = True
            async for chunk in response.aiter_raw(chunk_size=CHUNK_SIZE):
                if chunk:
                    await send_message(ws, {
                        "id": request_id,
                        "type": "chunk",
                        "body": base64.b64encode(chunk).decode("ascii"),
                    })
            await send_message(ws, {"id": request_id, "type": "end"})

    except Exception as exc:
        try:
            if not response_started:
                status = 403 if isinstance(exc, TargetSelectionError) else 502
                await send_message(ws, {
                    "id": request_id,
                    "type": "start",
                    "status": status,
                    "headers": [["content-type", "text/plain; charset=utf-8"]],
                })
            await send_message(ws, {
                "id": request_id,
                "type": "chunk",
                "body": base64.b64encode(("Local request failed: " + str(exc)).encode()).decode("ascii"),
            })
            await send_message(ws, {"id": request_id, "type": "end"})
        except Exception:
            pass


async def handle_websocket_request(ws, item):
    request_id = item.get("id", "")
    incoming = asyncio.Queue(maxsize=32)
    websocket_sessions[request_id] = incoming
    try:
        target_url = resolve_target(item)
        parsed_target = urlsplit(target_url)
        path = item.get("path", "/")
        query = item.get("query", "")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Invalid WebSocket path")
        if not isinstance(query, str) or query.startswith("//"):
            raise ValueError("Invalid WebSocket query")

        scheme = "wss" if parsed_target.scheme == "https" else "ws"
        local_path = parsed_target.path.rstrip("/") + path
        local_url = f"{scheme}://{parsed_target.netloc}{local_path}"
        if query:
            local_url += "?" + query

        blocked = {
            "host", "authorization", "cookie", "connection", "upgrade",
            "content-length", "transfer-encoding", "proxy-authorization",
            "proxy-connection",
        }
        headers = [
            (name, value)
            for name, value in item.get("headers", [])
            if isinstance(name, str)
            and name.lower() not in blocked
            and not name.lower().startswith("sec-websocket-")
        ]
        async with websockets.connect(
            local_url,
            additional_headers=headers,
            subprotocols=item.get("subprotocols") or None,
            open_timeout=15,
            ping_interval=20,
            ping_timeout=20,
            max_size=MAX_WEBSOCKET_FRAME,
        ) as local_ws:
            await send_message(
                ws,
                {
                    "id": request_id,
                    "type": "websocket_opened",
                    "subprotocol": local_ws.subprotocol,
                },
            )

            async def forward_local_messages():
                try:
                    async for message in local_ws:
                        if isinstance(message, bytes):
                            await send_message(
                                ws,
                                {
                                    "id": request_id,
                                    "type": "websocket_frame",
                                    "binary": base64.b64encode(message).decode("ascii"),
                                },
                            )
                        else:
                            await send_message(
                                ws,
                                {
                                    "id": request_id,
                                    "type": "websocket_frame",
                                    "text": message,
                                },
                            )
                finally:
                    await send_message(
                        ws,
                        {
                            "id": request_id,
                            "type": "websocket_close",
                            "code": local_ws.close_code or 1000,
                            "reason": local_ws.close_reason or "",
                        },
                    )

            forward_task = asyncio.create_task(forward_local_messages())
            try:
                while not forward_task.done():
                    receive_task = asyncio.create_task(incoming.get())
                    done, _ = await asyncio.wait(
                        {receive_task, forward_task},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if receive_task not in done:
                        receive_task.cancel()
                        await asyncio.gather(receive_task, return_exceptions=True)
                        break
                    message = receive_task.result()
                    if message.get("type") == "websocket_close":
                        await local_ws.close(
                            code=int(message.get("code", 1000)),
                            reason=str(message.get("reason", ""))[:123],
                        )
                        break
                    if message.get("type") != "websocket_frame":
                        continue
                    if "binary" in message:
                        frame = base64.b64decode(message["binary"], validate=True)
                    else:
                        frame = message.get("text", "")
                    frame_size = (
                        len(frame)
                        if isinstance(frame, bytes)
                        else len(frame.encode("utf-8"))
                    )
                    if frame_size > MAX_WEBSOCKET_FRAME:
                        await local_ws.close(code=1009, reason="WebSocket frame too large")
                        break
                    await local_ws.send(frame)
            finally:
                forward_task.cancel()
                await asyncio.gather(forward_task, return_exceptions=True)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        try:
            await send_message(
                ws,
                {
                    "id": request_id,
                    "type": "websocket_open_failed",
                    "error": str(exc)[:200],
                },
            )
        except Exception:
            pass
    finally:
        websocket_sessions.pop(request_id, None)


async def run():
    if not TUNNEL_URL.startswith("https://"):
        raise RuntimeError("TUNNEL_URL must start with https://")
    if not AGENT_TOKEN:
        raise RuntimeError("Set TUNNEL_AGENT_TOKEN first")

    ws_url = TUNNEL_URL.replace("https://", "wss://", 1)
    ws_url += "/_tunnel/agent"
    if PUBLIC_ACCESS:
        ws_url += "?public_access=true"

    print("Configured local targets:")
    for name, url in LOCAL_TARGETS.items():
        print(f"  {name}: {url}")
    print("Default target:", DEFAULT_TARGET)
    if PUBLIC_ACCESS:
        print("WARNING: Website access is public; anyone with the tunnel URL can access it.")

    timeout = httpx.Timeout(connect=15, read=None, write=30, pool=15)
    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            try:
                print("Connecting to", ws_url)

                async with websockets.connect(
                    ws_url,
                    additional_headers={
                        "Authorization": f"Bearer {AGENT_TOKEN}",
                        "X-Tunnel-Public-Access": str(PUBLIC_ACCESS).lower(),
                    },
                    ping_interval=20,
                    ping_timeout=20,
                    max_size=4 * 1024 * 1024,
                ) as ws:
                    print("Tunnel connected")

                    tasks = set()
                    async for raw in ws:
                        item = json.loads(raw)
                        if item.get("type") in {
                            "websocket_frame",
                            "websocket_close",
                        }:
                            session = websocket_sessions.get(item.get("id", ""))
                            if session is not None:
                                await session.put(item)
                            continue
                        task = asyncio.create_task(
                            handle_request(ws, client, item)
                        )
                        tasks.add(task)
                        task.add_done_callback(tasks.discard)

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                response = getattr(exc, "response", None)
                if getattr(response, "status_code", None) in {401, 403}:
                    print("Authentication rejected (HTTP 403).")
                    print(
                        "Check that TUNNEL_AGENT_TOKEN matches the value "
                        "configured on the Render service, then restart it."
                    )
                    return

                print("Disconnected:", repr(exc))
                print("Retrying in 3 seconds...")
                await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(run())
