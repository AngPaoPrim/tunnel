import asyncio
import json
import sys
import unittest
from unittest.mock import patch

with patch.object(sys.stdin, "isatty", return_value=False):
    import client


class ResolveTargetTests(unittest.TestCase):
    def test_default_tunnel_url_uses_active_custom_domain(self):
        self.assertEqual(client.TUNNEL_URL, "https://ang.pao.run.place")

    def test_port_target_resolves_explicit_numeric_key(self):
        with patch.dict(
            client.LOCAL_TARGETS,
            {"8000": "http://127.0.0.1:8000"},
            clear=True,
        ):
            self.assertEqual(
                client.resolve_target({"target": "port8000"}),
                "http://127.0.0.1:8000",
            )

    def test_explicit_port_name_takes_precedence(self):
        with patch.dict(
            client.LOCAL_TARGETS,
            {
                "8000": "http://127.0.0.1:8000",
                "port8000": "http://127.0.0.1:9000",
            },
            clear=True,
        ):
            self.assertEqual(
                client.resolve_target({"target": "port8000"}),
                "http://127.0.0.1:9000",
            )

    def test_unconfigured_port_target_is_rejected(self):
        with patch.dict(client.LOCAL_TARGETS, {}, clear=True):
            with self.assertRaises(client.TargetSelectionError):
                client.resolve_target({"target": "port8000"})

    def test_multiple_local_ports_are_added_as_independent_targets(self):
        targets = client.add_local_port_targets({}, "3737,8080; 3737")

        self.assertEqual(
            targets,
            {
                "port3737": "http://127.0.0.1:3737",
                "port8080": "http://127.0.0.1:8080",
            },
        )
        with patch.dict(client.LOCAL_TARGETS, targets, clear=True):
            self.assertEqual(
                client.resolve_target({"target": "port3737"}),
                "http://127.0.0.1:3737",
            )
            self.assertEqual(
                client.resolve_target({"target": "port8080"}),
                "http://127.0.0.1:8080",
            )


class WebSocketRelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_websocket_frames_are_forwarded_to_local_target(self):
        received_path = []

        async def echo(connection):
            received_path.append(connection.request.path)
            async for message in connection:
                await connection.send(message)

        class RelayConnection:
            def __init__(self):
                self.messages = []
                self.updated = asyncio.Event()

            async def send(self, raw):
                self.messages.append(json.loads(raw))
                self.updated.set()

            async def wait_for(self, message_type):
                while True:
                    for message in self.messages:
                        if message["type"] == message_type:
                            return message
                    self.updated.clear()
                    await asyncio.wait_for(self.updated.wait(), timeout=3)

        async with client.websockets.serve(echo, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            relay = RelayConnection()
            request_id = "websocket-test"
            with patch.dict(
                client.LOCAL_TARGETS,
                {"test": f"http://127.0.0.1:{port}"},
            ):
                task = asyncio.create_task(
                    client.handle_websocket_request(
                        relay,
                        {
                            "id": request_id,
                            "type": "websocket_open",
                            "target": "test",
                            "path": "/socket.io/",
                            "query": "EIO=4&transport=websocket",
                        },
                    )
                )
                await relay.wait_for("websocket_opened")
                incoming = client.websocket_sessions[request_id]
                await incoming.put(
                    {"type": "websocket_frame", "text": "hello"}
                )
                echoed = await relay.wait_for("websocket_frame")
                self.assertEqual(echoed["text"], "hello")
                self.assertEqual(
                    received_path, ["/socket.io/?EIO=4&transport=websocket"]
                )
                await incoming.put(
                    {"type": "websocket_close", "code": 1000}
                )
                await asyncio.wait_for(task, timeout=3)


class TunnelReconnectTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_agent_connection_stops_retrying(self):
        class DuplicateConnectionError(Exception):
            code = 1013
            reason = "Tunnel agent already connected"

        class FakeConnection:
            async def __aenter__(self):
                raise DuplicateConnectionError

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        class FakeHttpClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        with (
            patch.object(client, "AGENT_TOKEN", "test-token"),
            patch.object(
                client.httpx,
                "AsyncClient",
                return_value=FakeHttpClient(),
            ),
            patch.object(
                client.websockets,
                "connect",
                return_value=FakeConnection(),
            ) as connect,
            patch.object(client.asyncio, "sleep") as sleep,
        ):
            await client.run()

        connect.assert_called_once()
        sleep.assert_not_awaited()

    async def test_clean_disconnect_uses_exponential_backoff(self):
        delays = []

        class FakeWebSocket:
            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

        class FakeConnection:
            async def __aenter__(self):
                return FakeWebSocket()

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        class FakeHttpClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        async def capture_delay(delay):
            delays.append(delay)
            if len(delays) == 6:
                raise asyncio.CancelledError

        with (
            patch.object(client, "AGENT_TOKEN", "test-token"),
            patch.object(
                client.httpx,
                "AsyncClient",
                return_value=FakeHttpClient(),
            ),
            patch.object(
                client.websockets,
                "connect",
                side_effect=lambda *args, **kwargs: FakeConnection(),
            ) as connect,
            patch.object(
                client.asyncio,
                "sleep",
                side_effect=capture_delay,
            ),
            patch.object(
                client.random,
                "uniform",
                side_effect=lambda lower, upper: upper,
            ),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await client.run()

        for actual, expected in zip(delays, [3.6, 7.2, 14.4, 28.8, 30, 30]):
            self.assertAlmostEqual(actual, expected)
        self.assertEqual(connect.call_args.kwargs["ping_interval"], 20)
        self.assertEqual(connect.call_args.kwargs["ping_timeout"], 60)


if __name__ == "__main__":
    unittest.main()
