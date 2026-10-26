import asyncio
import json
import sys
import unittest
from unittest.mock import patch

with patch.object(sys.stdin, "isatty", return_value=False):
    import client


class ResolveTargetTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
