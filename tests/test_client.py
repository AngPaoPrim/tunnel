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


if __name__ == "__main__":
    unittest.main()
