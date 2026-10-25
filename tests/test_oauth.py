import base64
import hashlib
import importlib
import os
import re
import tempfile
import time
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import httpx
from fastapi import FastAPI

from oauth import install_oauth, public_base_url
from oauth_store import SQLiteMapping


BASE_URL = "https://tunnel-8fvo.onrender.com"
RESOURCE = BASE_URL + "/t/mcp/nexa"
CLIENT_ID = "static-test-client"
CLIENT_SECRET = "static-test-secret"
REDIRECT_URI = "https://chatgpt.com/connector/oauth/1DlruA5mlFg4"
USERNAME = "test-user"
PASSWORD = "test-password"
VERIFIER = "v" * 43
CHALLENGE = base64.urlsafe_b64encode(
    hashlib.sha256(VERIFIER.encode("ascii")).digest()
).rstrip(b"=").decode("ascii")


class OAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.storage_dir = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            os.environ,
            {
                "PUBLIC_BASE_URL": BASE_URL,
                "OAUTH_CLIENT_ID": CLIENT_ID,
                "OAUTH_CLIENT_SECRET": CLIENT_SECRET,
                "OAUTH_REDIRECT_URIS": REDIRECT_URI,
                "OAUTH_USERNAME": USERNAME,
                "OAUTH_PASSWORD": PASSWORD,
                "OAUTH_ALLOWED_TARGETS": "default",
                "OAUTH_DB_PATH": os.path.join(
                    self.storage_dir.name, "oauth.sqlite3"
                ),
            },
        )
        self.environment.start()
        self.app = FastAPI()
        self.tokens = install_oauth(self.app)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        )

    async def asyncTearDown(self):
        await self.client.aclose()
        self.environment.stop()
        self.storage_dir.cleanup()

    async def authorize(
        self, client=None, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI
    ):
        client = client or self.client
        authorization = await client.get(
            "/oauth/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "resource": RESOURCE,
                "scope": "mcp",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "state": "state-test",
            },
        )
        if authorization.status_code != 200:
            return authorization, None
        transaction_id = re.search(
            r'name="transaction_id" value="([^"]+)"', authorization.text
        ).group(1)
        csrf = re.search(r'name="csrf" value="([^"]+)"', authorization.text).group(1)
        consent = await client.post(
            "/oauth/authorize/consent",
            data={
                "transaction_id": transaction_id,
                "csrf": csrf,
                "username": USERNAME,
                "password": PASSWORD,
                "approve": "yes",
            },
            follow_redirects=False,
        )
        code = parse_qs(urlsplit(consent.headers["location"]).query)["code"][0]
        self.assertEqual(parse_qs(urlsplit(consent.headers["location"]).query)["state"], ["state-test"])
        return authorization, code

    def token_form(self, code, client_id=CLIENT_ID, secret=CLIENT_SECRET):
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": VERIFIER,
            "resource": RESOURCE,
        }
        if secret is not None:
            form["client_secret"] = secret
        return form

    async def test_static_registration_and_authorization_survive_reinitialization(self):
        registered = await self.client.post(
            "/oauth/register", json={"redirect_uris": [REDIRECT_URI]}
        )
        self.assertEqual(registered.status_code, 201)
        registration = registered.json()
        self.assertNotEqual(registration["client_id"], CLIENT_ID)
        self.assertEqual(registration["token_endpoint_auth_method"], "none")
        self.assertNotIn("client_secret", registration)

        restarted_app = FastAPI()
        install_oauth(restarted_app)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=restarted_app), base_url="http://test"
        ) as restarted_client:
            dynamic_authorization, _ = await self.authorize(
                restarted_client, client_id=registration["client_id"]
            )
            static_authorization, _ = await self.authorize(
                restarted_client, client_id=CLIENT_ID
            )
        self.assertEqual(dynamic_authorization.status_code, 200)
        self.assertEqual(static_authorization.status_code, 200)

    async def test_render_external_url_is_used_for_oauth_metadata(self):
        render_url = "https://new-service.onrender.com"
        with tempfile.TemporaryDirectory() as storage_dir, patch.dict(
            os.environ,
            {
                "PUBLIC_BASE_URL": "",
                "RENDER_EXTERNAL_URL": render_url,
                "OAUTH_DB_PATH": os.path.join(storage_dir, "oauth.sqlite3"),
            },
        ):
            self.assertEqual(public_base_url(), render_url)
            render_app = FastAPI()
            install_oauth(render_app)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=render_app),
                base_url="http://test",
            ) as render_client:
                protected = await render_client.get(
                    "/.well-known/oauth-protected-resource/t/mcp/nexa"
                )
                authorization_server = await render_client.get(
                    "/.well-known/oauth-authorization-server"
                )
                resource_authorization_server = await render_client.get(
                    "/.well-known/oauth-authorization-server/t/mcp/nexa"
                )

        self.assertEqual(protected.json()["resource"], render_url + "/t/mcp/nexa")
        self.assertEqual(
            protected.json()["authorization_servers"], [render_url]
        )
        metadata = authorization_server.json()
        self.assertEqual(metadata["issuer"], render_url)
        self.assertEqual(
            metadata["registration_endpoint"], render_url + "/oauth/register"
        )
        self.assertEqual(resource_authorization_server.status_code, 200)
        self.assertEqual(resource_authorization_server.json(), metadata)

    async def test_static_registration_and_authorization_reject_redirect_mismatch(self):
        wrong_redirect = REDIRECT_URI + "/"
        registration = await self.client.post(
            "/oauth/register", json={"redirect_uris": [wrong_redirect]}
        )
        self.assertEqual(registration.status_code, 201)

        authorization, _ = await self.authorize(
            client_id=registration.json()["client_id"], redirect_uri=REDIRECT_URI
        )
        self.assertEqual(authorization.status_code, 400)
        self.assertEqual(authorization.json()["error"], "invalid_request")

        invalid_registration = await self.client.post(
            "/oauth/register",
            json={"redirect_uris": ["http://example.com/callback"]},
        )
        self.assertEqual(invalid_registration.status_code, 400)
        self.assertEqual(invalid_registration.json()["error"], "invalid_redirect_uri")

    async def test_dynamic_registration_is_public_client_without_static_config(self):
        for name in ("OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET", "OAUTH_REDIRECT_URIS"):
            os.environ.pop(name, None)
        os.environ["OAUTH_DB_PATH"] = os.path.join(
            self.storage_dir.name, "dynamic.sqlite3"
        )
        dynamic_app = FastAPI()
        install_oauth(dynamic_app)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dynamic_app), base_url="http://test"
        ) as dynamic_client:
            response = await dynamic_client.post(
                "/oauth/register",
                json={"redirect_uris": [REDIRECT_URI]},
            )
        registration = response.json()
        self.assertEqual(response.status_code, 201)
        self.assertNotEqual(registration["client_id"], CLIENT_ID)
        self.assertEqual(registration["token_endpoint_auth_method"], "none")

        restarted_app = FastAPI()
        install_oauth(restarted_app)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=restarted_app), base_url="http://test"
        ) as restarted_client:
            authorization, code = await self.authorize(
                restarted_client,
                client_id=registration["client_id"],
            )
            self.assertEqual(authorization.status_code, 200)
            exchanged = await restarted_client.post(
                "/oauth/token",
                data=self.token_form(
                    code, client_id=registration["client_id"], secret=None
                ),
            )
            self.assertEqual(exchanged.status_code, 200)
            issued = exchanged.json()

        second_restart = FastAPI()
        install_oauth(second_restart)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=second_restart), base_url="http://test"
        ) as restarted_client:
            refreshed = await restarted_client.post(
                "/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": issued["refresh_token"],
                    "client_id": registration["client_id"],
                    "resource": RESOURCE,
                },
            )
            self.assertEqual(refreshed.status_code, 200)
            rotated = refreshed.json()["refresh_token"]
            reused = await restarted_client.post(
                "/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": issued["refresh_token"],
                    "client_id": registration["client_id"],
                    "resource": RESOURCE,
                },
            )
            self.assertEqual(reused.json()["error"], "invalid_grant")
            refreshed_again = await restarted_client.post(
                "/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": rotated,
                    "client_id": registration["client_id"],
                    "resource": RESOURCE,
                },
            )
            self.assertEqual(refreshed_again.status_code, 200)

    async def test_expired_refresh_token_remains_invalid_after_restart(self):
        _, code = await self.authorize()
        exchanged = await self.client.post(
            "/oauth/token", data=self.token_form(code)
        )
        refresh_token = exchanged.json()["refresh_token"]

        refresh_store = SQLiteMapping(os.environ["OAUTH_DB_PATH"], "refresh_tokens")
        record = refresh_store[refresh_token]
        record["expires_at"] = time.time() - 1
        refresh_store[refresh_token] = record

        restarted_app = FastAPI()
        install_oauth(restarted_app)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=restarted_app), base_url="http://test"
        ) as restarted_client:
            response = await restarted_client.post(
                "/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "resource": RESOURCE,
                },
            )
        self.assertEqual(response.json()["error"], "invalid_grant")

    async def test_code_and_refresh_exchange_use_advertised_auth_method(self):
        _, code = await self.authorize()
        self.assertIsNotNone(code)
        rejected = await self.client.post(
            "/oauth/token", data=self.token_form(code, secret="wrong-secret")
        )
        self.assertEqual(rejected.status_code, 401)
        self.assertEqual(rejected.json()["error"], "invalid_client")

        exchanged = await self.client.post(
            "/oauth/token", data=self.token_form(code)
        )
        self.assertEqual(exchanged.status_code, 200)
        tokens = exchanged.json()
        self.assertEqual(tokens["token_type"], "Bearer")
        self.assertEqual(tokens["scope"], "mcp")

        refreshed = await self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "resource": RESOURCE,
            },
        )
        self.assertEqual(refreshed.status_code, 200)

    async def test_unknown_client_and_invalid_codes_are_rejected(self):
        unknown = await self.client.get(
            "/oauth/authorize",
            params={
                "client_id": "unknown-client",
                "redirect_uri": REDIRECT_URI + "/unregistered",
                "response_type": "code",
            },
        )
        self.assertEqual(unknown.json()["error"], "invalid_client")

        _, code = await self.authorize()
        bad_client = await self.client.post(
            "/oauth/token", data=self.token_form(code, client_id="unknown-client")
        )
        self.assertEqual(bad_client.status_code, 401)
        self.assertEqual(bad_client.json()["error"], "invalid_client")

        invalid_code = await self.client.post(
            "/oauth/token", data=self.token_form("unknown-code")
        )
        self.assertEqual(invalid_code.json()["error"], "invalid_grant")

        invalid_refresh = await self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "unknown-refresh-token",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "resource": RESOURCE,
            },
        )
        self.assertEqual(invalid_refresh.json()["error"], "invalid_grant")

    async def test_missing_public_client_is_restored_for_configured_redirect(self):
        client_id = "chatgpt-public-client"
        authorization, code = await self.authorize(client_id=client_id)

        self.assertEqual(authorization.status_code, 200)
        self.assertIsNotNone(code)

        exchanged = await self.client.post(
            "/oauth/token",
            data=self.token_form(code, client_id=client_id, secret=None),
        )
        self.assertEqual(exchanged.status_code, 200)

    async def test_mcp_bearer_validation_and_target_permissions(self):
        with patch.dict(
            os.environ,
            {
                "PUBLIC_BASE_URL": BASE_URL,
                "OAUTH_CLIENT_ID": CLIENT_ID,
                "OAUTH_CLIENT_SECRET": CLIENT_SECRET,
                "OAUTH_REDIRECT_URIS": REDIRECT_URI,
                "OAUTH_USERNAME": USERNAME,
                "OAUTH_PASSWORD": PASSWORD,
                "OAUTH_ALLOWED_TARGETS": "default",
            },
        ):
            relay = importlib.reload(importlib.import_module("app"))
        previous_tokens = dict(relay.access_tokens)
        relay.access_tokens.clear()
        relay.access_tokens["test-access-token"] = {
            "resource": RESOURCE,
            "scope": "mcp",
            "targets": ["default"],
            "expires_at": 9999999999,
        }
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=relay.app), base_url="http://test"
            ) as relay_client:
                valid = await relay_client.get(
                    "/t/mcp/nexa",
                    headers={"Authorization": "Bearer test-access-token"},
                )
                missing = await relay_client.get("/t/mcp/nexa")
                unauthorized = await relay_client.get(
                    "/t/mcp/nexa", headers={"Authorization": "Bearer invalid-token"}
                )
                forbidden = await relay_client.get(
                    "/t/ports/other/data",
                    headers={"Authorization": "Bearer test-access-token"},
                )
            self.assertEqual(valid.status_code, 503)
            self.assertEqual(missing.status_code, 401)
            self.assertEqual(unauthorized.status_code, 401)
            self.assertEqual(forbidden.status_code, 403)
        finally:
            relay.access_tokens.clear()
            relay.access_tokens.update(previous_tokens)

    async def test_browser_login_and_direct_port_route(self):
        relay = importlib.reload(importlib.import_module("app"))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=relay.app), base_url="https://test"
        ) as browser:
            unauthorized_api = await browser.get(
                "/t/port/3737", headers={"Accept": "application/json"}
            )
            self.assertEqual(unauthorized_api.status_code, 401)

            redirect = await browser.get(
                "/t/port/3737", headers={"Accept": "text/html"}
            )
            self.assertEqual(redirect.status_code, 303)
            self.assertTrue(redirect.headers["location"].startswith("/t/login?"))

            login_page = await browser.get(redirect.headers["location"])
            self.assertEqual(login_page.status_code, 200)
            state = re.search(
                r'name="state" value="([^"]+)"', login_page.text
            ).group(1)
            csrf = re.search(
                r'name="csrf" value="([^"]+)"', login_page.text
            ).group(1)
            login_form = {
                "state": state,
                "csrf": csrf,
                "next": "/t/port/3737",
                "username": USERNAME,
                "password": PASSWORD,
            }

            rejected = await browser.post(
                "/t/login",
                data={**login_form, "password": "wrong-password"},
                headers={"Origin": BASE_URL},
                follow_redirects=False,
            )
            self.assertEqual(rejected.status_code, 200)
            self.assertNotIn("nexa_browser_session", browser.cookies)

            cross_origin = await browser.post(
                "/t/login",
                data=login_form,
                headers={"Origin": "https://attacker.example"},
                follow_redirects=False,
            )
            self.assertEqual(cross_origin.status_code, 403)

            accepted = await browser.post(
                "/t/login",
                data=login_form,
                headers={"Origin": BASE_URL},
                follow_redirects=False,
            )
            self.assertEqual(accepted.status_code, 303)
            cookie_header = accepted.headers["set-cookie"].lower()
            self.assertIn("httponly", cookie_header)
            self.assertIn("secure", cookie_header)
            self.assertIn("samesite=lax", cookie_header)
            self.assertIn("nexa_browser_session", browser.cookies)

            proxied = await browser.get(
                "/t/port/3737", headers={"Accept": "text/html"}
            )
            self.assertEqual(proxied.status_code, 307)
            self.assertEqual(proxied.headers["location"], "/t/port/3737/")

            directory = await browser.get(
                "/t/port/3737/", headers={"Accept": "text/html"}
            )
            self.assertEqual(directory.status_code, 503)

            file_request = await browser.get(
                "/t/port/3737/readme.txt", headers={"Accept": "text/html"}
            )
            self.assertEqual(file_request.status_code, 503)

            # The root redirect must preserve query parameters.
            queried_root = await browser.get(
                "/t/port/3737?download=1",
                headers={"Accept": "text/html"},
            )
            self.assertEqual(queried_root.status_code, 307)
            self.assertEqual(
                queried_root.headers["location"], "/t/port/3737/?download=1"
            )

            invalid_port = await browser.get(
                "/t/port/70000", headers={"Accept": "text/html"}
            )
            self.assertEqual(invalid_port.status_code, 404)

    async def test_public_site_access_skips_login_but_keeps_mcp_protected(self):
        relay = importlib.reload(importlib.import_module("app"))
        previous_public_access = relay.agent_public_access
        relay.agent_public_access = True
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=relay.app),
                base_url="https://test",
            ) as browser:
                website = await browser.get(
                    "/t/port/3737/", headers={"Accept": "text/html"}
                )
                mcp = await browser.get(
                    "/t/mcp/nexa", headers={"Accept": "application/json"}
                )

            self.assertEqual(website.status_code, 503)
            self.assertNotIn("/t/login", website.headers.get("location", ""))
            self.assertEqual(mcp.status_code, 401)
        finally:
            relay.agent_public_access = previous_public_access


if __name__ == "__main__":
    unittest.main()