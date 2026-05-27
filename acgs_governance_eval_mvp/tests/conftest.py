from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from governance.policy_loader import load_policy_bundle, load_roles

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

if sys.version_info >= (3, 14):
    try:
        import fastapi.testclient as fastapi_testclient
        import httpx
        import starlette.testclient as starlette_testclient
    except Exception:
        pass
    else:

        class _CompatTestClient:
            __test__ = False

            def __init__(self, app, *, base_url: str = "http://testserver", **kwargs):
                self.app = app
                self.base_url = base_url

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

            def close(self) -> None:
                return None

            def request(self, method: str, url: str, **kwargs):
                async def run_request():
                    transport = httpx.ASGITransport(app=self.app)
                    async with httpx.AsyncClient(transport=transport, base_url=self.base_url) as client:
                        response = await client.request(method, url, **kwargs)
                        await response.aread()
                        return response

                return asyncio.run(run_request())

            def get(self, url: str, **kwargs):
                return self.request("GET", url, **kwargs)

            def post(self, url: str, **kwargs):
                return self.request("POST", url, **kwargs)

        fastapi_testclient.TestClient = _CompatTestClient
        starlette_testclient.TestClient = _CompatTestClient


@pytest.fixture()
def roles_bundle():
    return load_roles("governance/roles.json")


@pytest.fixture()
def policy_bundle():
    return load_policy_bundle("governance/policies/2026-05")
