"""Smoke test live REST and Streamable HTTP MCP endpoints."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

import httpx


async def run_smoke_test(base_url: str, token: str | None) -> int:
    """Verify /healthz, /readyz, and /mcp Streamable HTTP initialize + tools/list."""
    base = base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=20.0) as client:
        health = await client.get(f"{base}/healthz")
        print(f"GET /healthz -> {health.status_code}: {health.text}")
        if health.status_code != 200:
            return 1

        ready = await client.get(f"{base}/readyz")
        print(f"GET /readyz -> {ready.status_code}: {ready.text}")

        if not token:
            unauth = await client.post(
                f"{base}/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            )
            print(f"Unauthenticated POST /mcp -> {unauth.status_code}")
            return 0 if unauth.status_code == 401 else 1

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        init_resp = await client.post(
            f"{base}/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "smoke-test", "version": "0.1.0"},
                },
            },
        )
        print(f"POST /mcp (initialize) -> {init_resp.status_code}")
        if init_resp.status_code != 200:
            print(init_resp.text)
            return 1

        tools_resp = await client.post(
            f"{base}/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        print(f"POST /mcp (tools/list) -> {tools_resp.status_code}")
        if tools_resp.status_code != 200:
            print(tools_resp.text)
            return 1
        print(json.dumps({"mcp_response_preview": tools_resp.text[:400]}, indent=2))
    return 0


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Smoke-test REST + MCP endpoints.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default=None)
    args = parser.parse_args()
    return asyncio.run(run_smoke_test(args.base_url, args.token))


if __name__ == "__main__":
    sys.exit(main())
