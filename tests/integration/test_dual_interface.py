"""End-to-end integration tests for dual REST + FastMCP Streamable HTTP interfaces."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import httpx2
import jwt
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from src.domain.models import RunbookStep, StepRiskLevel
from src.infrastructure.auth.jwt import SupabaseJwtVerifier
from src.infrastructure.config import Settings
from src.infrastructure.embeddings.provider import DeterministicTestEmbedder
from src.infrastructure.security.approval_tokens import HmacApprovalSigner
from src.main import create_app
from tests.fakes import InMemoryStore, build_fake_uow_factory

TEST_JWT_SECRET = "integration-test-jwt-secret-32-bytes"


def _mint_jwt(user_id: UUID, email: str = "ic@example.com") -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "aud": "authenticated",
            "iss": "https://demo.supabase.co/auth/v1",
            "role": "authenticated",
            "email": email,
            "exp": int((datetime.now(UTC) + timedelta(minutes=15)).timestamp()),
        },
        TEST_JWT_SECRET,
        algorithm="HS256",
    )


def _parse_mcp_response(resp: httpx.Response) -> dict[str, Any]:
    """Decode either JSON or SSE-framed Streamable HTTP JSON-RPC responses."""
    ctype = resp.headers.get("content-type", "")
    if "application/json" in ctype:
        return resp.json()
    for line in resp.text.splitlines():
        if line.startswith("data: "):
            payload = line.removeprefix("data: ").strip()
            if payload:
                return json.loads(payload)
    raise AssertionError(f"Unable to parse Streamable HTTP body: {resp.text}")


async def test_dual_rest_and_stateless_mcp_streamable_http() -> None:
    store = InMemoryStore()
    settings = Settings(
        supabase_url="https://demo.supabase.co",
        supabase_jwt_secret=TEST_JWT_SECRET,
        embedding_provider="deterministic",
        embedding_dimensions=128,
        mcp_stateless_http=True,
        approval_signing_secret="integration-approval-secret",
        environment="test",
    )
    app = create_app(
        settings=settings,
        uow_factory=build_fake_uow_factory(store),
        embedder=DeterministicTestEmbedder(dimensions=128),
        jwt_verifier=SupabaseJwtVerifier(settings),
        approval_signer=HmacApprovalSigner("integration-approval-secret", 300),
    )

    user_a = uuid4()
    user_b = uuid4()
    token_a = _mint_jwt(user_a, "alice@example.com")
    token_b = _mint_jwt(user_b, "bob@example.com")

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            # 1. Health & Readiness
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["mcp_stateless_http"] is True

            ready = await client.get("/readyz")
            assert ready.status_code == 503  # No DATABASE_URL in unit/fake mode

            # 2. Auth guards on BOTH REST and MCP
            assert (await client.get("/api/v1/incidents")).status_code == 401
            unauth_mcp = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            )
            assert unauth_mcp.status_code == 401

            # 3. Verify explicit operation_id definitions in OpenAPI
            schema = (await client.get("/openapi.json")).json()
            op_ids = {
                op["operationId"]
                for path_item in schema["paths"].values()
                for op in path_item.values()
                if isinstance(op, dict) and "operationId" in op
            }
            assert {
                "create_incident",
                "diagnose_incident",
                "transition_incident_status",
                "search_similar_postmortems",
                "execute_runbook_step",
            }.issubset(op_ids)

            # 4. Seed runbook, postmortem, and incident via REST as User A
            headers_a = {"Authorization": f"Bearer {token_a}"}
            rb_resp = await client.post(
                "/api/v1/runbooks",
                headers=headers_a,
                json={
                    "slug": "redis-eviction-spike",
                    "title": "Mitigate Redis Eviction Spike",
                    "service_name": "session-cache",
                    "symptom_summary": "Redis maxmemory eviction causing auth cache misses",
                    "is_shared": True,
                    "steps": [
                        {
                            "step_number": 1,
                            "title": "Raise maxmemory cap",
                            "instruction": "Scale cache memory limit",
                            "command_template": "redis-cli config set maxmemory 4gb",
                            "risk_level": "high",
                            "requires_approval": True,
                            "blast_radius": "Modifies live cache memory allocation.",
                        }
                    ],
                },
            )
            assert rb_resp.status_code == 201

            pm_resp = await client.post(
                "/api/v1/postmortems",
                headers=headers_a,
                json={
                    "title": "Redis eviction outage Q3",
                    "service_name": "session-cache",
                    "root_cause": "Unbounded session keys filled Redis maxmemory",
                    "resolution_summary": "Added TTL and scaled Redis memory",
                    "action_items": ["Enforce session TTL"],
                    "is_shared": True,
                },
            )
            assert pm_resp.status_code == 201

            inc_resp = await client.post(
                "/api/v1/incidents",
                headers=headers_a,
                json={
                    "title": "Session cache eviction storm",
                    "description": "Redis maxmemory reached 100%, evicting active sessions",
                    "severity": "sev1",
                    "service_name": "session-cache",
                    "telemetry": {"evicted_keys_per_sec": 920},
                },
            )
            assert inc_resp.status_code == 201
            incident_id = inc_resp.json()["id"]

            # 5. Tenant isolation check: User B cannot view User A's incident
            headers_b = {"Authorization": f"Bearer {token_b}"}
            assert (
                await client.get(f"/api/v1/incidents/{incident_id}", headers=headers_b)
            ).status_code == 404

            # 6. Call MCP Streamable HTTP endpoint (/mcp) as User A
            mcp_headers = {
                "Authorization": f"Bearer {token_a}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            }
            init_msg = await client.post(
                "/mcp",
                headers=mcp_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest-mcp", "version": "1.0"},
                    },
                },
            )
            assert init_msg.status_code == 200
            assert "Incident-Control-Plane" in _parse_mcp_response(init_msg)["result"][
                "serverInfo"
            ]["name"]

            # List tools in stateless mode (no Mcp-Session-Id needed!)
            tools_msg = await client.post(
                "/mcp",
                headers=mcp_headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            assert tools_msg.status_code == 200
            tool_names = {
                t["name"] for t in _parse_mcp_response(tools_msg)["result"]["tools"]
            }
            assert {
                "diagnose_incident",
                "search_similar_postmortems",
                "transition_incident_status",
                "execute_runbook_step",
            }.issubset(tool_names)

            # Call diagnose_incident over /mcp
            diag_msg = await client.post(
                "/mcp",
                headers=mcp_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "diagnose_incident",
                        "arguments": {"incident_id": incident_id},
                    },
                },
            )
            assert diag_msg.status_code == 200
            diag_payload = _parse_mcp_response(diag_msg)["result"]["structuredContent"]
            assert diag_payload["matched_runbooks"][0]["slug"] == "redis-eviction-spike"
            assert len(diag_payload["similar_postmortems"]) == 1

            # Two-phase HITL execution over stateless /mcp
            step_req = await client.post(
                "/mcp",
                headers=mcp_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "execute_runbook_step",
                        "arguments": {
                            "incident_id": incident_id,
                            "runbook_slug": "redis-eviction-spike",
                            "step_number": 1,
                        },
                    },
                },
            )
            challenge_data = _parse_mcp_response(step_req)["result"]["structuredContent"]
            assert challenge_data["status"] == "confirmation_required"
            approval_token = challenge_data["challenge"]["approval_token"]

            step_confirm = await client.post(
                "/mcp",
                headers=mcp_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "execute_runbook_step",
                        "arguments": {
                            "incident_id": incident_id,
                            "runbook_slug": "redis-eviction-spike",
                            "step_number": 1,
                            "approval_token": approval_token,
                            "justification": "Confirmed during integration test",
                        },
                    },
                },
            )
            exec_data = _parse_mcp_response(step_confirm)["result"]["structuredContent"]
            assert exec_data["status"] == "executed"

            # Verify REST GET sees all MCP-driven audit events via shared domain/uow
            detail = await client.get(
                f"/api/v1/incidents/{incident_id}", headers=headers_a
            )
            assert detail.status_code == 200
            event_types = [ev["event_type"] for ev in detail.json()["events"]]
            assert event_types == [
                "incident_created",
                "incident_diagnosed",
                "runbook_approval_requested",
                "runbook_step_executed",
            ]


async def test_stateful_local_mode_elicitation_and_fallback() -> None:
    """Verify stateful Streamable HTTP transport completes HITL safely across protocol eras."""
    store = InMemoryStore()
    settings = Settings(
        supabase_url="https://demo.supabase.co",
        supabase_jwt_secret=TEST_JWT_SECRET,
        mcp_service_token="local-inspector-token",
        embedding_provider="deterministic",
        embedding_dimensions=64,
        mcp_stateless_http=False,
        approval_signing_secret="local-secret",
        environment="test",
    )
    app = create_app(
        settings=settings,
        uow_factory=build_fake_uow_factory(store),
        embedder=DeterministicTestEmbedder(dimensions=64),
        jwt_verifier=SupabaseJwtVerifier(settings),
        approval_signer=HmacApprovalSigner("local-secret", 300),
    )

    principal = await app.state.container.jwt_verifier.verify("local-inspector-token")
    await app.state.container.runbook_service.create_runbook(
        slug="gw-drain",
        title="Drain edge node",
        service_name="edge-gw",
        symptom_summary="502 upstream reset",
        steps=[
            RunbookStep(
                step_number=1,
                title="Drain edge",
                instruction="Drain node",
                risk_level=StepRiskLevel.CRITICAL,
                requires_approval=True,
            )
        ],
        is_shared=True,
        principal=principal,
    )

    async def approve_handler(message, response_type, params, context):
        return {"confirm": True, "justification": "Approved in local Inspector"}

    def asgi_client_factory(**kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            headers=kwargs.get("headers"),
            timeout=kwargs.get("timeout") or httpx2.Timeout(30.0),
            auth=kwargs.get("auth"),
            follow_redirects=kwargs.get("follow_redirects", True),
        )

    async with app.router.lifespan_context(app):
        transport = StreamableHttpTransport(
            url="http://testserver/mcp",
            headers={"Authorization": "Bearer local-inspector-token"},
            httpx_client_factory=asgi_client_factory,
        )
        async with Client(transport, elicitation_handler=approve_handler) as mcp_client:
            created = await mcp_client.call_tool(
                "trigger_incident",
                {
                    "title": "API 502 spike",
                    "description": "Gateway upstream reset",
                    "severity": "sev2",
                    "service_name": "edge-gw",
                },
            )
            inc_id = created.data["incident_id"]

            first_try = await mcp_client.call_tool(
                "execute_runbook_step",
                {
                    "incident_id": inc_id,
                    "runbook_slug": "gw-drain",
                    "step_number": 1,
                },
            )
            if first_try.data["status"] == "confirmation_required":
                # MCP 2026-07-28 removes push ctx.elicit(); verify automatic challenge fallback
                token = first_try.data["challenge"]["approval_token"]
                second_try = await mcp_client.call_tool(
                    "execute_runbook_step",
                    {
                        "incident_id": inc_id,
                        "runbook_slug": "gw-drain",
                        "step_number": 1,
                        "approval_token": token,
                        "justification": "Confirmed via two-phase fallback",
                    },
                )
                assert second_try.data["status"] == "executed"
            else:
                assert first_try.data["status"] == "executed"
