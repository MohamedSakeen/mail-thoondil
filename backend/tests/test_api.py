"""Tests for the API endpoints.

These tests set SKIP_DB=1 to run without a PostgreSQL instance.
"""

import io
import os
import pytest
from httpx import AsyncClient, ASGITransport

# Force skip DB for tests
os.environ["SKIP_DB"] = "1"

from app.main import app


EMAIL_BYTES = b"""\
From: Microsoft Security <security@micros0ft.example>
Reply-To: attacker@evil.example
To: user@example.com
Subject: Urgent account verification
Authentication-Results: example; spf=fail; dkim=pass; dmarc=fail
Content-Type: text/plain; charset=utf-8

Your account will be suspended. Verify your password immediately:
https://1.2.3.4/login
"""


@pytest.mark.asyncio
class TestAnalyzeEndpoint:
    async def test_analyze_email(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            files = {"email": ("test.eml", io.BytesIO(EMAIL_BYTES), "message/rfc822")}
            response = await client.post("/api/v1/analyze", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data["schema_version"] == "1.0"
        assert "analysis_id" in data
        assert "risk" in data
        assert "signals" in data
        assert "verdict" in data
        assert data["risk"]["classification"] in ("benign", "suspicious", "high_suspicious", "phishing")

    async def test_analyze_phishing_detected(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            files = {"email": ("phish.eml", io.BytesIO(EMAIL_BYTES), "message/rfc822")}
            response = await client.post("/api/v1/analyze", files=files)

        data = response.json()
        assert data["risk"]["score"] >= 25
        assert len(data["signals"]) > 0

    async def test_analyze_empty_file(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            files = {"email": ("empty.eml", io.BytesIO(b""), "message/rfc822")}
            response = await client.post("/api/v1/analyze", files=files)

        assert response.status_code == 400

    async def test_analyze_no_file(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/analyze")

        assert response.status_code == 422

    async def test_health_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_stats_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/stats")

        assert response.status_code == 200
        data = response.json()
        assert "schema_version" in data
        assert "rule_version" in data
        assert "ml_model_version" in data

    async def test_list_analyses_empty(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/analyses")

        assert response.status_code == 200
        assert response.json() == []

    async def test_get_nonexistent_analysis(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/analyses/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 503

    async def test_get_invalid_analysis_id(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/analyses/not-a-uuid")

        assert response.status_code == 400

    async def test_feedback_no_db(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/analyses/00000000-0000-0000-0000-000000000000/feedback",
                json={"verdict_agreement": "agree"},
            )

        assert response.status_code == 503

    async def test_analyze_response_structure(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            files = {"email": ("test.eml", io.BytesIO(EMAIL_BYTES), "message/rfc822")}
            response = await client.post("/api/v1/analyze", files=files)

        data = response.json()
        # Verify all expected top-level keys
        expected_keys = [
            "schema_version", "analysis_id", "metadata", "sender",
            "authentication", "headers", "urls", "content", "html",
            "attachments", "relationships", "signals", "risk", "verdict",
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"

        # Verify risk structure
        assert "score" in data["risk"]
        assert "classification" in data["risk"]

        # Verify verdict structure
        assert "classification" in data["verdict"]
        assert "reasons" in data["verdict"]
