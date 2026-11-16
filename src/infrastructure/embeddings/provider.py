"""Lightweight HTTP and deterministic embedding adapters (no heavy ML deps)."""

from __future__ import annotations

import hashlib
import math
import re

import httpx

from src.domain.ports import EmbeddingProvider
from src.infrastructure.config import Settings

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


class DeterministicTestEmbedder:
    """Zero-dependency normalized vector embedder for tests and offline fallback."""

    def __init__(self, dimensions: int = 1536) -> None:
        self._dimensions = dimensions

    @property
    def dimensions(self) -> int:
        """Return configured vector dimension count."""
        return self._dimensions

    async def embed_text(self, text: str) -> list[float]:
        """Generate a deterministic unit-length bag-of-tokens projection vector."""
        vec = [0.0] * self._dimensions
        tokens = _TOKEN_RE.findall(text.lower()) or ["empty"]
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % self._dimensions
            sign = 1.0 if (digest[4] & 1) == 0 else -1.0
            vec[bucket] += sign

        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            vec[0] = 1.0
            return vec
        return [v / norm for v in vec]


class HttpEmbeddingProvider:
    """Async httpx client supporting OpenAI, Vercel AI Gateway, and Gemini embeddings."""

    def __init__(
        self,
        *,
        provider: str,
        api_key: str,
        model: str,
        dimensions: int,
        base_url: str,
    ) -> None:
        self._provider = provider
        self._api_key = api_key
        self._model = model
        self._dimensions = dimensions
        self._base_url = base_url.rstrip("/")

    @property
    def dimensions(self) -> int:
        """Return configured vector dimension count."""
        return self._dimensions

    async def embed_text(self, text: str) -> list[float]:
        """Request an embedding vector from the configured HTTP endpoint."""
        if not self._api_key:
            raise RuntimeError(
                f"EMBEDDING_API_KEY is required when EMBEDDING_PROVIDER='{self._provider}'."
            )

        if self._provider == "gemini":
            return await self._embed_gemini(text)
        return await self._embed_openai_compatible(text)

    async def _embed_openai_compatible(self, text: str) -> list[float]:
        url = f"{self._base_url}/embeddings"
        payload: dict[str, object] = {
            "input": text,
            "model": self._model,
            "dimensions": self._dimensions,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
        return [float(x) for x in data["data"][0]["embedding"]]

    async def _embed_gemini(self, text: str) -> list[float]:
        model_path = (
            self._model if self._model.startswith("models/") else f"models/{self._model}"
        )
        base = (
            self._base_url
            if "generativelanguage.googleapis.com" in self._base_url
            else "https://generativelanguage.googleapis.com/v1beta"
        )
        url = f"{base}/{model_path}:embedContent"
        payload = {
            "model": model_path,
            "content": {"parts": [{"text": text}]},
            "outputDimensionality": self._dimensions,
        }
        headers = {
            "x-goog-api-key": self._api_key,
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
        return [float(x) for x in data["embedding"]["values"]]


def build_embedding_provider(settings: Settings) -> EmbeddingProvider:
    """Build the configured EmbeddingProvider."""
    if settings.embedding_provider == "deterministic":
        return DeterministicTestEmbedder(dimensions=settings.embedding_dimensions)

    if not settings.embedding_api_key.strip() and settings.environment in {
        "development",
        "test",
    }:
        return DeterministicTestEmbedder(dimensions=settings.embedding_dimensions)

    return HttpEmbeddingProvider(
        provider=settings.embedding_provider,
        api_key=settings.embedding_api_key.strip(),
        model=settings.embedding_model,
        dimensions=settings.embedding_dimensions,
        base_url=settings.embedding_base_url,
    )
