"""Indexer boundary. Rules consume FileIndex and never see parser nodes."""

from __future__ import annotations

from typing import Protocol

from vyarth.model import FileIndex


class AnalysisBackend(Protocol):
    def index_source(
        self,
        path: str,
        source: str,
        *,
        fold: dict[str, str] | None = None,
        duplicate_min_statements: int = 5,
    ) -> FileIndex:
        """Index one module. `index_source` is pure so a process pool can wrap it later."""
