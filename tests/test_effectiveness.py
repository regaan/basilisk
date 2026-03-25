"""
Basilisk Probe Effectiveness and Eval Schema -- test suite.

Tests SQLite-backed effectiveness tracking and JSON Schema validation.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from basilisk.payloads.effectiveness import (
    ProbeOutcome,
    record_outcome,
    record_batch,
    probe_effectiveness,
    model_effectiveness,
    category_leaderboard,
    stats_summary,
)


class TestEffectivenessTracker(unittest.TestCase):
    """Test the SQLite-backed probe effectiveness tracker."""

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(self._tmp.name)
        self._tmp.close()

    def tearDown(self):
        self.db_path.unlink(missing_ok=True)

    def _record_outcomes(self):
        """Seed the DB with test data."""
        outcomes = [
            ProbeOutcome("INJ-001", "Direct Override", "injection", "openai", "gpt-4o",
                         passed=False, compliance_score=0.8),
            ProbeOutcome("INJ-001", "Direct Override", "injection", "openai", "gpt-4o",
                         passed=False, compliance_score=0.7),
            ProbeOutcome("INJ-001", "Direct Override", "injection", "openai", "gpt-4o",
                         passed=True, compliance_score=0.1),
            ProbeOutcome("INJ-001", "Direct Override", "injection", "anthropic", "claude-3-opus",
                         passed=True, compliance_score=0.0),
            ProbeOutcome("INJ-001", "Direct Override", "injection", "anthropic", "claude-3-opus",
                         passed=True, compliance_score=0.0),
            ProbeOutcome("EXT-001", "System Prompt Leak", "extraction", "openai", "gpt-4o",
                         passed=True, compliance_score=0.0),
            ProbeOutcome("EXT-001", "System Prompt Leak", "extraction", "openai", "gpt-4o",
                         passed=False, compliance_score=0.9),
            ProbeOutcome("EXT-001", "System Prompt Leak", "extraction", "openai", "gpt-4o",
                         passed=True, compliance_score=0.1),
        ]
        record_batch(outcomes, db_path=self.db_path)

    def test_record_single_outcome(self):
        outcome = ProbeOutcome(
            "TEST-001", "Test Probe", "injection",
            "openai", "gpt-4o", passed=True,
        )
        record_outcome(outcome, db_path=self.db_path)
        summary = stats_summary(db_path=self.db_path)
        assert summary["total_records"] == 1
        assert summary["unique_probes"] == 1

    def test_record_batch(self):
        count = record_batch([
            ProbeOutcome("A-001", "A", "cat", "p", "m", passed=True),
            ProbeOutcome("A-002", "B", "cat", "p", "m", passed=False),
        ], db_path=self.db_path)
        assert count == 2
        summary = stats_summary(db_path=self.db_path)
        assert summary["total_records"] == 2

    def test_record_batch_empty(self):
        count = record_batch([], db_path=self.db_path)
        assert count == 0

    def test_probe_effectiveness(self):
        self._record_outcomes()
        stats = probe_effectiveness("INJ-001", db_path=self.db_path)

        assert stats["probe_id"] == "INJ-001"
        assert stats["total_runs"] == 5  # 3 openai + 2 anthropic

        # openai/gpt-4o: 2 bypasses out of 3
        gpt = stats["by_model"]["openai/gpt-4o"]
        assert gpt["runs"] == 3
        assert gpt["bypasses"] == 2
        assert gpt["bypass_rate"] > 0.6

        # anthropic/claude: 0 bypasses out of 2
        claude = stats["by_model"]["anthropic/claude-3-opus"]
        assert claude["runs"] == 2
        assert claude["bypasses"] == 0

    def test_model_effectiveness(self):
        self._record_outcomes()
        stats = model_effectiveness("openai", "gpt-4o", db_path=self.db_path)

        assert stats["provider"] == "openai"
        assert stats["model"] == "gpt-4o"
        assert stats["total_runs"] == 6  # 3 INJ + 3 EXT
        assert "injection" in stats["by_category"]
        assert "extraction" in stats["by_category"]

    def test_category_leaderboard(self):
        self._record_outcomes()
        board = category_leaderboard(db_path=self.db_path)

        assert isinstance(board, list)
        assert len(board) > 0
        # Sorted by bypass rate desc
        if len(board) >= 2:
            assert board[0]["bypass_rate"] >= board[-1]["bypass_rate"]

    def test_category_leaderboard_filtered(self):
        self._record_outcomes()
        board = category_leaderboard(category="injection", db_path=self.db_path)
        for entry in board:
            assert entry["category"] == "injection"

    def test_stats_summary(self):
        self._record_outcomes()
        summary = stats_summary(db_path=self.db_path)

        assert summary["total_records"] == 8
        assert summary["unique_probes"] == 2
        assert summary["unique_models"] == 2
        assert summary["unique_categories"] == 2
        assert 0.0 <= summary["overall_bypass_rate"] <= 1.0

    def test_empty_db_queries_dont_crash(self):
        stats = probe_effectiveness("NONEXISTENT", db_path=self.db_path)
        assert stats["total_runs"] == 0

        model = model_effectiveness("fake", "model", db_path=self.db_path)
        assert model["total_runs"] == 0

        board = category_leaderboard(db_path=self.db_path)
        assert board == []

        summary = stats_summary(db_path=self.db_path)
        assert summary["total_records"] == 0


class TestEvalSchema(unittest.TestCase):
    """Test that the JSON Schema is valid and covers the config format."""

    def test_schema_is_valid_json(self):
        schema_path = Path(__file__).parent.parent / "basilisk" / "eval" / "eval-schema.json"
        data = json.loads(schema_path.read_text("utf-8"))
        assert data["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert data["title"] == "Basilisk Eval Config"

    def test_schema_has_required_fields(self):
        schema_path = Path(__file__).parent.parent / "basilisk" / "eval" / "eval-schema.json"
        data = json.loads(schema_path.read_text("utf-8"))
        assert "target" in data["required"]
        assert "tests" in data["required"]

    def test_schema_assertion_types(self):
        schema_path = Path(__file__).parent.parent / "basilisk" / "eval" / "eval-schema.json"
        data = json.loads(schema_path.read_text("utf-8"))
        assertion_types = (
            data["properties"]["tests"]["items"]["properties"]
            ["assertions"]["items"]["properties"]["type"]["enum"]
        )
        expected = [
            "must_refuse", "must_not_refuse", "must_contain",
            "must_not_contain", "max_compliance", "max_tokens",
            "regex_match", "regex_no_match", "similarity", "llm_grade",
        ]
        assert assertion_types == expected

    def test_schema_provider_enum(self):
        schema_path = Path(__file__).parent.parent / "basilisk" / "eval" / "eval-schema.json"
        data = json.loads(schema_path.read_text("utf-8"))
        providers = data["properties"]["target"]["properties"]["provider"]["enum"]
        assert "openai" in providers
        assert "anthropic" in providers
        assert "groq" in providers

    def test_schema_timeout_constraints(self):
        schema_path = Path(__file__).parent.parent / "basilisk" / "eval" / "eval-schema.json"
        data = json.loads(schema_path.read_text("utf-8"))
        timeout = data["properties"]["defaults"]["properties"]["timeout"]
        assert timeout["minimum"] == 0.1
        assert timeout["maximum"] == 600
