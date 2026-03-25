"""
Tests for Basilisk CLI commands.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from basilisk.cli.main import cli


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_version_command(self):
        result = self.runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "Version:" in result.output

    def test_help_command(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Basilisk" in result.output
        assert "scan" in result.output
        assert "recon" in result.output

    def test_scan_help(self):
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output
        assert "--provider" in result.output
        assert "--mode" in result.output
        assert "--execution-mode" in result.output

    def test_recon_help(self):
        result = self.runner.invoke(cli, ["recon", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output

    def test_replay_help(self):
        result = self.runner.invoke(cli, ["replay", "--help"])
        assert result.exit_code == 0

    def test_modules_command(self):
        result = self.runner.invoke(cli, ["modules"])
        # May fail if modules have import errors, but should not crash
        assert result.exit_code == 0

    def test_interactive_help(self):
        result = self.runner.invoke(cli, ["interactive", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output

    def test_sessions_help(self):
        result = self.runner.invoke(cli, ["sessions", "--help"])
        assert result.exit_code == 0

    def test_scan_requires_target(self):
        result = self.runner.invoke(cli, ["scan"])
        assert result.exit_code != 0
        assert "Missing" in result.output or "required" in result.output.lower()

    def test_recon_requires_target(self):
        result = self.runner.invoke(cli, ["recon"])
        assert result.exit_code != 0

    def test_scan_rejects_inline_api_key(self):
        result = self.runner.invoke(
            cli,
            ["scan", "-t", "https://example.test", "--api-key", "sk-inline-secret"],
        )
        assert result.exit_code != 0
        assert "no longer accepts inline secret values" in result.output

    def test_scan_rejects_inline_attacker_api_key(self):
        result = self.runner.invoke(
            cli,
            ["scan", "-t", "https://example.test", "--attacker-api-key", "sk-inline-secret"],
        )
        assert result.exit_code != 0
        assert "no longer accepts inline secret values" in result.output
