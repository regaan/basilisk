"""
Basilisk Eval Report — output formatters for eval results.

Supports console (rich), JSON, JUnit XML, and Markdown output.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from basilisk.eval.runner import EvalResult


def format_console(result: EvalResult) -> str:
    """Format eval results for terminal display using rich markup."""
    lines: list[str] = []
    lines.append("")
    lines.append(f"  Target: {result.target_provider}/{result.target_model}")
    lines.append(f"  Tests:  {result.total_tests}")
    lines.append(f"  Passed: {result.passed_tests}")
    lines.append(f"  Failed: {result.failed_tests}")
    lines.append(f"  Rate:   {result.pass_rate:.0%}")
    lines.append(f"  Time:   {result.total_duration_ms:.0f}ms")
    lines.append("")

    for t in result.tests:
        icon = "✓" if t.passed else "✗"
        status = "PASS" if t.passed else "FAIL"
        lines.append(f"  {icon} [{status}] {t.test_id}: {t.test_name} ({t.duration_ms:.0f}ms)")

        if not t.passed:
            for a in t.failed_assertions:
                lines.append(f"      └─ {a.assertion_type}: {a.reason}")
            if t.error:
                lines.append(f"      └─ ERROR: {t.error}")

    lines.append("")
    verdict = "ALL TESTS PASSED" if result.failed_tests == 0 else f"{result.failed_tests} TEST(S) FAILED"
    lines.append(f"  {verdict}")
    lines.append("")
    return "\n".join(lines)


def format_json(result: EvalResult, pretty: bool = True) -> str:
    """Format eval results as JSON."""
    return json.dumps(result.to_dict(), indent=2 if pretty else None)


def format_junit_xml(result: EvalResult) -> str:
    """Format eval results as JUnit XML for CI/CD integration.

    Compatible with: GitHub Actions, GitLab CI, Jenkins, CircleCI.
    """
    testsuite = ET.Element("testsuite", {
        "name": f"basilisk-eval-{result.target_provider}",
        "tests": str(result.total_tests),
        "failures": str(result.failed_tests),
        "errors": str(sum(1 for t in result.tests if t.error)),
        "time": f"{result.total_duration_ms / 1000:.3f}",
        "timestamp": result.started_at or datetime.now(timezone.utc).isoformat(),
    })

    for t in result.tests:
        testcase = ET.SubElement(testsuite, "testcase", {
            "classname": f"basilisk.eval.{result.target_provider}",
            "name": f"{t.test_id}: {t.test_name}",
            "time": f"{t.duration_ms / 1000:.3f}",
        })

        if t.error:
            error = ET.SubElement(testcase, "error", {
                "message": t.error,
                "type": "RuntimeError",
            })
            error.text = t.error

        elif not t.passed:
            failed = t.failed_assertions
            message = "; ".join(f"{a.assertion_type}: {a.reason}" for a in failed)
            failure = ET.SubElement(testcase, "failure", {
                "message": message[:500],
                "type": "AssertionFailure",
            })
            detail_lines = [
                f"Prompt: {t.prompt[:200]}",
                f"Response: {t.response[:300]}",
                "",
                "Failed assertions:",
            ]
            for a in failed:
                detail_lines.append(f"  - {a.assertion_type}: {a.reason}")
            failure.text = "\n".join(detail_lines)

    tree = ET.ElementTree(testsuite)
    ET.indent(tree, space="  ")

    import io
    buf = io.StringIO()
    tree.write(buf, encoding="unicode", xml_declaration=True)
    return buf.getvalue()


def format_markdown(result: EvalResult) -> str:
    """Format eval results as Markdown (for PR comments)."""
    lines: list[str] = []

    # Header
    icon = "✅" if result.failed_tests == 0 else "❌"
    lines.append(f"## {icon} Basilisk Eval Results\n")
    lines.append(f"**Target**: `{result.target_provider}/{result.target_model}`  ")
    lines.append(f"**Pass Rate**: {result.pass_rate:.0%} ({result.passed_tests}/{result.total_tests})  ")
    lines.append(f"**Duration**: {result.total_duration_ms:.0f}ms\n")

    # Results table
    lines.append("| Status | Test ID | Name | Score | Time |")
    lines.append("|--------|---------|------|-------|------|")

    for t in result.tests:
        icon = "✅" if t.passed else "❌"
        lines.append(
            f"| {icon} | `{t.test_id}` | {t.test_name} | "
            f"{t.score:.2f} | {t.duration_ms:.0f}ms |"
        )

    # Failed details
    failed_tests = [t for t in result.tests if not t.passed]
    if failed_tests:
        lines.append("\n### Failed Tests\n")
        for t in failed_tests:
            lines.append(f"#### `{t.test_id}`: {t.test_name}\n")
            lines.append(f"**Prompt**: `{t.prompt[:100]}`\n")
            if t.error:
                lines.append(f"**Error**: {t.error}\n")
            for a in t.failed_assertions:
                lines.append(f"- **{a.assertion_type}**: {a.reason}")
            lines.append("")

    return "\n".join(lines)


def save_eval_report(
    result: EvalResult,
    format: str = "json",
    output_path: str = "",
) -> str:
    """Save eval report to file and return the path."""
    formatters = {
        "json": format_json,
        "junit": format_junit_xml,
        "markdown": format_markdown,
        "console": format_console,
    }

    formatter = formatters.get(format, format_json)
    content = formatter(result)

    if not output_path:
        ext_map = {"json": ".json", "junit": ".xml", "markdown": ".md", "console": ".txt"}
        ext = ext_map.get(format, ".json")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("./basilisk-reports")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(output_dir / f"eval_{timestamp}{ext}")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(content, encoding="utf-8")

    return output_path
