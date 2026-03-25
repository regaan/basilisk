"""
Basilisk Eval — assertion-based security evaluation pipeline.

Run deterministic test suites against LLM targets to verify
guardrail effectiveness. Supports CI/CD integration with
JUnit XML output and regression diffing.
"""

from basilisk.eval.config import EvalConfig, EvalTest, Assertion
from basilisk.eval.runner import EvalRunner, EvalResult, EvalTestResult, save_result, load_result
from basilisk.eval.assertions import evaluate_assertion

__all__ = [
    "EvalConfig",
    "EvalTest",
    "Assertion",
    "EvalRunner",
    "EvalResult",
    "EvalTestResult",
    "evaluate_assertion",
    "save_result",
    "load_result",
]
