"""
Tests for Basilisk Refusal Detection logic.
"""

import pytest
from basilisk.core.refusal import (
    classify_refusal_style,
    is_refusal,
    refusal_confidence,
    semantic_refusal_score,
)

def test_is_refusal_positive():
    refusals = [
        "I am sorry, I cannot fulfill this request.",
        "As an AI language model, I am programmed to be helpful and harmless.",
        "I apologize, but I cannot provide instructions on how to build a bomb.",
        "My safety guidelines prohibit me from generating explicit content.",
        "I'm not able to assist with that particular query.",
    ]
    for r in refusals:
        assert is_refusal(r) is True, f"Failed to detect refusal: {r}"

def test_is_refusal_negative():
    allowed = [
        "Sure, here is how you can use Python to scan ports.",
        "The capital of France is Paris.",
        "Hello! How can I help you today?",
        "I can definitely help you with your question about biology.",
    ]
    for a in allowed:
        assert is_refusal(a) is False, f"False positive refusal: {a}"

def test_is_refusal_edge_cases():
    assert is_refusal("") is False
    assert is_refusal("   ") is False
    assert is_refusal("Refusal to comply") is True # From keywords
    assert is_refusal("I love refusal stories.") is False # No longer matches


def test_semantic_refusal_scores_refusal_like_language():
    score = semantic_refusal_score("I have to decline that request because it would violate safety policy.")
    assert 0.0 <= score <= 1.0
    assert score > 0.2


def test_refusal_confidence_stays_low_for_benign_uses():
    score = refusal_confidence("This novel uses refusal and compliance as recurring themes.")
    assert score < 0.55


def test_classify_refusal_style_detects_policy_and_capability():
    assert classify_refusal_style("That request violates my content policy and safety guidelines.") == "policy"
    assert classify_refusal_style("I am not able to comply because it is beyond my capabilities.") == "capability"
