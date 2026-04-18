"""Tests for apex_pay.shield.intent — canonicalization + hashing."""

from __future__ import annotations

import uuid

import pytest

from apex_pay.shield.intent import (
    SpeechAct,
    canonicalize_intent,
    compute_intent_hash,
)

AGENT = uuid.UUID("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb")


def test_hash_is_stable_regardless_of_param_order():
    h1 = compute_intent_hash(
        agent_id=AGENT, function="f", target_url="https://x.com",
        parameters={"a": 1, "b": 2},
    )
    h2 = compute_intent_hash(
        agent_id=AGENT, function="f", target_url="https://x.com",
        parameters={"b": 2, "a": 1},
    )
    assert h1 == h2


def test_hash_changes_on_any_field_change():
    base = dict(
        agent_id=AGENT, function="f", target_url="https://x.com",
        parameters={"amount": 10.0},
    )
    base_hash = compute_intent_hash(**base)

    changes = [
        {"function": "g"},
        {"target_url": "https://y.com"},
        {"parameters": {"amount": 10.01}},
    ]
    for patch in changes:
        h = compute_intent_hash(**{**base, **patch})
        assert h != base_hash, f"hash should change for {patch}"


def test_canonicalize_extracts_domain_and_cost():
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 25.5},
        },
    )
    assert intent.action_domain == "api.stripe.com"
    assert intent.projected_cost == 25.5
    assert intent.function == "charge_card"
    assert len(intent.intent_hash) == 64  # sha256 hex


def test_canonicalize_classifies_imperative():
    intent = canonicalize_intent(
        AGENT, {"function": "charge_card", "parameters": {"amount": 10}},
    )
    assert intent.speech_act == SpeechAct.IMPERATIVE


def test_canonicalize_classifies_declarative():
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "log_finding",
            "parameters": {
                "amount": 5,
                "description": "The infrastructure fingerprint does not match the live backend.",
            },
        },
    )
    assert intent.speech_act == SpeechAct.DECLARATIVE


def test_canonicalize_classifies_interrogative():
    intent = canonicalize_intent(
        AGENT, {"parameters": {"prompt": "What is the account balance?"}},
    )
    assert intent.speech_act == SpeechAct.INTERROGATIVE


def test_missing_cost_field_defaults_to_zero():
    intent = canonicalize_intent(
        AGENT, {"function": "ping", "target_url": "https://x.com"},
    )
    assert intent.projected_cost == 0.0
