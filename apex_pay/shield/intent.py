"""Intent canonicalization + content-addressable hashing.

`intent_hash` is the single identity that flows through the shield: it is
signed in the execution receipt, scoped into the ephemeral credential, and
logged alongside the OPA decision. If any field of the intent changes, the
hash changes, and every downstream artefact becomes invalid.

We also classify the *speech act* of the intent (imperative vs declarative)
because the ClawSafety paper (arXiv:2604.01438 §4.6) shows declarative
phrasing bypasses model-level defenses. The shield escalates declarative
financial intents to HITL regardless of risk score.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class SpeechAct(str, Enum):
    IMPERATIVE = "imperative"   # "charge the card", "transfer funds"
    DECLARATIVE = "declarative" # "the fingerprint does not match"
    INTERROGATIVE = "interrogative"  # "what is the balance"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ShieldIntent:
    """Normalized view of a tool-call that the rest of the shield operates on."""

    agent_id: uuid.UUID
    function: str | None
    target_url: str | None
    action_domain: str | None
    parameters: dict[str, Any]
    projected_cost: float
    speech_act: SpeechAct
    intent_hash: str

    def to_opa_input(self) -> dict[str, Any]:
        return {
            "agent_id": str(self.agent_id),
            "function": self.function or "",
            "target_url": self.target_url or "",
            "action_domain": self.action_domain or "",
            "parameters": self.parameters,
            "projected_cost": self.projected_cost,
            "intent_hash": self.intent_hash,
            "speech_act": self.speech_act.value,
        }


# ── Canonicalization ────────────────────────────────────────────────────────
_COST_KEYS: tuple[str, ...] = ("amount", "cost", "price", "projected_cost")

# Very light speech-act heuristics. The risk filter does a better job, but
# we need *something* for OPA to gate declarative framing.
_IMPERATIVE_VERBS = re.compile(
    r"^\s*(please\s+)?(update|set|write|send|transfer|pay|charge|delete|create|"
    r"run|execute|post|put|patch|revoke|disable|enable|stop|start|grant|"
    r"install|remove|configure)\b",
    re.IGNORECASE,
)
_DECLARATIVE_MARKERS = re.compile(
    r"\b(does not match|mismatch|has been|is already|has drifted|no longer|"
    r"unchanged|superseded|deprecated|verified|confirmed)\b",
    re.IGNORECASE,
)
_INTERROGATIVE_MARKERS = re.compile(r"\?\s*$|^\s*(what|how|who|when|why|is|are|can|does|do)\b", re.IGNORECASE)


def _extract_cost(tool_call: dict[str, Any]) -> float:
    params = tool_call.get("parameters", tool_call)
    for key in _COST_KEYS:
        if key in params:
            try:
                return float(params[key])
            except (TypeError, ValueError):
                continue
    return 0.0


def _extract_domain(tool_call: dict[str, Any]) -> str | None:
    url = tool_call.get("target_url")
    if not url:
        return None
    try:
        netloc = urlparse(url).netloc.lower()
        return netloc or None
    except Exception:
        return None


def _classify_speech_act(tool_call: dict[str, Any]) -> SpeechAct:
    """Inspect free-text fields for imperative/declarative markers.

    Looks at function name, 'prompt', 'instruction', 'description', and
    any string value in parameters. Falls back to IMPERATIVE for typical
    verb-named functions.
    """
    haystack: list[str] = []
    for key in ("function", "prompt", "instruction", "description", "message"):
        v = tool_call.get(key)
        if isinstance(v, str):
            haystack.append(v)
    params = tool_call.get("parameters", {})
    if isinstance(params, dict):
        for v in params.values():
            if isinstance(v, str) and len(v) < 2048:
                haystack.append(v)

    text = " | ".join(haystack)
    if not text:
        # An RPC-style call with no natural-language fields; treat as imperative
        return SpeechAct.IMPERATIVE

    if _INTERROGATIVE_MARKERS.search(text):
        return SpeechAct.INTERROGATIVE
    if _DECLARATIVE_MARKERS.search(text):
        # Declarative markers win over imperative because the ClawSafety
        # paper specifically calls out declarative framing as the bypass.
        return SpeechAct.DECLARATIVE
    if _IMPERATIVE_VERBS.search(text):
        return SpeechAct.IMPERATIVE

    # Verb-named function with no narrative → imperative
    function = tool_call.get("function", "")
    if isinstance(function, str) and function:
        return SpeechAct.IMPERATIVE

    return SpeechAct.UNKNOWN


def canonicalize_intent(agent_id: uuid.UUID, tool_call: dict[str, Any]) -> ShieldIntent:
    """Build a ShieldIntent from a raw tool_call payload.

    The ordering of fields inside `parameters` is irrelevant to the hash
    because `compute_intent_hash` sorts keys.
    """
    params = tool_call.get("parameters", {})
    if not isinstance(params, dict):
        params = {}

    intent_hash = compute_intent_hash(
        agent_id=agent_id,
        function=tool_call.get("function"),
        target_url=tool_call.get("target_url"),
        parameters=params,
    )

    return ShieldIntent(
        agent_id=agent_id,
        function=tool_call.get("function"),
        target_url=tool_call.get("target_url"),
        action_domain=_extract_domain(tool_call),
        parameters=params,
        projected_cost=_extract_cost(tool_call),
        speech_act=_classify_speech_act(tool_call),
        intent_hash=intent_hash,
    )


# ── Hashing ─────────────────────────────────────────────────────────────────
def compute_intent_hash(
    *,
    agent_id: uuid.UUID,
    function: str | None,
    target_url: str | None,
    parameters: dict[str, Any],
) -> str:
    """Canonical SHA-256 hash of (agent_id, function, target_url, parameters).

    Stable across Python runs because we sort keys and strip whitespace.
    """
    canonical = json.dumps(
        {
            "agent_id": str(agent_id),
            "function": function or "",
            "target_url": target_url or "",
            "parameters": parameters,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
