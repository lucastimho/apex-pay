"""Semantic risk filter.

Classifies an intent into labels and returns:
    * score    — scalar risk in [0, 1]
    * entropy  — normalised Shannon entropy of the label distribution,
                 in [0, 1]. Higher entropy = classifier was uncertain.
    * labels   — the labels that fired (for audit trail)

The shield's OPA policy uses `score >= risk_block` to hard-deny and
`entropy >= entropy_escalate` to route to HITL. Entropy is the key novel
gate: if the classifier is not confident, we do not execute, period.

Two implementations ship:

1. `HeuristicClassifier` — deterministic regex/keyword scoring, keyed to
   the three attack vectors measured in the ClawSafety paper (skill,
   email, web) plus explicit checks for declarative-framing bypasses.
   Runs offline, is the default for tests and for the "no GPU" case.

2. `LlamaGuardAdapter` — thin HTTP client for an external Llama-Guard
   or Phi-3 Safety endpoint. Wire a real inference server behind
   `LLAMA_GUARD_URL` in production; it is unused in tests.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

logger = logging.getLogger("apex_pay.shield.risk")


# ── Result type ─────────────────────────────────────────────────────────────
@dataclass
class RiskAssessment:
    score: float                          # overall risk in [0, 1]
    entropy: float                        # normalised Shannon entropy in [0, 1]
    labels: list[str] = field(default_factory=list)
    label_probs: dict[str, float] = field(default_factory=dict)
    classifier: str = "heuristic"

    def __post_init__(self) -> None:
        self.score = max(0.0, min(1.0, float(self.score)))
        self.entropy = max(0.0, min(1.0, float(self.entropy)))


class RiskClassifier(Protocol):
    async def classify(self, intent_text: str, context: dict[str, Any]) -> RiskAssessment: ...


# ── Heuristic classifier ────────────────────────────────────────────────────
@dataclass(frozen=True)
class _Rule:
    label: str
    pattern: re.Pattern[str]
    weight: float


class HeuristicClassifier:
    """Regex-and-keyword risk classifier.

    Category weights are tuned loosely against the ClawSafety trust gradient
    (skill > email > web). The weights are intentionally stable — these are
    policy knobs, not learned parameters — so reviewers can audit them.
    """

    # Higher weight = higher risk contribution if the rule fires.
    _RULES: tuple[_Rule, ...] = (
        # ── Credential forwarding (0% ASR hard block) ──────────────────────
        _Rule("credential_forwarding",
              re.compile(r"(?i)\b(api[_-]?key|secret|bearer\s+token|private\s+key|session\s+token)\b"),
              0.85),
        _Rule("credential_forwarding",
              re.compile(r"(?i)\b(exfiltrate|leak|forward|send).{0,40}(credentials?|tokens?|keys?)\b"),
              0.95),

        # ── Destination substitution ───────────────────────────────────────
        _Rule("destination_substitution",
              re.compile(r"(?i)\b(redirect|reroute|change|override)\b.{0,40}\b(wallet|account|recipient|destination)\b"),
              0.80),
        _Rule("destination_substitution",
              re.compile(r"(?i)\b(new|updated|verified)\s+wallet\s+address\b"),
              0.55),

        # ── Prompt-injection verbs (imperative framing) ────────────────────
        _Rule("prompt_injection_imperative",
              re.compile(r"(?i)\b(ignore|disregard|override|forget)\s+(all|the\s+)?(previous|prior|above)\b"),
              0.70),
        _Rule("prompt_injection_imperative",
              re.compile(r"(?i)\b(jailbreak|bypass|disable)\s+(safety|policy|guardrails?)\b"),
              0.85),

        # ── Declarative-framing bypasses (ClawSafety §4.6) ─────────────────
        _Rule("declarative_framing",
              re.compile(r"(?i)\b(does not match|mismatch|no longer valid|has drifted|superseded)\b"),
              0.45),
        _Rule("declarative_framing",
              re.compile(r"(?i)\b(verified|attested|reviewed)\b.{0,40}\b(finding|alert|advisory)\b"),
              0.35),

        # ── Destructive actions ────────────────────────────────────────────
        _Rule("destructive_action",
              re.compile(r"(?i)\b(delete|wipe|purge|drop|terminate|force[-_ ]delete)\b"),
              0.60),

        # ── Data exfiltration ──────────────────────────────────────────────
        _Rule("data_exfiltration",
              re.compile(r"(?i)\b(upload|post|send)\b.{0,40}\b(database|dump|backup|pii)\b"),
              0.75),

        # ── Benign / tool-use signals (lower risk) ─────────────────────────
        _Rule("benign_financial",
              re.compile(r"(?i)\b(charge|authorize|capture|refund|invoice)\b"),
              0.05),
    )

    # Vector labels from ClawSafety — context.channel indicates where the
    # intent came from. We bias the score accordingly.
    _CHANNEL_BIAS: dict[str, float] = {
        "skill": 0.15,   # skill-like channels carry highest trust → highest ASR
        "email": 0.10,
        "web":   0.05,
        "agent": 0.00,   # direct API call from registered agent
    }

    async def classify(self, intent_text: str, context: dict[str, Any]) -> RiskAssessment:
        text = intent_text or ""

        label_scores: dict[str, float] = {}
        for rule in self._RULES:
            if rule.pattern.search(text):
                # Keep the worst-case per label (so redundant matches don't
                # compound arbitrarily).
                existing = label_scores.get(rule.label, 0.0)
                label_scores[rule.label] = max(existing, rule.weight)

        # No signal at all → flat "benign" label
        if not label_scores:
            label_scores["benign"] = 0.05

        # Channel bias: skill > email > web (ClawSafety trust gradient).
        channel = (context.get("channel") or "agent").lower()
        bias = self._CHANNEL_BIAS.get(channel, 0.0)

        # Aggregate score = max rule weight + channel bias, clipped
        raw = max(label_scores.values()) + bias
        score = max(0.0, min(1.0, raw))

        # Label distribution for entropy: softmax over rule weights so that
        # several near-equal rules produce high entropy and one dominant
        # rule produces low entropy. "benign" has a floor contribution so
        # a totally unseen pattern isn't 0-entropy.
        probs = self._softmax(label_scores, temperature=0.25)
        entropy = self._normalised_entropy(list(probs.values()))

        labels = sorted(label_scores, key=lambda k: -label_scores[k])

        return RiskAssessment(
            score=score,
            entropy=entropy,
            labels=labels,
            label_probs=probs,
            classifier="heuristic",
        )

    # ── Math helpers ────────────────────────────────────────────────────
    @staticmethod
    def _softmax(scores: dict[str, float], temperature: float = 1.0) -> dict[str, float]:
        if not scores:
            return {}
        t = max(temperature, 1e-6)
        exps = {k: math.exp(v / t) for k, v in scores.items()}
        total = sum(exps.values())
        if total == 0:
            n = len(exps)
            return {k: 1.0 / n for k in exps}
        return {k: v / total for k, v in exps.items()}

    @staticmethod
    def _normalised_entropy(probs: list[float]) -> float:
        probs = [p for p in probs if p > 0]
        if len(probs) <= 1:
            return 0.0
        h = -sum(p * math.log2(p) for p in probs)
        h_max = math.log2(len(probs))
        return h / h_max if h_max > 0 else 0.0


# ── External-model adapter (Llama-Guard / Phi-3) ────────────────────────────
class LlamaGuardAdapter:
    """Thin HTTP client for an external safety classifier.

    Expected response shape (configurable via `response_key`):
        {"labels": [{"name": str, "probability": float}], "flagged": bool}

    We compute `score = max(probability for unsafe labels)` and `entropy`
    over the full returned distribution. If the endpoint is unreachable or
    returns a malformed body, we fall back to `HeuristicClassifier`.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 2.0,
        unsafe_prefixes: tuple[str, ...] = ("S",),
        fallback: RiskClassifier | None = None,
    ):
        self._url = url
        self._timeout = timeout
        self._unsafe_prefixes = unsafe_prefixes
        self._fallback: RiskClassifier = fallback or HeuristicClassifier()

    async def classify(self, intent_text: str, context: dict[str, Any]) -> RiskAssessment:
        payload = {"input": intent_text, "context": context}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._url, json=payload)
                resp.raise_for_status()
                body = resp.json()
        except Exception as exc:
            logger.warning("Llama-Guard endpoint unavailable (%s); using fallback.", exc)
            return await self._fallback.classify(intent_text, context)

        labels = body.get("labels") or []
        if not isinstance(labels, list):
            logger.warning("Llama-Guard returned malformed body; using fallback.")
            return await self._fallback.classify(intent_text, context)

        label_probs: dict[str, float] = {}
        for item in labels:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            prob = float(item.get("probability") or 0.0)
            if name:
                label_probs[name] = prob

        if not label_probs:
            return await self._fallback.classify(intent_text, context)

        unsafe_scores = [
            p for name, p in label_probs.items()
            if any(name.startswith(px) for px in self._unsafe_prefixes)
        ]
        score = max(unsafe_scores) if unsafe_scores else 0.0
        entropy = HeuristicClassifier._normalised_entropy(list(label_probs.values()))

        return RiskAssessment(
            score=score,
            entropy=entropy,
            labels=sorted(label_probs, key=lambda k: -label_probs[k]),
            label_probs=label_probs,
            classifier="llama-guard",
        )


# ── Text extraction helper ──────────────────────────────────────────────────
def intent_to_text(tool_call: dict[str, Any]) -> str:
    """Concatenate the free-text fields of a tool_call for classification."""
    parts: list[str] = []
    for key in ("function", "target_url", "prompt", "instruction", "description", "message"):
        v = tool_call.get(key)
        if isinstance(v, str):
            parts.append(v)
    params = tool_call.get("parameters", {})
    if isinstance(params, dict):
        for k, v in params.items():
            parts.append(str(k))
            if isinstance(v, (str, int, float, bool)):
                parts.append(str(v))
    return " ".join(parts)
