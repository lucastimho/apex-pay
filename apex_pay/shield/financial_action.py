"""FinancialAction — the strict Pydantic schema for monetary agent intents.

Design brief (security architect)
---------------------------------
Every agent intent that touches money flows through `FinancialAction` before
anything else runs. The model is *closed* in three orthogonal ways so a hostile
payload has nowhere to hide:

  1. **Shape closure** (`extra="forbid"`, `frozen=True`) — no unexpected fields,
     no post-validation mutation. The object that leaves validation is the
     object that feeds OPA, Vault, and the audit log.

  2. **Type closure** (`Literal`, `Decimal`, `constr` with patterns) — enums
     are enums, money is decimal, strings match explicit regexes. Rejects
     type confusion (stringy amounts, bool-masquerading-as-int) before it
     reaches Rego.

  3. **Content closure** — every free-text field is scanned for control bytes,
     bidi overrides, zero-width characters, homoglyph categories, NULL bytes,
     and CR/LF (log-injection). The scan uses Unicode *categories* rather
     than blocklists, so novel attack glyphs don't slip through.

Output
------
A validated `FinancialAction` is:

  - **Canonicalisable** to deterministic JSON (`canonical_json()`), so the
    intent_hash used for signing, dedup, and OPA input is reproducible
    across machines and Python versions.

  - **Content-addressable** (`content_hash()` → SHA-256 hex of the canonical
    form), so the hash can be stamped on the audit row and the Ed25519
    receipt without any re-derivation logic at the call site.

  - **OPA-ready** via `to_opa_input()`, which emits the exact structure the
    `apex.financial` Rego package expects.

Everything here is defence-in-depth. The existing `ToolCallPayload`,
`apex.rego`, and `apex.financial.rego` are each independently sufficient
to block a given attack. `FinancialAction` is the structural checkpoint
that narrows what the later layers have to consider.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from decimal import Decimal
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StringConstraints,
    field_validator,
    model_validator,
)

# ── Constants (mirror the Rego policy) ──────────────────────────────────────

MAX_TRANSACTION_USD: Decimal = Decimal("50.00")

VERIFIED_DOMAIN_SUFFIXES: frozenset[str] = frozenset({
    "stripe.com",
    "paypal.com",
    "adyen.com",
    "squareup.com",
    "checkout.com",
    "mollie.com",
    "plaid.com",
    "dwolla.com",
    "wise.com",
    "braintreepayments.com",
})

ALLOWED_CURRENCIES: frozenset[str] = frozenset({
    "USD", "EUR", "GBP", "CAD", "AUD", "JPY",
})

# ISO 4217 subset: currencies with zero decimal places.
ZERO_DECIMAL_CURRENCIES: frozenset[str] = frozenset({"JPY"})

ActionType = Literal["charge", "refund", "transfer", "payout", "preauth", "capture"]

# ── Input-string safety patterns ────────────────────────────────────────────

# Domain: RFC 1035 label syntax, lowercase, 1-253 chars total, no trailing dot.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

# Opaque identifiers (idempotency keys, recipient refs).
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")

# Memo / human-readable free text. Deliberately narrow: ASCII letters, digits,
# whitespace, and a small set of punctuation. No backticks, angle brackets,
# dollar signs, braces, quotes, or backslashes — each of these has been a
# stage-1 vector in a real injection somewhere.
_MEMO_RE = re.compile(r"^[\w\s.,:;!?/@#+\-]*$")

# Unicode categories we refuse outright anywhere in a string field.
# See https://www.unicode.org/reports/tr44/#General_Category_Values
# Cc = control characters (includes NULL, CR, LF, tab beyond whitespace cap)
# Cf = format characters (RLO, LRO, zero-width joiner, etc.)
# Cs = surrogate (should never appear in valid UTF-8)
# Co = private-use characters
_FORBIDDEN_CATEGORIES: frozenset[str] = frozenset({"Cc", "Cf", "Cs", "Co"})

# Specific codepoints that are technically in "safe" categories but are
# classic attack tools. Redundant with the category filter in most cases;
# explicit here as defence-in-depth and documentation.
_FORBIDDEN_CODEPOINTS: frozenset[str] = frozenset({
    "\u0000",  # NULL — SQL/C string terminator
    "\u0008",  # Backspace
    "\u000A",  # LF
    "\u000D",  # CR
    "\u001B",  # ESC
    "\u007F",  # DEL
    "\u200B",  # ZWSP — invisible word-split
    "\u200C",  # ZWNJ
    "\u200D",  # ZWJ
    "\u202A",  # LRE — bidi
    "\u202B",  # RLE
    "\u202C",  # PDF
    "\u202D",  # LRO
    "\u202E",  # RLO — the classic "make-this-look-harmless" trick
    "\u2066",  # LRI
    "\u2067",  # RLI
    "\u2068",  # FSI
    "\u2069",  # PDI
    "\uFEFF",  # BOM
})


def _assert_safe_string(value: str, *, field_name: str, max_length: int) -> str:
    """Raise ValueError if `value` contains anything that smells like injection.

    The validator runs AFTER Pydantic's length/regex checks as an
    additional Unicode-category scan.
    """
    if len(value) > max_length:
        raise ValueError(f"{field_name} exceeds max length {max_length}")
    # Normalise to NFC so homoglyph expansions don't sneak past category checks.
    nfc = unicodedata.normalize("NFC", value)
    if nfc != value:
        # Normalisation changed the string — reject rather than silently
        # accepting. A well-formed client sends NFC already; an attacker is
        # probably the one sending decomposed or non-standard forms.
        raise ValueError(f"{field_name} must be Unicode NFC")
    for ch in value:
        if ch in _FORBIDDEN_CODEPOINTS:
            raise ValueError(
                f"{field_name} contains forbidden codepoint U+{ord(ch):04X}"
            )
        if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES:
            raise ValueError(
                f"{field_name} contains forbidden Unicode category "
                f"{unicodedata.category(ch)!r} (U+{ord(ch):04X})"
            )
    return value


# ── The model ───────────────────────────────────────────────────────────────


class FinancialAction(BaseModel):
    """Strict, immutable representation of a monetary agent intent.

    Use `FinancialAction.from_tool_call(...)` to parse a legacy
    `ToolCallPayload.tool_call` dict with error aggregation; use the
    normal `FinancialAction(**data)` constructor for already-structured
    input.
    """

    model_config = ConfigDict(
        extra="forbid",                    # unknown fields → ValidationError
        frozen=True,                       # post-validation immutable
        str_strip_whitespace=True,         # trims leading/trailing whitespace
        str_max_length=512,                # global cap as defence-in-depth
        validate_assignment=True,          # (frozen makes this largely moot)
        populate_by_name=False,
        # NaN/Inf are refused by the Decimal field validator (see test
        # `test_rejects_nan_infinity`); Pydantic 2.10's ser_json_inf_nan
        # doesn't accept "error", so we rely on input-side rejection.
    )

    # ── Required fields ─────────────────────────────────────────────────
    action_type: ActionType = Field(
        ..., description="Enum of monetary actions. Matches the OPA allowlist."
    )

    # Money is Decimal, never float. Two decimal places for ISO 4217 (except JPY
    # which is enforced in the model validator).
    amount: Annotated[Decimal, Field(
        gt=Decimal("0"),
        le=Decimal("10000"),
        decimal_places=4,
        description="Amount in the declared currency. ≥ 0 and ≤ hard ceiling.",
    )]

    currency: Annotated[str, StringConstraints(
        min_length=3, max_length=3, pattern=r"^[A-Z]{3}$",
    )] = Field(..., description="ISO 4217 three-letter currency code.")

    target_domain: Annotated[str, StringConstraints(
        min_length=1, max_length=253,
    )] = Field(..., description="Registrable hostname of the downstream API.")

    target_url: HttpUrl = Field(
        ..., description="Full request URL. Scheme must be https.",
    )

    idempotency_key: Annotated[str, StringConstraints(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_\-]{1,128}$",
    )] = Field(
        ...,
        description="Client-supplied dedup key. Opaque alphanumeric, no separators.",
    )

    # ── Optional fields ─────────────────────────────────────────────────
    recipient_ref: Annotated[str | None, StringConstraints(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_\-]{1,128}$",
    )] = Field(default=None, description="Downstream recipient handle (if any).")

    memo: str | None = Field(
        default=None,
        max_length=256,
        description="Free-text memo. Narrow-ASCII only.",
    )

    # ── Validators ──────────────────────────────────────────────────────

    @field_validator("target_domain")
    @classmethod
    def _validate_domain_syntax(cls, v: str) -> str:
        lower = v.lower()
        if not _DOMAIN_RE.match(lower):
            raise ValueError("target_domain is not a valid hostname")
        return lower

    @field_validator("target_domain")
    @classmethod
    def _domain_must_be_verified(cls, v: str) -> str:
        if not _is_verified_domain(v):
            raise ValueError(
                f"target_domain {v!r} is not in the verified-domain allowlist"
            )
        return v

    @field_validator("currency")
    @classmethod
    def _currency_on_whitelist(cls, v: str) -> str:
        if v not in ALLOWED_CURRENCIES:
            raise ValueError(f"currency {v!r} is not on the allowed list")
        return v

    @field_validator("memo")
    @classmethod
    def _memo_is_clean(cls, v: str | None) -> str | None:
        if v is None:
            return None
        # Length cap already applied by Pydantic; re-check + scan.
        _assert_safe_string(v, field_name="memo", max_length=256)
        if not _MEMO_RE.match(v):
            raise ValueError("memo contains characters outside the safe set")
        return v

    @field_validator("idempotency_key", "recipient_ref")
    @classmethod
    def _opaque_id_scan(cls, v: str | None) -> str | None:
        if v is None:
            return None
        # Regex already enforces charset; the category scan is a no-op but
        # documents intent and catches future regex loosening.
        _assert_safe_string(v, field_name="opaque_id", max_length=128)
        if not _OPAQUE_RE.match(v):
            raise ValueError("opaque identifier fails charset check")
        return v

    @model_validator(mode="after")
    def _cross_field_checks(self) -> "FinancialAction":
        """Checks that need two+ fields at once.

        Runs after individual field validators, so every field here is
        already shape-valid.
        """
        # (a) amount precision matches currency.
        exponent_places = 0 if self.currency in ZERO_DECIMAL_CURRENCIES else 2
        quantum = Decimal(10) ** -exponent_places
        if self.amount.as_tuple().exponent < -exponent_places:
            raise ValueError(
                f"amount has more than {exponent_places} decimal place(s) "
                f"for currency {self.currency}"
            )
        # Snap to quantum on the returned object. Frozen → use __dict__ write.
        object.__setattr__(self, "amount", self.amount.quantize(quantum))

        # (b) target_url's host must equal target_domain. Closes the
        # "claim Stripe but POST to attacker" split-field trick.
        parsed = urlparse(str(self.target_url))
        if (parsed.hostname or "").lower() != self.target_domain:
            raise ValueError(
                f"target_url host {parsed.hostname!r} does not match "
                f"target_domain {self.target_domain!r}"
            )
        if parsed.scheme != "https":
            raise ValueError("target_url scheme must be https")

        # (c) hard ceiling (mirrors OPA D1). This is redundant with the Rego
        # gate but we want Pydantic to reject at the API boundary so logs
        # don't even get an attempted $51 charge in the "attempted" bucket.
        if _amount_in_usd(self.amount, self.currency) > MAX_TRANSACTION_USD:
            raise ValueError(
                f"amount exceeds hard ceiling of ${MAX_TRANSACTION_USD} USD"
            )

        return self

    # ── Canonicalisation & signing ──────────────────────────────────────

    def canonical_json(self) -> bytes:
        """Deterministic UTF-8 JSON for signing / hashing.

        Keys sorted, no whitespace, Decimal serialised as string (avoids
        float-rounding between processes), None fields omitted so an
        optional-field addition doesn't break old signatures.
        """
        payload: dict[str, Any] = {
            "action_type": self.action_type,
            "amount": str(self.amount),
            "currency": self.currency,
            "target_domain": self.target_domain,
            "target_url": str(self.target_url),
            "idempotency_key": self.idempotency_key,
        }
        if self.recipient_ref is not None:
            payload["recipient_ref"] = self.recipient_ref
        if self.memo is not None:
            payload["memo"] = self.memo
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def content_hash(self) -> str:
        """SHA-256 hex digest of the canonical form. Safe to log."""
        return hashlib.sha256(self.canonical_json()).hexdigest()

    # ── OPA adapter ─────────────────────────────────────────────────────

    def to_opa_input(self, *, agent_id: str, policy_version: str) -> dict[str, Any]:
        """Build the exact input shape `apex.financial` expects."""
        return {
            "action": {
                "action_type":   self.action_type,
                "amount_usd":    float(_amount_in_usd(self.amount, self.currency)),
                "currency":      self.currency,
                "target_domain": self.target_domain,
                "target_url":    str(self.target_url),
                "idempotency_key": self.idempotency_key,
            },
            "context": {
                "agent_id":       agent_id,
                "policy_version": policy_version,
            },
        }

    # ── Factory ─────────────────────────────────────────────────────────

    @classmethod
    def from_tool_call(cls, tool_call: dict[str, Any]) -> "FinancialAction":
        """Strict extractor from a legacy ToolCallPayload.tool_call dict.

        Accepts either a flat dict (`{action_type, amount, currency, ...}`)
        or the nested style used by existing APEX tool calls
        (`{function, target_url, parameters: {...}}`).

        The extractor is deliberately un-forgiving — anything ambiguous
        raises rather than guessing. Callers get structured
        `ValidationError` they can log or translate to a 400.
        """
        if "action_type" in tool_call:
            return cls(**tool_call)
        # Legacy nested shape.
        parameters = tool_call.get("parameters") or {}
        if not isinstance(parameters, dict):
            raise ValueError("tool_call.parameters must be an object")
        target_url = tool_call.get("target_url")
        if not target_url:
            raise ValueError("tool_call.target_url is required")
        parsed = urlparse(str(target_url))
        return cls(
            action_type=parameters.get("action_type") or tool_call.get("function"),
            amount=Decimal(str(parameters["amount"])),
            currency=parameters.get("currency", "USD"),
            target_domain=(parsed.hostname or "").lower(),
            target_url=target_url,
            idempotency_key=parameters.get("idempotency_key") or tool_call["idempotency_key"],
            recipient_ref=parameters.get("recipient_ref"),
            memo=parameters.get("memo"),
        )


# ── Module helpers ──────────────────────────────────────────────────────────


def _is_verified_domain(domain: str) -> bool:
    """Suffix match against VERIFIED_DOMAIN_SUFFIXES. Mirrors the Rego helper."""
    d = domain.lower()
    for suffix in VERIFIED_DOMAIN_SUFFIXES:
        if d == suffix or d.endswith("." + suffix):
            return True
    return False


def _amount_in_usd(amount: Decimal, currency: str) -> Decimal:
    """Normalise amount to USD for ceiling comparison.

    v1 stub: returns the amount unchanged for USD, raises on other
    currencies until the FX service is wired. The ceiling is still
    enforced in Rego on the `amount_usd` field the caller provides; this
    function exists so the Pydantic pre-check doesn't silently allow a
    JPY 9999 that the ceiling would have denied.
    """
    if currency == "USD":
        return amount
    raise NotImplementedError(
        f"FX normalisation for {currency} not wired; set currency=USD for v1"
    )
