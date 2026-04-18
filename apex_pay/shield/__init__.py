"""APEX-Shield — Zero-Trust security layer on top of APEX-Pay.

The shield sits between the Pydantic-validated tool-call and the policy
decision. It adds, in order:

    1. Intent canonicalization + SHA-256 hash     (proof-of-intent identity)
    2. Semantic risk filter (SLM / heuristic)     (score + entropy)
    3. OPA policy evaluation                      (Rego: deny / escalate)
    4. Ephemeral credential issuance              (single-transaction scope)
    5. Ed25519 signed execution receipt           (non-repudiation)

Each piece is wired in apex_pay.routers.gateway via `ShieldPipeline.evaluate`.
The legacy PolicyEngine still runs for backwards compatibility — the shield
augments it rather than replacing it.
"""

from apex_pay.shield.intent import (
    SpeechAct,
    ShieldIntent,
    canonicalize_intent,
    compute_intent_hash,
)
from apex_pay.shield.receipt_service import ReceiptService, SignedReceipt
from apex_pay.shield.risk_filter import (
    HeuristicClassifier,
    LlamaGuardAdapter,
    RiskAssessment,
    RiskClassifier,
)
from apex_pay.shield.credential_manager import (
    CredentialManager,
    DevCredentialBackend,
    EphemeralCredential,
    VaultCredentialBackend,
)
from apex_pay.shield.opa_client import OPADecision, OPAClient, EmbeddedOPAEvaluator
from apex_pay.shield.pipeline import ShieldDecision, ShieldPipeline

__all__ = [
    "SpeechAct",
    "ShieldIntent",
    "canonicalize_intent",
    "compute_intent_hash",
    "ReceiptService",
    "SignedReceipt",
    "HeuristicClassifier",
    "LlamaGuardAdapter",
    "RiskAssessment",
    "RiskClassifier",
    "CredentialManager",
    "DevCredentialBackend",
    "EphemeralCredential",
    "VaultCredentialBackend",
    "OPADecision",
    "OPAClient",
    "EmbeddedOPAEvaluator",
    "ShieldDecision",
    "ShieldPipeline",
]
