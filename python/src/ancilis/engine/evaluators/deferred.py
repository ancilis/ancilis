"""Deferred AKSI evaluators for controls blocked on future architecture."""

from __future__ import annotations

from dataclasses import dataclass
import time

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


@dataclass(frozen=True)
class DeferredSpec:
    control_id: str
    control_name: str
    reason: str
    todo_block: str


LEGACY_DEFERRED_CONTROL_SPECS: dict[str, DeferredSpec] = {
    "DE-05": DeferredSpec(
        control_id="DE-05",
        control_name="AI Outcome Evaluation and Harm Monitoring",
        reason="new_data",
        todo_block=(
            "Gap class: `new_data`. This control requires evaluation of agent outputs "
            "and tool outcomes for reliability, hallucination, harmful output, bias, "
            "safety drift, and out-of-scope behavior. The current Action shape does "
            "not consistently capture final model output, evaluator scores, "
            "ground-truth labels, safety-review outcomes, or task success metrics. "
            "A producer or external evaluation integration would need to provide "
            "output telemetry and assessment records before a runtime evaluator can "
            "compute coverage. Complexity: substantial."
        ),
    ),
    "DE-06": DeferredSpec(
        control_id="DE-06",
        control_name="Assurance Testing and Vulnerability Evidence Ingestion",
        reason="new_data",
        todo_block=(
            "Gap class: `new_data`. This control requires vulnerability scans, "
            "adversarial tests, red-team exercises, resilience tests, safety "
            "validations, and third-party evaluations to be ingested as control "
            "evidence with remediation state. The SDK has SARIF/CycloneDX-style "
            "import surfaces elsewhere, but Engine.evaluate(Action) does not receive "
            "scan artifacts or remediation lifecycle state. A producer/importer "
            "should supply normalized assurance findings and remediation status; "
            "the evaluator would validate freshness, severity threshold, and closure "
            "state. Complexity: substantial."
        ),
    ),
    "ID-03": DeferredSpec(
        control_id="ID-03",
        control_name="Data Flow Mapping and Classification",
        reason="cross_action",
        todo_block=(
            "Gap class: `cross_action`. This control requires mapping inputs, context "
            "stores, outputs, destinations, and observed data classes for every "
            "governed system. A single Action can expose parameters and destination, "
            "but complete flow mapping needs aggregation across sessions and "
            "producers plus classification history. State should live in the "
            "evidence store or a dedicated data-flow graph keyed by agent, data "
            "class, source, destination, and processing purpose. Complexity: "
            "substantial."
        ),
    ),
    "ID-04": DeferredSpec(
        control_id="ID-04",
        control_name="Supply Chain and Dependency Risk",
        reason="new_data",
        todo_block=(
            "Gap class: `new_data`. This control requires supply-chain risk "
            "assessment for models, tools, dependencies, prompts, and orchestration "
            "components. Action metadata does not include dependency SBOMs, "
            "vulnerability scan results, model provenance attestations, or prompt "
            "package integrity records. Producers/importers should provide SBOM, "
            "SARIF/CycloneDX findings, model card/provenance metadata, prompt "
            "package hashes, and approval state. Complexity: substantial."
        ),
    ),
    "PAY-01": DeferredSpec(
        control_id="PAY-01",
        control_name="Agent Payment Authorization and Sanctions Screening",
        reason="new_data",
        todo_block=(
            "Gap class: `new_data`. This control applies when DC-PAY or payment "
            "targets activate, and it requires agent-initiated payments to be "
            "authorized against spend policy, recipient trust, sanctions screening, "
            "and approval requirements. Current generic Actions do not guarantee "
            "payment intent, recipient, amount/currency, approval ID, sanctions "
            "result, wallet policy, or payment token metadata. A payment "
            "producer/integration should provide those fields; the evaluator would "
            "check thresholds, required approval, recipient allowlist/trust, "
            "sanctions result, and policy ID membership. Complexity: substantial."
        ),
    ),
    "PAY-02": DeferredSpec(
        control_id="PAY-02",
        control_name="Payment Settlement Reconciliation and Irreversibility Control",
        reason="new_data",
        todo_block=(
            "Gap class: `new_data`. This control requires payment settlement to be "
            "reconciled against receipts, ledger state, irreversibility risk, and "
            "reversal/escalation policy. That cannot be computed from a single "
            "pre-payment Action without external settlement and ledger records. A "
            "payment integration should provide transaction ID, receipt, "
            "chain/ledger state, finality/irreversibility flag, reconciliation "
            "status, reversal window, and escalation decision. Complexity: "
            "substantial."
        ),
    ),
    "PR-10": DeferredSpec(
        control_id="PR-10",
        control_name="Memory and Context Integrity",
        reason="cross_action",
        todo_block=(
            "Gap class: `cross_action`. This control requires persistent memory, "
            "retrieved context, and shared task state to carry provenance, integrity "
            "checks, and quarantine controls. A single Action can carry snippets of "
            "retrieved context, but integrity requires history across memory "
            "writes/reads and quarantine state. State should live in a memory/context "
            "evidence store or provenance graph keyed by memory item, source, hash, "
            "quarantine status, and consuming action. Complexity: substantial."
        ),
    ),
    "PR-12": DeferredSpec(
        control_id="PR-12",
        control_name="Secrets, Credential and Wallet Key Custody",
        reason="new_data",
        todo_block=(
            "Gap class: `new_data`. This control requires secrets, API keys, signing "
            "keys, wallet material, access information, and payment credentials to be "
            "vaulted, scoped, rotated, and kept out of prompts/tools. Actions can be "
            "scanned for leaked secrets, but custody validation needs "
            "vault/secret-manager metadata, key scope, rotation state, and wallet "
            "policy. Producers/integrations should provide secret scan findings, "
            "vault references, rotation timestamps, key scope, and prompt/tool "
            "exposure evidence. Complexity: substantial."
        ),
    ),
    "RS-01": DeferredSpec(
        control_id="RS-01",
        control_name="Automated Compliance Response",
        reason="cross_action",
        todo_block=(
            "Gap class: `cross_action`. This control requires predefined policy "
            "responses to run when evidence crosses control, classification, or "
            "overlay thresholds. Current Engine.evaluate returns decisions for "
            "individual Actions, but broader response automation needs state across "
            "evidence and hooks that execute response playbooks. State should live "
            "in the evidence store or incident/response system with threshold "
            "configuration, trigger record, response action, outcome, and owner. "
            "Complexity: substantial."
        ),
    ),
    "RS-04": DeferredSpec(
        control_id="RS-04",
        control_name="Cascade Containment and Blast-Radius Control",
        reason="cross_action",
        todo_block=(
            "Gap class: `cross_action`. This control requires multi-agent workflows "
            "to enforce failure-domain isolation, circuit breakers, and coordinated "
            "kill-switch behavior. That requires state across agents, sessions, "
            "parent/child actions, tools, and workflow topology. State should live "
            "in a workflow/evidence graph with agent relationships, failure domains, "
            "circuit-breaker state, propagated containment decisions, and "
            "blast-radius metrics. Complexity: substantial."
        ),
    ),
}

DEFERRED_CONTROL_SPECS: dict[str, DeferredSpec] = {}


class DeferredEvaluator:
    """Evaluator that records an honest architecture blocker for a control."""

    def __init__(self, control_id: str, reason: str, todo_block: str) -> None:
        self.control_id = control_id
        self.control_name = DEFERRED_CONTROL_SPECS.get(
            control_id,
            DeferredSpec(control_id, control_id, reason, todo_block),
        ).control_name
        self.reason = reason
        self.todo_block = todo_block

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="SKIP",
            detail=f"Legacy architecture blocker: {self.reason}",
            evidence_data={
                "todo": self.todo_block,
                "blocking_capability": self.reason,
            },
            duration_ms=(time.perf_counter() - start) * 1000,
        )


def make_deferred_evaluators() -> dict[str, DeferredEvaluator]:
    return {
        control_id: DeferredEvaluator(
            spec.control_id,
            reason=spec.reason,
            todo_block=spec.todo_block,
        )
        for control_id, spec in DEFERRED_CONTROL_SPECS.items()
    }
