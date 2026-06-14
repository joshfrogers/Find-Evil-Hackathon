# pyre-strict
"""Iterative multi-round adversarial verification.

Wraps the single-round ``VerifierAgent.challenge_once()`` in an early-stopping
loop (up to ``max_rounds``, default 3) bounded by a time budget. Each round
challenges the finding; if the verdict is still ambiguous, the loop refines with
another round, feeding a summary of prior rounds back into the challenge.

Termination (whichever comes first):
  - clear refute: the original output does not support the claim, or a round
    returns ``refuted``;
  - clear confirm: a ``confirmed`` round with cross-domain corroboration, or with
    no contradicting counter-evidence;
  - ``max_rounds`` reached;
  - the time budget is exhausted.

The verdict is ``confirmed`` | ``downgraded`` | ``refuted``. Confidence
recalibration (which can *raise* confidence on corroboration) is applied by the
orchestrator via ``verification.confidence.recalibrate``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agents.base import ChallengeResult, Finding, VerifierAgent
    from audit.logger import AuditLogger

DEFAULT_MAX_ROUNDS: int = 3
DEFAULT_TIME_BUDGET_SECONDS: float = 180.0


@dataclass
class VerificationOutcome:
    """Result of a multi-round verification."""

    verdict: str
    rounds_taken: int
    reasoning_chain: list[str] = field(default_factory=list)
    counter_evidence: list[str] = field(default_factory=list)


class MultiRoundVerifier:
    """Drives up to ``max_rounds`` challenge rounds with early-stop + time budget.

    Usage:
        mrv = MultiRoundVerifier(verifier_agent, audit)
        outcome = mrv.verify(finding, original_outputs, evidence_path,
                             corroboration_count=c.count,
                             corroboration_ids=c.corroborating_ids)
    """

    def __init__(
        self,
        challenger: "VerifierAgent",
        audit_logger: "AuditLogger",
        max_rounds: int = DEFAULT_MAX_ROUNDS,
        time_budget_seconds: float = DEFAULT_TIME_BUDGET_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.challenger = challenger
        self.audit = audit_logger
        self.max_rounds = max_rounds
        self.time_budget_seconds = time_budget_seconds
        self._clock = clock

    def verify(
        self,
        finding: "Finding",
        original_outputs: list[dict],
        evidence_path: str,
        corroboration_count: int = 0,
        corroboration_ids: list[str] | None = None,
    ) -> VerificationOutcome:
        start = self._clock()
        chain: list[str] = []
        counter_evidence: list[str] = []
        verdict = "confirmed"
        rounds = 0

        for round_num in range(1, self.max_rounds + 1):
            over_budget = (self._clock() - start) >= self.time_budget_seconds
            if round_num > 1 and over_budget:
                chain.append(f"Round {round_num}: skipped — time budget exhausted")
                break

            result = self.challenger.challenge_once(
                finding,
                original_outputs,
                evidence_path,
                prior_context="\n".join(chain),
            )
            rounds = round_num
            if result.counter_evidence:
                counter_evidence = result.counter_evidence
            verdict = result.verdict
            chain.append(self._summarize(round_num, result, corroboration_count))

            if result.llm_failed:
                break
            if not result.supports_claim or result.verdict == "refuted":
                verdict = "refuted"
                break
            if result.verdict == "confirmed" and (
                corroboration_count >= 1 or not result.counter_results
            ):
                break
            # Ambiguous (downgraded, or confirmed-but-uncorroborated with
            # contradicting counter-evidence): refine in another round.

        self.audit.log_verification(
            self.challenger.name,
            finding.finding_id,
            verdict,
            counter_evidence=counter_evidence,
            corroboration=corroboration_ids or [],
            rounds_taken=rounds,
        )
        return VerificationOutcome(verdict, rounds, chain, counter_evidence)

    @staticmethod
    def _summarize(
        round_num: int,
        result: "ChallengeResult",
        corroboration_count: int,
    ) -> str:
        bits = [f"Round {round_num}: verdict={result.verdict}"]
        if result.llm_failed:
            bits.append("LLM unavailable (defaulted to confirmed)")
        elif not result.supports_claim:
            bits.append("original output does not support the claim")
        else:
            bits.append(f"{len(result.counter_results)} counter-check(s)")
            bits.append(f"corroboration={corroboration_count}")
        if result.analysis:
            bits.append(result.analysis[:160])
        return " | ".join(bits)
