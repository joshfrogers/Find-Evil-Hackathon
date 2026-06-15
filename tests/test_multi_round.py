# pyre-strict
"""Tests for the iterative multi-round verifier."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# sys.path setup required for standalone execution on SIFT workstations
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.base import ChallengeResult, Finding
from audit.logger import AuditLogger
from verification.multi_round import MultiRoundVerifier


def _finding() -> Finding:
    return Finding(
        finding_id="F-1",
        description="Persistence via Run key",
        confidence="confirmed",
        evidence_links=["exec-1"],
        agent_name="artifacts_agent",
    )


def _result(
    verdict: str,
    supports_claim: bool = True,
    counter_results: list[dict] | None = None,
    llm_failed: bool = False,
    analysis: str = "",
) -> ChallengeResult:
    return ChallengeResult(
        verdict=verdict,
        supports_claim=supports_claim,
        analysis=analysis,
        counter_evidence=[f"ce-{verdict}"] if counter_results else [],
        counter_results=counter_results or [],
        llm_failed=llm_failed,
    )


class MultiRoundVerifierTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        self.challenger = MagicMock()
        self.challenger.name = "verifier"

    def _verifier(self, **kwargs) -> MultiRoundVerifier:
        return MultiRoundVerifier(self.challenger, self.audit, **kwargs)

    def test_clear_confirm_with_corroboration_stops_round_one(self):
        self.challenger.challenge_once.side_effect = [
            _result("confirmed", counter_results=[{"tool": "x"}])
        ]
        outcome = self._verifier().verify(_finding(), [], "/img", corroboration_count=2)
        self.assertEqual(outcome.verdict, "confirmed")
        self.assertEqual(outcome.rounds_taken, 1)
        self.assertEqual(self.challenger.challenge_once.call_count, 1)

    def test_confirmed_no_counter_evidence_stops_early(self):
        # Confirmed with no contradicting counter-evidence -> confident stop.
        self.challenger.challenge_once.side_effect = [_result("confirmed")]
        outcome = self._verifier().verify(_finding(), [], "/img", corroboration_count=0)
        self.assertEqual(outcome.verdict, "confirmed")
        self.assertEqual(outcome.rounds_taken, 1)

    def test_clear_refute_stops_immediately(self):
        self.challenger.challenge_once.side_effect = [
            _result("refuted", supports_claim=False, analysis="no such key")
        ]
        outcome = self._verifier().verify(_finding(), [], "/img")
        self.assertEqual(outcome.verdict, "refuted")
        self.assertEqual(outcome.rounds_taken, 1)

    def test_ambiguous_runs_until_cap(self):
        # Downgraded every round -> keeps refining until max_rounds.
        self.challenger.challenge_once.side_effect = [
            _result("downgraded", counter_results=[{"tool": "a"}]),
            _result("downgraded", counter_results=[{"tool": "b"}]),
            _result("downgraded", counter_results=[{"tool": "c"}]),
        ]
        outcome = self._verifier(max_rounds=3).verify(_finding(), [], "/img")
        self.assertEqual(outcome.rounds_taken, 3)
        self.assertEqual(outcome.verdict, "downgraded")
        self.assertEqual(self.challenger.challenge_once.call_count, 3)

    def test_confirmed_uncorroborated_with_counter_evidence_keeps_going(self):
        # confirmed + counter-evidence + no corroboration is ambiguous -> refine,
        # then a clean confirmed (no counter-evidence) ends it.
        self.challenger.challenge_once.side_effect = [
            _result("confirmed", counter_results=[{"tool": "a"}]),
            _result("confirmed"),
        ]
        outcome = self._verifier().verify(_finding(), [], "/img", corroboration_count=0)
        self.assertEqual(outcome.verdict, "confirmed")
        self.assertEqual(outcome.rounds_taken, 2)

    def test_llm_failure_stops_with_unverified_verdict(self):
        # When the verification LLM is unavailable, the finding must NOT be
        # reported as "confirmed" (that would present an unverified claim at
        # parity with a genuinely challenged one). It stops with a distinct
        # "unverified" verdict the orchestrator keeps but does not mark verified.
        self.challenger.challenge_once.side_effect = [
            _result("confirmed", llm_failed=True)
        ]
        outcome = self._verifier().verify(_finding(), [], "/img")
        self.assertEqual(outcome.verdict, "unverified")
        self.assertEqual(outcome.rounds_taken, 1)

    def test_time_budget_caps_rounds(self):
        # Ambiguous results would run 3 rounds, but a zero budget stops after one.
        self.challenger.challenge_once.side_effect = [
            _result("downgraded", counter_results=[{"tool": "a"}]),
            _result("downgraded", counter_results=[{"tool": "b"}]),
            _result("downgraded", counter_results=[{"tool": "c"}]),
        ]
        outcome = self._verifier(time_budget_seconds=0.0).verify(_finding(), [], "/img")
        self.assertEqual(outcome.rounds_taken, 1)
        self.assertEqual(self.challenger.challenge_once.call_count, 1)

    def test_logs_verification_with_rounds_and_corroboration(self):
        self.challenger.challenge_once.side_effect = [
            _result("downgraded", counter_results=[{"tool": "a"}]),
            _result("confirmed"),
        ]
        self._verifier().verify(
            _finding(),
            [],
            "/img",
            corroboration_count=1,
            corroboration_ids=["F-9"],
        )
        events = self.audit.get_events("verification")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["rounds_taken"], 2)
        self.assertEqual(events[0]["corroboration"], ["F-9"])
        self.assertEqual(events[0]["verdict"], "confirmed")

    def test_reasoning_chain_records_each_round(self):
        self.challenger.challenge_once.side_effect = [
            _result("downgraded", counter_results=[{"tool": "a"}]),
            _result("confirmed"),
        ]
        outcome = self._verifier().verify(_finding(), [], "/img")
        self.assertEqual(len(outcome.reasoning_chain), 2)
        self.assertIn("Round 1", outcome.reasoning_chain[0])
        self.assertIn("Round 2", outcome.reasoning_chain[1])


class ChallengeOnceTest(unittest.TestCase):
    """challenge_once returns structured results without logging a verdict."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(Path(self._tmpdir) / "audit.jsonl")
        from executor.runner import LocalExecutor

        self.executor = MagicMock(spec=LocalExecutor)
        self.tools = [
            {
                "name": "fls",
                "display_name": "fls",
                "path": "/usr/bin/fls",
                "description": "x",
            }
        ]

    def test_challenge_once_does_not_log_verification(self):
        from unittest.mock import patch

        from agents.base import VerifierAgent

        with patch("agents.base.call_claude_json") as mock_claude:
            mock_claude.return_value = {
                "output_supports_claim": True,
                "counter_evidence_commands": [],
            }
            verifier = VerifierAgent(self.executor, self.audit, self.tools)
            result = verifier.challenge_once(_finding(), [], "/img")

        self.assertEqual(result.verdict, "confirmed")
        self.assertTrue(result.supports_claim)
        # No verification event — that is the multi-round loop's responsibility.
        self.assertEqual(len(self.audit.get_events("verification")), 0)
