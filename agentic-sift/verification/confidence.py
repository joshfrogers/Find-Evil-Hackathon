# pyre-strict
"""Deterministic confidence recalibration after verification.

Policy:
  - The verifier's verdict can only LOWER confidence:
      * ``refuted``    -> the finding is dropped (caller drops it; confidence
                          is returned unchanged for the record);
      * ``downgraded`` -> one level down (confirmed -> inferred -> possible,
                          floored at possible).
  - Cross-domain corroboration can RAISE confidence by one level, but ONLY when
    the verdict is ``confirmed`` (we never override the verifier's decision to
    lower a finding), and never above ``confirmed``.

Confidence ladder: possible < inferred < confirmed.
"""

from __future__ import annotations

_LEVELS: list[str] = ["possible", "inferred", "confirmed"]


def _index(confidence: str) -> int:
    try:
        return _LEVELS.index(confidence)
    except ValueError:
        return 0  # unknown -> treat as the weakest level


def recalibrate(
    base_confidence: str,
    verdict: str,
    corroboration_count: int,
) -> tuple[str, str]:
    """Recompute confidence from a verdict + cross-domain corroboration.

    Returns ``(final_confidence, human_readable_reason)``.
    """
    if verdict == "refuted":
        return base_confidence, "refuted by verifier; finding dropped"

    idx = _index(base_confidence)

    if verdict == "downgraded":
        new_idx = max(0, idx - 1)
        return (
            _LEVELS[new_idx],
            f"downgraded by verifier ({base_confidence} -> {_LEVELS[new_idx]})",
        )

    # Non-lowering verdict (confirmed): corroboration may raise by one level.
    if corroboration_count >= 1:
        new_idx = min(len(_LEVELS) - 1, idx + 1)
        if new_idx != idx:
            return (
                _LEVELS[new_idx],
                f"confirmed and corroborated by {corroboration_count} "
                f"cross-domain finding(s) ({base_confidence} -> {_LEVELS[new_idx]})",
            )
        return (
            _LEVELS[idx],
            f"confirmed; already at max confidence with "
            f"{corroboration_count} cross-domain corroboration(s)",
        )

    return _LEVELS[idx], "confirmed; no cross-domain corroboration"
