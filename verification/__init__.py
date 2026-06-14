# pyre-strict
"""Multi-round adversarial verification.

Public API:
  - recalibrate: deterministic confidence recalibration after a verdict.
  - CorroborationIndex / Corroboration: deterministic cross-domain corroboration.
"""

from verification.confidence import recalibrate
from verification.corroboration import Corroboration, CorroborationIndex

__all__ = ["recalibrate", "Corroboration", "CorroborationIndex"]
