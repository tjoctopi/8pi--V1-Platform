"""Evidence fusion — combine independent signals via Bayesian update (spec §5).

When independent tools/oracles report on the same asset, we combine their
confidences with a Bayesian odds update rather than taking a max or an average:
agreement raises confidence, disagreement lowers it. Working in log-odds keeps
the update numerically stable and order-independent.

    posterior_odds = prior_odds * Π (likelihood_ratio_i)

Each piece of evidence contributes a likelihood ratio derived from its reported
probability. Independent confirmations multiply; a contradicting signal divides.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

_EPS = 1e-6


def _clamp(p: float) -> float:
    return min(1.0 - _EPS, max(_EPS, p))


@dataclass(frozen=True)
class Evidence:
    """One independent signal about a hypothesis (e.g. "vuln is real")."""

    #: Probability the hypothesis is true GIVEN this evidence alone.
    probability: float
    #: How much to trust this source in general (0..1); scales its pull.
    weight: float = 1.0
    source: str = "unknown"


def fuse(evidence: list[Evidence], prior: float = 0.5) -> float:
    """Fuse independent evidence into a posterior probability.

    ``prior`` is the base rate before any evidence. Each item nudges the
    log-odds by ``weight * (logit(p) - logit(prior))`` — an item at the prior
    contributes nothing; a confident agreeing item pushes up; a confident
    disagreeing item pushes down.
    """

    prior = _clamp(prior)
    prior_logit = math.log(prior / (1 - prior))
    log_odds = prior_logit
    for ev in evidence:
        p = _clamp(ev.probability)
        ev_logit = math.log(p / (1 - p))
        log_odds += ev.weight * (ev_logit - prior_logit)
    return 1.0 / (1.0 + math.exp(-log_odds))


def agreement_boost(probabilities: list[float]) -> float:
    """Convenience: fuse several equally-weighted agreeing/disagreeing signals."""

    return fuse([Evidence(probability=p) for p in probabilities])
