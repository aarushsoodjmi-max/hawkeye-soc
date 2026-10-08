"""
seed.py
--------
Deterministic random-seed utilities for the HawkEye SOC simulator.

All randomness in the simulator flows through a single `random.Random`
instance so that the same seed always reproduces the same alert dataset —
important for unit tests, detection-rule regression tests, and demos.
"""

import random


def get_rng(seed: int = None) -> random.Random:
    """
    Return a random.Random instance.

    If `seed` is provided, the returned generator is fully deterministic:
    calling get_rng(42) twice and generating scenarios in the same order
    will produce identical DataFrames (aside from the intentionally
    non-deterministic alert_id column — see event_generator.make_alert_id).

    If `seed` is None, a non-deterministic generator is returned, seeded
    from OS entropy.
    """
    return random.Random(seed)


def set_global_seed(seed: int) -> None:
    """
    Seed Python's global `random` module. Provided for convenience when a
    caller wants module-level reproducibility rather than an explicit
    random.Random instance (e.g. quick scripts, notebooks).
    """
    random.seed(seed)
