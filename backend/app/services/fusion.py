"""
Signal Fusion Engine.

Combines signals from rules, ML, and relationship analysis into a
unified set of signals. Applies category caps to prevent any single
dimension from dominating the final score.

Key principles:
- Avoid double-counting correlated indicators
- Group by category and enforce caps
- Preserve the highest-severity signal per unique explanation
"""

from __future__ import annotations

from typing import Any

from app.core.config import CATEGORY_CAPS
from app.schemas.analysis import Signal


def fuse_signals(
    rule_signals: list[Signal],
    ml_signal: Signal | None = None,
    relationship_signals: list[Signal] | None = None,
) -> list[Signal]:
    """Fuse all signal sources into a deduplicated, capped set."""
    all_signals: list[Signal] = []

    # Add rule signals
    all_signals.extend(rule_signals)

    # Add ML signal
    if ml_signal:
        all_signals.append(ml_signal)

    # Add relationship signals
    if relationship_signals:
        all_signals.extend(relationship_signals)

    # Deduplicate: keep highest-severity signal per signal_id
    deduped = _deduplicate_signals(all_signals)

    # Apply category caps
    capped = _apply_category_caps(deduped)

    return capped


def _deduplicate_signals(signals: list[Signal]) -> list[Signal]:
    """Keep only the highest-severity signal per signal_id."""
    best: dict[str, Signal] = {}
    for sig in signals:
        existing = best.get(sig.signal_id)
        if existing is None or sig.risk_contribution > existing.risk_contribution:
            best[sig.signal_id] = sig
    return list(best.values())


def _apply_category_caps(signals: list[Signal]) -> list[Signal]:
    """Enforce per-category risk contribution caps."""
    # Group by category
    by_category: dict[str, list[Signal]] = {}
    for sig in signals:
        by_category.setdefault(sig.category, []).append(sig)

    result: list[Signal] = []
    for category, cat_signals in by_category.items():
        # Sort by risk contribution descending
        cat_signals.sort(key=lambda s: s.risk_contribution, reverse=True)

        cap = CATEGORY_CAPS.get(category, 25.0)
        total = 0.0

        for sig in cat_signals:
            if total >= cap:
                break
            remaining = cap - total
            # If this signal exceeds the remaining budget, clip it
            if sig.risk_contribution > remaining:
                # Create a clipped copy
                clipped = Signal(
                    signal_id=sig.signal_id,
                    category=sig.category,
                    severity=sig.severity,
                    risk_contribution=round(remaining, 2),
                    source=sig.source,
                    explanation=sig.explanation,
                    evidence=sig.evidence,
                )
                result.append(clipped)
                total = cap
            else:
                result.append(sig)
                total += sig.risk_contribution

    return result
