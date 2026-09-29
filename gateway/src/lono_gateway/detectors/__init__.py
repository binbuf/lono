"""Detectors for the Lono security pipeline."""

from __future__ import annotations


class DetectorUnavailable(RuntimeError):
    """Raised when a detector is required (fail-closed) but unavailable."""