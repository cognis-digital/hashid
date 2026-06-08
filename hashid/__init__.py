"""HASHID — identify hash types and estimate crack cost/feasibility.

Defensive/authorized-testing utility. Analysis and triage only:
it classifies a hash string and estimates the difficulty of recovering
the plaintext. It performs NO cracking and makes NO network calls.
"""
from .core import (
    HashCandidate,
    CrackEstimate,
    identify,
    estimate_crack,
    analyze,
)

TOOL_NAME = "hashid"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "HashCandidate",
    "CrackEstimate",
    "identify",
    "estimate_crack",
    "analyze",
]
