"""Core data models, scoring, file walking, and scan orchestration.

The core depends on ``lattice.rules`` only; it must never import a detector
or an emitter (dependency direction: detectors/emitters -> core -> rules).
"""
