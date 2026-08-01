"""Detector registry: the one place that knows every concrete detector.

The CLI and tests build detector sets from here; ``core`` never imports it
(dependency rule: core knows only the ``Detector`` interface).
"""

from __future__ import annotations

from lattice.detectors.base import Detector
from lattice.detectors.c_cpp_det import CCppDetector
from lattice.detectors.config_det import ConfigDetector
from lattice.detectors.csharp_det import CSharpDetector
from lattice.detectors.dependency_det import DependencyDetector
from lattice.detectors.go_det import GoDetector
from lattice.detectors.java_det import JavaDetector
from lattice.detectors.javascript_det import JavaScriptDetector
from lattice.detectors.php_det import PHPDetector
from lattice.detectors.python_det import PythonDetector
from lattice.detectors.ruby_det import RubyDetector
from lattice.detectors.rust_det import RustDetector
from lattice.detectors.swift_det import SwiftDetector

#: --languages token -> detector class
LANGUAGE_MAP: dict[str, type[Detector]] = {
    "py": PythonDetector,
    "java": JavaDetector,
    "js": JavaScriptDetector,
    "go": GoDetector,
    "c": CCppDetector,
    "rust": RustDetector,
    "csharp": CSharpDetector,
    "ruby": RubyDetector,
    "php": PHPDetector,
    "swift": SwiftDetector,
    "config": ConfigDetector,
    "deps": DependencyDetector,
}


def all_detectors() -> list[Detector]:
    """One instance of every detector, in stable order."""
    return [cls() for cls in LANGUAGE_MAP.values()]


def detectors_for(languages: list[str] | None) -> list[Detector]:
    """Detectors for a --languages selection (None = all).

    Language filtering never disables the config and dependency detectors:
    they are cross-language and inventory-only.
    """
    if not languages:
        return all_detectors()
    selected: list[Detector] = []
    unknown = [lang for lang in languages if lang not in LANGUAGE_MAP]
    if unknown:
        raise ValueError(f"unknown language(s): {', '.join(unknown)}")
    for token, cls in LANGUAGE_MAP.items():
        if token in languages or token in ("config", "deps"):
            selected.append(cls())
    return selected
