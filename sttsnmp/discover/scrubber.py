"""
configlint.scrubber — Strip noise lines from device configs.

Same logic as driftwatch's scrubber — remove timestamps, boot markers,
and other lines that change without meaningful config change. Keeps
policy checks focused on actual configuration.
"""

from __future__ import annotations

import re
import logging
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml



logger = logging.getLogger(__name__)


BUILTIN_FILTERS: dict[str, list[str]] = {
    "juniper": [
        r"^## Last changed:.*",
        r"^## Last commit:.*",
        r"^## Last commit by:.*",
        r"^\s*/\*.*\*/\s*$",
    ],
    "arista": [
        r"^! Last configuration change at.*",
        r"^! Startup-config last modified at.*",
        r"^! boot system flash:.*",
        r"^! device:.*",
        r"^! Serial Number:.*",
    ],
    "global": [
        r"^\s*$",
        r"^Building configuration.*",
        r"^Current configuration.*",
        r"^!Time:.*",
        r"^! Command:.*",
        r"^!\s*$",
    ],
}


class ConfigScrubber:
    """Strip noise lines from device configuration text."""

    def __init__(self, filters_file: Optional[Path] = None):
        self._filters: dict[str, list[re.Pattern]] = {}
        self._load_filters(filters_file)

    def _load_filters(self, filters_file: Optional[Path]) -> None:
        raw: dict[str, list[str]] = {}

        for section, patterns in BUILTIN_FILTERS.items():
            raw.setdefault(section, []).extend(patterns)

        if filters_file and filters_file.exists():
            try:
                user_filters = yaml.safe_load(filters_file.read_text()) or {}
                for section, patterns in user_filters.items():
                    if isinstance(patterns, dict) and "strip_lines" in patterns:
                        patterns = patterns["strip_lines"]
                    if isinstance(patterns, list):
                        raw.setdefault(section, []).extend(patterns)
                logger.debug(f"Loaded user filters from {filters_file}")
            except Exception as e:
                logger.warning(f"Failed to load filters file: {e}")

        for section, patterns in raw.items():
            compiled = []
            for p in patterns:
                try:
                    compiled.append(re.compile(p))
                except re.error as e:
                    logger.warning(f"Invalid filter pattern {p!r}: {e}")
            self._filters[section] = compiled

    def scrub(self, config: str, platform: Platform) -> str:
        patterns: list[re.Pattern] = []
        patterns.extend(self._filters.get("global", []))
        patterns.extend(self._filters.get(platform.value, []))

        lines = config.splitlines()
        cleaned = []

        for line in lines:
            if not any(p.match(line) for p in patterns):
                cleaned.append(line)

        # Juniper display-set: sort for deterministic comparison
        if platform == Platform.JUNIPER:
            set_lines = [l for l in cleaned if l.startswith("set ")]
            other_lines = [l for l in cleaned if not l.startswith("set ")]
            cleaned = other_lines + sorted(set_lines)

        return "\n".join(cleaned) + "\n" if cleaned else ""
