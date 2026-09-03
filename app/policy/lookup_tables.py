"""
Loads the two legal lookup tables from config files. Kept separate
from the decision engine itself so the engine's logic can be tested
against fake tables without touching the filesystem (see tests/).
"""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AdequacyTable:
    adequate_countries: frozenset[str]

    def is_adequate(self, country: str) -> bool:
        return country in self.adequate_countries

    @classmethod
    def load(cls, path: Path) -> "AdequacyTable":
        data = json.loads(path.read_text())
        return cls(adequate_countries=frozenset(data["adequate_countries"]))


@dataclass(frozen=True)
class QualifiedProviderTable:
    qualified_pairs: frozenset[tuple[str, str]]

    def is_qualified(self, cloud: str, region: str) -> bool:
        return (cloud, region) in self.qualified_pairs

    @classmethod
    def load(cls, path: Path) -> "QualifiedProviderTable":
        data = json.loads(path.read_text())
        pairs = {(p["cloud"], p["region"]) for p in data["qualified_providers"]}
        return cls(qualified_pairs=frozenset(pairs))