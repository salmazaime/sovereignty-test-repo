# app/connectors/region_lookup.py
"""
Same lookup-table philosophy as app/policy/lookup_tables.py: legal/
geographic facts belong in config files a non-developer can update,
not hardcoded in connector logic
"""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RegionCountryTable:
    aws: dict[str, str]
    azure: dict[str, str]

    def country_for(self, cloud: str, region: str) -> str | None:
        table = self.aws if cloud == "aws" else self.azure
        return table.get(region)

    @classmethod
    def load(cls, path: Path) -> "RegionCountryTable":
        data = json.loads(path.read_text())
        return cls(aws=data["aws"], azure=data["azure"])
        