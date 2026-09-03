"""
Single source of truth for translating external DLP vendor
categories into our fixed SensitivityCategory enum. Both the Macie
and Purview connectors import from here — duplicating this mapping
in two files would mean a future correction (e.g. "actually SSN
should map to national_id, not ordinary_pii") only gets fixed in
one place if we're not careful. One file, one mapping, per the same
"single seam" principle as app/connectors/transform.py in Step 13.

This is a deliberately LOSSY translation, and that's worth stating
outright rather than hiding: AWS Macie and Azure Purview know
generic, US/EU-centric PII categories (SSN, credit card, name,
email). Neither product has native awareness of Moroccan legal
categories (CIN structure, Loi 09-08's specific enumerated
categories). Anything that doesn't map cleanly falls back to
'ordinary_pii' rather than being silently dropped -- an
over-inclusive fallback is the fail-cautious choice, consistent
with every other "assume the riskier classification on uncertainty"
decision made in this project (Step 11's fail-closed, Step 13's
"assume public on unknown").
"""

import logging

from app.schemas import SensitivityCategory

logger = logging.getLogger(__name__)

# AWS Macie detection "type" values -> our category enum.
# Reference: Macie's built-in managed data identifiers.
MACIE_DETECTION_MAP: dict[str, SensitivityCategory] = {
    "EMAIL_ADDRESS": SensitivityCategory.ORDINARY_PII,
    "NAME": SensitivityCategory.ORDINARY_PII,
    "ADDRESS": SensitivityCategory.ORDINARY_PII,
    "PHONE_NUMBER": SensitivityCategory.ORDINARY_PII,
    "US_SOCIAL_SECURITY_NUMBER": SensitivityCategory.NATIONAL_ID,
    "US_PASSPORT_NUMBER": SensitivityCategory.NATIONAL_ID,
    "NATIONAL_IDENTIFICATION_NUMBER": SensitivityCategory.NATIONAL_ID,
    "CREDIT_CARD_NUMBER": SensitivityCategory.ORDINARY_PII,
    "BANK_ACCOUNT_NUMBER": SensitivityCategory.ORDINARY_PII,
    "HEALTH_INSURANCE_CLAIM_NUMBER": SensitivityCategory.HEALTH,
    "MEDICAL_RECORD_NUMBER": SensitivityCategory.HEALTH,
    "GENETIC_INFORMATION": SensitivityCategory.GENETIC,
    "CRIMINAL_JUSTICE": SensitivityCategory.CRIMINAL_RECORD_OR_SECURITY_MEASURE,
}

# AWS Macie top-level "category" values (from classificationDetails.result
# .sensitiveData[].category) -> our category enum, used when a specific
# detection "type" isn't in MACIE_DETECTION_MAP above.
MACIE_CATEGORY_FALLBACK_MAP: dict[str, SensitivityCategory] = {
    "PERSONAL_INFORMATION": SensitivityCategory.ORDINARY_PII,
    "FINANCIAL_INFORMATION": SensitivityCategory.ORDINARY_PII,
    "CREDENTIALS": SensitivityCategory.ORDINARY_PII,
    "HEALTH": SensitivityCategory.HEALTH,
}


def map_macie_detection(detection_type: str, top_level_category: str) -> SensitivityCategory:
    if detection_type in MACIE_DETECTION_MAP:
        return MACIE_DETECTION_MAP[detection_type]
    if top_level_category in MACIE_CATEGORY_FALLBACK_MAP:
        logger.info(
            "Macie detection type '%s' unmapped, falling back to category-level "
            "mapping for '%s'.", detection_type, top_level_category,
        )
        return MACIE_CATEGORY_FALLBACK_MAP[top_level_category]
    logger.warning(
        "Unmapped Macie detection '%s' (category '%s') -> defaulting to ordinary_pii.",
        detection_type, top_level_category,
    )
    return SensitivityCategory.ORDINARY_PII


# Azure Purview classification names follow the pattern
# "MICROSOFT.<DOMAIN>.<SPECIFIC>" -- we match on substrings within
# <DOMAIN>/<SPECIFIC> rather than an exhaustive exact-match table,
# since Purview's classifier catalog is large and grows over time;
# substring matching is more resilient to new classifier names being
# added upstream without our mapping going stale.
_PURVIEW_SUBSTRING_MAP: list[tuple[str, SensitivityCategory]] = [
    ("PASSPORT", SensitivityCategory.NATIONAL_ID),
    ("NATIONAL_ID", SensitivityCategory.NATIONAL_ID),
    ("DRIVERS_LICENSE", SensitivityCategory.NATIONAL_ID),
    ("TAX_FILE_NUMBER", SensitivityCategory.NATIONAL_ID),
    ("HEALTH", SensitivityCategory.HEALTH),
    ("MEDICAL", SensitivityCategory.HEALTH),
    ("GENETIC", SensitivityCategory.GENETIC),
    ("RELIGION", SensitivityCategory.RELIGIOUS_PHILOSOPHICAL),
    ("POLITICAL", SensitivityCategory.POLITICAL),
    ("ETHNIC", SensitivityCategory.RACIAL_ETHNIC_ORIGIN),
    ("RACIAL", SensitivityCategory.RACIAL_ETHNIC_ORIGIN),
    ("UNION", SensitivityCategory.UNION),
    ("CRIMINAL", SensitivityCategory.CRIMINAL_RECORD_OR_SECURITY_MEASURE),
    ("PERSONAL", SensitivityCategory.ORDINARY_PII),
    ("FINANCIAL", SensitivityCategory.ORDINARY_PII),
    ("CREDIT_CARD", SensitivityCategory.ORDINARY_PII),
    ("BANK", SensitivityCategory.ORDINARY_PII),
]


def map_purview_classification(classification_name: str) -> SensitivityCategory:
    upper = classification_name.upper()
    for keyword, category in _PURVIEW_SUBSTRING_MAP:
        if keyword in upper:
            return category
    logger.warning(
        "Unmapped Purview classification '%s' -> defaulting to ordinary_pii.",
        classification_name,
    )
    return SensitivityCategory.ORDINARY_PII
    