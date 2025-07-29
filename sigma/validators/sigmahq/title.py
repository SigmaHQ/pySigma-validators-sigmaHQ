# sigma/validators/sigmahq/title.py

from dataclasses import dataclass
from typing import ClassVar, List, Tuple

from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)
from .config import ConfigHQ

config = ConfigHQ()


@dataclass
class SigmahqTitleLengthIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title that is too long."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


@dataclass(frozen=True)
class SigmahqTitleLengthValidator(SigmaRuleValidator):
    """Checks if a rule has an excessively long title."""

    max_length: int = 120

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if len(rule.title) > self.max_length:
            return [SigmahqTitleLengthIssue([rule])]
        return []


@dataclass
class SigmahqTitleStartIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title that starts with the word 'Detect' or 'Detects'."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqTitleStartValidator(SigmaRuleValidator):
    """Checks if a rule title starts with the word 'Detect' or 'Detects'."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.title.startswith("Detect ") or rule.title.startswith("Detects "):
            return [SigmahqTitleStartIssue([rule])]
        return []


@dataclass
class SigmahqTitleEndIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title that ends with a dot(.)"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqTitleEndValidator(SigmaRuleValidator):
    """Checks if a rule has a title that ends with a dot(.)."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.title.endswith("."):
            return [SigmahqTitleEndIssue([rule])]
        return []


@dataclass
class SigmahqTitleCaseIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title with invalid casing"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    word: str


@dataclass(frozen=True)
class SigmahqTitleCaseValidator(SigmaRuleValidator):
    """Checks if a rule has a title with invalid casing."""

    word_list: Tuple[str, ...] = (
        "a",
        "an",
        "and",
        "as",
        "at",
        "by",
        "for",
        "from",
        "in",
        "new",
        "of",
        "on",
        "or",
        "over",
        "the",
        "through",
        "to",
        "via",
        "with",
        "without",
    )

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        wrong_casing = []
        for word in rule.title.split(" "):
            if (
                word.islower()
                and not word.lower() in self.word_list
                and not "." in word
                and not "/" in word
                and not "_" in word
                and not word[0].isdigit()
            ):
                wrong_casing.append(word)
        case_error = []
        for word in wrong_casing:
            case_error.append(SigmahqTitleCaseIssue([rule], word))
        return case_error
