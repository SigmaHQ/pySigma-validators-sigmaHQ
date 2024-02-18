from dataclasses import dataclass
from typing import ClassVar, List

from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)
from .config import ConfigHq

config = ConfigHq()


@dataclass
class SigmahqTitleLengthIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        f"Rule has a title longer than {config.title_lengh} characters"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqTitleLengthValidator(SigmaRuleValidator):
    """Checks if rule has a title too long."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if len(rule.title) > config.title_lengh:
            return [SigmahqTitleLengthIssue([rule])]
        else:
            return []


@dataclass
class SigmahqTitleStartIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title start with Detects"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqTitleStartValidator(SigmaRuleValidator):
    """Checks if rule title start with Detects."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.title.startswith("Detects "):
            return [SigmahqTitleStartIssue([rule])]
        return []


@dataclass
class SigmahqTitleEndIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title that end with a dot"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqTitleEndValidator(SigmaRuleValidator):
    """Checks if rule title end with a dot(.)."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.title.endswith("."):
            return [SigmahqTitleEndIssue([rule])]
        return []


@dataclass
class SigmahqTitleCaseIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title with invalid case"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
    word: str


class SigmahqTitleCaseValidator(SigmaRuleValidator):
    """Checks if rule title use capitalization."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        wrong_casing = []
        for word in rule.title.split(" "):
            if (
                word.islower()
                and not word.lower() in config.allowed_lowercase_words
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
