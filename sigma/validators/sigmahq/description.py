from dataclasses import dataclass
from typing import ClassVar, List, Tuple


from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqDescriptionExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule is missing the description field"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqDescriptionExistenceValidator(SigmaRuleValidator):
    """Checks if a rule is missing the description field"""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.description is None:
            return [SigmahqDescriptionExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqDescriptionLengthIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has an overly brief description."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


@dataclass(frozen=True)
class SigmahqDescriptionLengthValidator(SigmaRuleValidator):
    """Checks if a rule has an overly brief description."""

    description_len: int = 16

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.description is not None and len(rule.description) < self.description_len:
            return [SigmahqDescriptionLengthIssue([rule])]
        else:
            return []


@dataclass
class SigmahqLinkInDescriptionIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule has a description field that contains a reference to a hyperlink. All hyperlinks are reserved for the references field"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    word: str


@dataclass(frozen=True)
class SigmahqLinkInDescriptionValidator(SigmaRuleValidator):
    """Checks if a rule has a description field that contains a reference to a hyperlink."""

    word_list: Tuple[str, ...] = ("http://", "https://", "internal research")

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.description and rule.references == []:
            for word in self.word_list:
                if word in rule.description.lower():
                    return [SigmahqLinkInDescriptionIssue([rule], word)]
        return []
