from dataclasses import dataclass
from typing import ClassVar, List, Tuple
import re

from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqFalsepositivesCapitalIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule contains a falsepositive entry that doesn't start with a capital letter"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    word: str


class SigmahqFalsepositivesCapitalValidator(SigmaRuleValidator):
    """Checks if a rule falsepositive entry starts with a capital letter."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        false_positive: List[SigmaValidationIssue] = []
        if rule.falsepositives:
            for fp in rule.falsepositives:
                if fp[0].upper() != fp[0]:
                    # return only the first word
                    false_positive.append(
                        SigmahqFalsepositivesCapitalIssue([rule], fp.split(" ")[0])
                    )
        return false_positive


@dataclass
class SigmahqFalsepositivesBannedWordIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule defines a falsepositive entry that is part of the banned words list"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    word: str


@dataclass(frozen=True)
class SigmahqFalsepositivesBannedWordValidator(SigmaRuleValidator):
    """Checks if a rule contains a falsepositive entry that is part of the banned word list."""

    word_list: Tuple[str, ...] = ("none", "pentest", "penetration")

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        banned_words: List[SigmaValidationIssue] = []
        if rule.falsepositives:
            for fp_entry in rule.falsepositives:
                for fp in fp_entry.split(" "):
                    for banned_word in self.word_list:
                        if fp.lower().strip() == banned_word:
                            banned_words.append(SigmahqFalsepositivesBannedWordIssue([rule], fp))
        return banned_words


@dataclass
class SigmahqFalsepositivesTypoWordIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule contains a falsepositive entry with a common typo."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    word: str


@dataclass(frozen=True)
class SigmahqFalsepositivesTypoWordValidator(SigmaRuleValidator):
    """Checks if a rule falsepositive entry contains a common typo."""

    word_list: Tuple[str, ...] = ("unkown", "ligitimate", "legitim ", "legitimeate")

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        typos: List[SigmaValidationIssue] = []
        if rule.falsepositives:
            for fp_entry in rule.falsepositives:
                for fp in fp_entry.split(" "):
                    for typo in self.word_list:
                        if fp.lower().strip() == typo:
                            typos.append(SigmahqFalsepositivesTypoWordIssue([rule], fp))
        return typos
