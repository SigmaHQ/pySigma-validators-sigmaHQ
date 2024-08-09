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
class SigmahqStatusExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has no status field"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqStatusExistenceValidator(SigmaRuleValidator):
    """Checks if a rule is missing the status field."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status is None:
            return [SigmahqStatusExistenceIssue(rule)]
        else:
            return []


@dataclass
class SigmahqStatusIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule uses the Deprecated or Unsupported status field"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqStatusValidator(SigmaRuleValidator):
    """Checks if rule has a status field with the value Deprecated or Unsupported."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status and rule.status.name in ["DEPRECATED", "UNSUPPORTED"]:
            return [SigmahqStatusIssue(rule)]
        else:
            return []


@dataclass
class SigmahqDateExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has no date field"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqDateExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a data."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.date is None:
            return [SigmahqDateExistenceIssue(rule)]
        else:
            return []


@dataclass
class SigmahqDescriptionExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has no description field"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqDescriptionExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description is None:
            return [SigmahqDescriptionExistenceIssue(rule)]
        else:
            return []


@dataclass
class SigmahqDescriptionLengthIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has an overly brief description."
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqDescriptionLengthValidator(SigmaRuleValidator):
    """Checks if a rule has a has an overly brief description."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description is not None and len(rule.description) < 16:
            return [SigmahqDescriptionLengthIssue(rule)]
        else:
            return []


@dataclass
class SigmahqLevelExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has no level field"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqLevelExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a level field."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.level is None:
            return [SigmahqLevelExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqFalsepositivesCapitalIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule falsepositive must start with a capital"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
    word: str


class SigmahqFalsepositivesCapitalValidator(SigmaRuleValidator):
    """Checks if rule falsepositive start with a capital."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        falsepositif = []
        if rule.falsepositives:
            for fp in rule.falsepositives:
                if fp[0].upper() != fp[0]:
                    # return only fisrt word
                    falsepositif.append(
                        SigmahqFalsepositivesCapitalIssue(rule, fp.split(" ")[0])
                    )
        return falsepositif


@dataclass
class SigmahqFalsepositivesBannedWordIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule falsepositive start with a banned word"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
    word: str


class SigmahqFalsepositivesBannedWordValidator(SigmaRuleValidator):
    """Checks if rule falsepositive start with a banned word."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        falsepositif = []
        if rule.falsepositives:
            for fp in rule.falsepositives:
                if fp.split(" ")[0].lower() in config.sigmahq_fp_banned_word:
                    falsepositif.append(
                        SigmahqFalsepositivesBannedWordIssue(rule, fp.split(" ")[0])
                    )
        return falsepositif


@dataclass
class SigmahqFalsepositivesTypoWordIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule falsepositive start with a common typo error"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
    word: str


class SigmahqFalsepositivesTypoWordValidator(SigmaRuleValidator):
    """Checks if rule falsepositive start with a common typo error."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        falsepositif = []
        if rule.falsepositives:
            for fp in rule.falsepositives:
                if fp.split(" ")[0].lower() in config.sigmahq_fp_typo_word:
                    falsepositif.append(
                        SigmahqFalsepositivesTypoWordIssue(rule, fp.split(" ")[0])
                    )
        return falsepositif


@dataclass
class SigmahqLinkDescriptionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule description have a link with no references"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )


class SigmahqLinkDescriptionValidator(SigmaRuleValidator):
    """Checks if rule description use a link instead of references."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description and rule.references == []:
            for link in config.sigmahq_link_in_description:
                if link in rule.description.lower():
                    return [SigmahqLinkDescriptionIssue(rule)]
        return []


@dataclass
class SigmahqUnknownFieldIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule uses an unknown field"
    severity: ClassVar[SigmaValidationIssueSeverity] = (
        SigmaValidationIssueSeverity.MEDIUM
    )
    fieldname: List[str]


class SigmahqUnknownFieldValidator(SigmaRuleValidator):
    """Checks if a rule uses an unknown field."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if len(rule.custom_attributes) > 0:
            return [SigmahqUnknownFieldIssue(rule, list(rule.custom_attributes.keys()))]
        else:
            return []
