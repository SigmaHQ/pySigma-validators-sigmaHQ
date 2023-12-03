from dataclasses import dataclass
from typing import List

from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

sigmahq_invalid_trademark = {"MITRE ATT&CK", "ATT&CK"}
sigmahq_fp_banned_word = {"none", "pentest", "penetration"}
sigmahq_fp_typo_word = {"unkown", "ligitimate", "legitim ", "legitimeate"}
sigmahq_link_in_description = {"http://", "https://", "internal research"}


@dataclass
class SigmahqStatusExistenceIssue(SigmaValidationIssue):
    description = "Rule has no status"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqStatusExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a status."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status is None:
            return [SigmahqStatusExistenceIssue(rule)]
        else:
            return []


@dataclass
class SigmahqStatusUnsupportedIssue(SigmaValidationIssue):
    description = "Rule has a UNSUPPORTED status"
    severity = SigmaValidationIssueSeverity.HIGH


class SigmahqStatusUnsupportedValidator(SigmaRuleValidator):
    """Checks if rule has a status UNSUPPORTED."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status and rule.status.name == "UNSUPPORTED":
            return [SigmahqStatusUnsupportedIssue(rule)]
        else:
            return []


@dataclass
class SigmahqStatusDeprecatedIssue(SigmaValidationIssue):
    description = "Rule has a DEPRECATED status"
    severity = SigmaValidationIssueSeverity.HIGH


class SigmahqStatusDeprecatedValidator(SigmaRuleValidator):
    """Checks if rule has a status DEPRECATED."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status and rule.status.name == "DEPRECATED":
            return [SigmahqStatusDeprecatedIssue(rule)]
        else:
            return []


@dataclass
class SigmahqDateExistenceIssue(SigmaValidationIssue):
    description = "Rule has no date"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqDateExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a data."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.date is None:
            return [SigmahqDateExistenceIssue(rule)]
        else:
            return []


@dataclass
class SigmahqDescriptionExistenceIssue(SigmaValidationIssue):
    description = "Rule has no description"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqDescriptionExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description is None:
            return [SigmahqDescriptionExistenceIssue(rule)]
        else:
            return []


@dataclass
class SigmahqDescriptionLengthIssue(SigmaValidationIssue):
    description = "Rule has a too short description"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqDescriptionLengthValidator(SigmaRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description is not None and len(rule.description) < 16:
            return [SigmahqDescriptionLengthIssue(rule)]
        else:
            return []


@dataclass
class SigmahqLevelExistenceIssue(SigmaValidationIssue):
    description = "Rule has no level"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqLevelExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a level."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.level is None:
            return [SigmahqLevelExistenceIssue([rule])]
        else:
            return []


@dataclass
class SigmahqLegalTrademarkIssue(SigmaValidationIssue):
    description = "Rule contains a legal trademark"
    severity = SigmaValidationIssueSeverity.MEDIUM
    trademark: str


class SigmahqLegalTrademarkValidator(SigmaRuleValidator):
    """Checks if rule contains a legal trademark."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        raw_rule = str(rule)
        for trademark in sigmahq_invalid_trademark:
            if trademark in raw_rule:
                return [SigmahqLegalTrademarkIssue([rule], trademark)]
        return []


@dataclass
class SigmahqFalsepositivesCapitalIssue(SigmaValidationIssue):
    description = "Rule falsepositive must start with a capital"
    severity = SigmaValidationIssueSeverity.MEDIUM
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
    description = "Rule falsepositive start with a banned word"
    severity = SigmaValidationIssueSeverity.MEDIUM
    word: str


class SigmahqFalsepositivesBannedWordValidator(SigmaRuleValidator):
    """Checks if rule falsepositive start with a banned word."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        falsepositif = []
        if rule.falsepositives:
            for fp in rule.falsepositives:
                if fp.split(" ")[0].lower() in sigmahq_fp_banned_word:
                    falsepositif.append(
                        SigmahqFalsepositivesBannedWordIssue(rule, fp.split(" ")[0])
                    )
        return falsepositif


@dataclass
class SigmahqFalsepositivesTypoWordIssue(SigmaValidationIssue):
    description = "Rule falsepositive start with a common typo error"
    severity = SigmaValidationIssueSeverity.MEDIUM
    word: str


class SigmahqFalsepositivesTypoWordValidator(SigmaRuleValidator):
    """Checks if rule falsepositive start with a common typo error."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        falsepositif = []
        if rule.falsepositives:
            for fp in rule.falsepositives:
                if fp.split(" ")[0].lower() in sigmahq_fp_typo_word:
                    falsepositif.append(
                        SigmahqFalsepositivesTypoWordIssue(rule, fp.split(" ")[0])
                    )
        return falsepositif


@dataclass
class SigmahqLinkDescriptionIssue(SigmaValidationIssue):
    description = "Rule description have a link with no references"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqLinkDescriptionValidator(SigmaRuleValidator):
    """Checks if rule description use a link instead of references."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description and rule.references == []:
            for link in sigmahq_link_in_description:
                if link in rule.description.lower():
                    return [SigmahqLinkDescriptionIssue(rule)]
        return []