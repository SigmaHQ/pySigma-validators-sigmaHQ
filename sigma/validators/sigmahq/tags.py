from dataclasses import dataclass
from typing import ClassVar, List, Tuple

from sigma.rule import SigmaRule, SigmaRuleBase
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)
from .config import ConfigHQ

config = ConfigHQ()


@dataclass
class SigmahqTagsDetectionEmergingthreatsIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule in Emerging-threats folder don't have detection.emerging-threats tag."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW


class SigmahqTagsDetectionEmergingthreatsValidator(SigmaRuleValidator):
    """Checks if a rule in Emerging-threats folder have the detection.emerging-threats tag."""

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        if rule.source and "rules-emerging-threats" in str(rule.source):
            if rule.tags:
                for tag in rule.tags:
                    if tag.namespace == "detection" and tag.name == "emerging-threats":
                        return []
            return [SigmahqTagsDetectionEmergingthreatsIssue([rule])]
        return []


@dataclass
class SigmahqTagsDetectionThreathuntingIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule in Threat-hunting folder don't have detection.threat-hunting tag."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW


class SigmahqTagsDetectionThreathuntingValidator(SigmaRuleValidator):
    """Checks if a rule in Threat-hunting folder have the detection.threat-hunting tag."""

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        if rule.source and "rules-threat-hunting" in str(rule.source):
            if rule.tags:
                for tag in rule.tags:
                    if tag.namespace == "detection" and tag.name == "threat-hunting":
                        return []
            return [SigmahqTagsDetectionThreathuntingIssue([rule])]
        return []


@dataclass
class SigmahqTagsDetectionDfirIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule in Dfir folder don't have the detection.dfir tag."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW


class SigmahqTagsDetectionDfirValidator(SigmaRuleValidator):
    """Checks if a rule in Dfir folder have detection.dfir tag."""

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        if rule.source and "rules-dfir" in str(rule.source):
            if rule.tags:
                for tag in rule.tags:
                    if tag.namespace == "detection" and tag.name == "dfir":
                        return []
            return [SigmahqTagsDetectionDfirIssue([rule])]
        return []


@dataclass
class SigmahqTagsTlpIssue(SigmaValidationIssue):
    description: ClassVar[str] = "The rule uses a non-authorized TLP."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    tlp: str


@dataclass(frozen=True)
class SigmahqTagsTlpValidator(SigmaRuleValidator):
    """Checks if a rule use a not allowed tlp tag."""

    allowed_tlp: Tuple[str, ...] = ("clear",)

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        rule_error = list()
        if rule.tags:
            for tag in rule.tags:
                if tag.namespace == "tlp" and tag.name not in self.allowed_tlp:
                    rule_error.append(SigmahqTagsTlpIssue([rule], tag.name))
        return rule_error
