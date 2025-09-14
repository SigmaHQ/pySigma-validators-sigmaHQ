# sigma/validators/sigmahq/check_tags.py
# Only SigmaRule have tags in V2.0.0

from dataclasses import dataclass
from typing import ClassVar, List, Tuple, Union

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqTagsUniqueDetectionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Multiple 'detection' tags found."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqTagsUniqueDetectionValidator(SigmaRuleValidator):
    """Ensures that the tag.namespace 'detection' is unique in the tags."""

    def validate(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []
        detection_tags = [tag for tag in rule.tags or [] if tag.namespace == "detection"]
        if len(detection_tags) > 1:
            return [SigmahqTagsUniqueDetectionIssue([rule])]
        return []


@dataclass
class SigmahqTagsDetectionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule doesn't have a detection tag."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    tag: str


@dataclass(frozen=True)
class SigmahqTagsDetectionValidator(SigmaRuleValidator):
    """Checks if a rule in a specific folder has the corresponding detection tag."""

    folder_tag: Tuple[str, ...] = ("dfir", "emerging-threats", "threat-hunting")

    def validate(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []

        if not rule.source:
            return []

        source_path = str(rule.source)

        for name in self.folder_tag:
            if f"rules-{name}" in source_path:
                tag_found = False
                for tag in rule.tags or []:
                    if tag.namespace == "detection" and tag.name == name:
                        tag_found = True
                        break
                if not tag_found:
                    return [SigmahqTagsDetectionIssue([rule], tag=name)]
        return []


@dataclass
class SigmahqTagsUniqueTlpIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Multiple 'tlp' tags found."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqTagsUniqueTlpValidator(SigmaRuleValidator):
    """Ensures that the tag.namespace 'tlp' is unique in the tags."""

    def validate(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []
        tlp_tags = [tag for tag in rule.tags or [] if tag.namespace == "tlp"]
        if len(tlp_tags) > 1:
            return [SigmahqTagsUniqueTlpIssue([rule])]
        return []


@dataclass
class SigmahqTagsTlpIssue(SigmaValidationIssue):
    description: ClassVar[str] = "The rule uses a non-authorized TLP."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    tlp: str


@dataclass(frozen=True)
class SigmahqTagsTlpValidator(SigmaRuleValidator):
    """Checks if a rule uses a non-authorized TLP tag."""

    allowed_tlp: Tuple[str, ...] = ("clear",)

    def validate(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []
        for tag in rule.tags or []:
            if tag.namespace == "tlp" and tag.name not in self.allowed_tlp:
                return [SigmahqTagsTlpIssue([rule], tlp=tag.name)]
        return []
