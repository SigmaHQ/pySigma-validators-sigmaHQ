# sigma/validators/sigmahq/tags.py

from dataclasses import dataclass
from typing import ClassVar, List, Tuple

from sigma.rule import SigmaRuleBase
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

from sigma.data.mitre_attack import mitre_attack_techniques_tactics_mapping

from .config import ConfigHQ

config = ConfigHQ()


@dataclass
class SigmahqTagsUniqueDetectionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Multiple 'detection' tags found."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


class SigmahqTagsUniqueDetectionValidator(SigmaRuleValidator):
    """Ensures that the tag.namespace 'detection' is unique in the tags."""

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
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

    Folder_tag: Tuple[str, ...] = ("dfir", "emerging-threats", "threat-hunting")

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        if rule.source:
            for name in self.Folder_tag:
                if f"rules-{name}" in str(rule.source):
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

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        tlp_tags = [tag for tag in rule.tags or [] if tag.namespace == "tlp"]
        if len(tlp_tags) > 1:
            return [SigmahqTagsUniqueTlpIssue([rule])]
        return []


@dataclass
class SigmahqTagsTlpIssue(SigmaValidationIssue):
    tlp: str
    description: ClassVar[str] = "The rule uses a non-authorized TLP."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


@dataclass(frozen=True)
class SigmahqTagsTlpValidator(SigmaRuleValidator):
    """Checks if a rule uses a non-authorized TLP tag."""

    allowed_tlp: Tuple[str, ...] = ("clear",)

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        for tag in rule.tags or []:
            if tag.namespace == "tlp" and tag.name not in self.allowed_tlp:
                return [SigmahqTagsTlpIssue([rule], tlp=tag.name)]
        return []


@dataclass
class SigmahqTagsTechniquesWithoutTacticsIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "A MITRE ATT&CK technique tag was found without its corresponding tactic name. (e.g. when using 'attack.t1059' you have to add 'attack.execution' as well)"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    techniques: List[str]
    missing_tactic: str


class SigmahqTagsTechniquesWithoutTacticsValidator(SigmaRuleValidator):
    """Ensures that MITRE ATT&CK technique tags have their corresponding tactic tags."""

    def validate(self, rule: SigmaRuleBase) -> List[SigmaValidationIssue]:
        issues = []

        attack_tags = [tag for tag in rule.tags or [] if tag.namespace == "attack"]

        technique_tags = [
            tag.name
            for tag in attack_tags
            if tag.name.startswith("t") and any(c.isdigit() for c in tag.name)
        ]
        tactic_tags = [tag.name for tag in attack_tags if not tag.name.startswith("t")]

        missing_tactics = []
        for technique in technique_tags:
            technique_upper = technique.upper()

            if technique_upper in mitre_attack_techniques_tactics_mapping:
                required_tactics = mitre_attack_techniques_tactics_mapping[technique_upper]
                missing_tactics.extend(
                    [tactic for tactic in required_tactics if tactic not in tactic_tags]
                )

        if missing_tactics:
            for missing_tactic in set(missing_tactics):
                techniques = [
                    technique
                    for technique in technique_tags
                    if missing_tactic in mitre_attack_techniques_tactics_mapping[technique.upper()]
                ]
                issues.append(
                    SigmahqTagsTechniquesWithoutTacticsIssue(
                        [rule],
                        techniques=["attack." + t for t in techniques],
                        missing_tactic="attack." + missing_tactic,
                    )
                )

        return issues
