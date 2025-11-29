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
class SigmahqGithubLinkIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule has a branch GitHub link instead of a permalink. Use e.g. https://github.com/SigmaHQ/sigma/blob/bd2a4c37efde5f69f87040173e990f1f6ff9e234/README.md instead of https://github.com/SigmaHQ/sigma/blob/master/README.md"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    link: str


class SigmahqGithubLinkValidator(SigmaRuleValidator):
    """Checks if a rule has a branch GitHub link"""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        result: List[SigmaValidationIssue] = []
        if rule.references is not None:
            for link in rule.references:
                if re.match(r"https://github.com/.*\.\w{1,3}$", link) is not None:
                    if re.match(r".*/[0-9a-z]{40}/.*", link) is None:
                        result.append(SigmahqGithubLinkIssue([rule], link))
        return result


@dataclass
class SigmahqMitreLinkIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule has a MITRE link instead of a MITRE attack tag. Use e.g. - attack.t1053.003"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    link: str


class SigmahqMitreLinkValidator(SigmaRuleValidator):
    """Checks if a rule uses a MITRE link instead of tag"""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        result: List[SigmaValidationIssue] = []
        if rule.references is not None:
            for link in rule.references:
                if link.startswith("https://attack.mitre.org/"):
                    result.append(SigmahqMitreLinkIssue([rule], link))
        return result
