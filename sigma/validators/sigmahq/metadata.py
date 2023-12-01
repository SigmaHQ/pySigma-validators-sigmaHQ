import re
from collections import Counter
from collections import defaultdict
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Set
from uuid import UUID

from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class SigmahqFilenameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filemane doesn't match SigmaHQ standard"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    filename: str


class SigmahqFilenameValidator(SigmaRuleValidator):
    """Check rule filename match SigmaHQ standard."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        filename_pattern = re.compile(r"[a-z0-9_]{10,90}\.yml")
        if rule.source is not None:
            filename = rule.source.path.name
            if filename_pattern.match(filename) is None or not "_" in filename:
                return [SigmahqFilenameIssue(rule, filename)]
        return []


@dataclass
class SigmahqTitleLengthIssue(SigmaValidationIssue):
    description = "Rule has a title longer than 110 characters"
    severity = SigmaValidationIssueSeverity.MEDIUM


class SigmahqTitleLengthValidator(SigmaRuleValidator):
    """Checks if rule has a title length longer than 110."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if len(rule.title) > 110:
            return [SigmahqTitleLengthIssue([rule])]
        else:
            return []
