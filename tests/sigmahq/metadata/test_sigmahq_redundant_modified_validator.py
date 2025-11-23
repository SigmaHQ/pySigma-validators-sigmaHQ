from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqRedundantModifiedIssue,
    SigmahqRedundantModifiedValidator,
)


def test_validator_SigmahqRedundantModified():
    validator = SigmahqRedundantModifiedValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    date: 2024-08-09
    modified: 2024-08-09
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqRedundantModifiedIssue([rule])]


def test_validator_SigmahqRedundantModified_valid():
    validator = SigmahqRedundantModifiedValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    date: 2024-08-09
    modified: 2025-05-30
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []
