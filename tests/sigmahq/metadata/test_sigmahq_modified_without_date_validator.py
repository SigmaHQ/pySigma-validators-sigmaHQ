from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqModifiedWithoutDateIssue,
    SigmahqModifiedWithoutDateValidator,
)


def test_validator_SigmahqModifiedWithoutDate():
    validator = SigmahqModifiedWithoutDateValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    modified: 2023-12-05
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqModifiedWithoutDateIssue([rule])]


def test_validator_SigmahqModifiedWithoutDate_valid():
    validator = SigmahqModifiedWithoutDateValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    date: 2023-12-10
    modified: 2023-12-15
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []
