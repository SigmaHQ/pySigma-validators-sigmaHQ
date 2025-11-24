from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqModifiedDateOrderIssue,
    SigmahqModifiedDateOrderValidator,
)


def test_validator_SigmahqModifiedDateOrder_older():
    validator = SigmahqModifiedDateOrderValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    date: 2023-12-10
    modified: 2023-12-05
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqModifiedDateOrderIssue([rule])]


def test_validator_SigmahqModifiedDateOrder_valid():
    validator = SigmahqModifiedDateOrderValidator()
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
