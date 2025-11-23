from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqDateExistenceIssue,
    SigmahqDateExistenceValidator,
)


def test_validator_SigmahqDateExistence():
    validator = SigmahqDateExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqDateExistenceIssue([rule])]


def test_validator_SigmahqDateExistence_valid():
    validator = SigmahqDateExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    date: 2023-12-10
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []
