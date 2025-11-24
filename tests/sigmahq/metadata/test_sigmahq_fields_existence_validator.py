from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqFieldsExistenceIssue,
    SigmahqFieldsExistenceValidator,
)


def test_validator_SigmahqFieldsExistence_1():
    validator = SigmahqFieldsExistenceValidator()
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
    fields:
        - eventid
    """
    )
    assert validator.validate(rule) == [SigmahqFieldsExistenceIssue([rule])]


def test_validator_SigmahqFieldsExistence_2():
    validator = SigmahqFieldsExistenceValidator()
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
    fields:
        - eventid
        - CommandLine
    """
    )
    assert validator.validate(rule) == [SigmahqFieldsExistenceIssue([rule])]


def test_validator_SigmahqFieldsExistence_valid():
    validator = SigmahqFieldsExistenceValidator()
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
