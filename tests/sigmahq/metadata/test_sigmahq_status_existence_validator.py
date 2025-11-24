from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqStatusExistenceIssue,
    SigmahqStatusExistenceValidator,
)


def test_validator_SigmahqStatusExistence():
    validator = SigmahqStatusExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusExistenceIssue([rule])]


def test_validator_SigmahqStatusExistence_valid():
    validator = SigmahqStatusExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []
