from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqLevelExistenceIssue,
    SigmahqLevelExistenceValidator,
)


def test_validator_SigmahqLevelExistence():
    validator = SigmahqLevelExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqLevelExistenceIssue([rule])]


def test_validator_SigmahqLevelExistence_valid():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    level: low
    """
    )
    assert validator.validate(rule) == []
