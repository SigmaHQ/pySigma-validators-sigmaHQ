from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqDescriptionExistenceIssue,
    SigmahqDescriptionExistenceValidator,
)


def test_validator_SigmahqDescriptionExistence():
    validator = SigmahqDescriptionExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqDescriptionExistenceIssue([rule])]


def test_validator_SigmahqDescriptionExistence_valid():
    validator = SigmahqDescriptionExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: a simple description
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []
