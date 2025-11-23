from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqAuthorExistenceIssue,
    SigmahqAuthorExistenceValidator,
)


def test_validator_SigmahqAuthorExistence():
    validator = SigmahqAuthorExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqAuthorExistenceIssue([rule])]


def test_validator_SigmahqAuthorExistence_valid():
    validator = SigmahqAuthorExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    author: test
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
