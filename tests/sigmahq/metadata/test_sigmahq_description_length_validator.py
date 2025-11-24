from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqDescriptionLengthIssue,
    SigmahqDescriptionLengthValidator,
)


def test_validator_SigmahqDescriptionLength():
    validator = SigmahqDescriptionLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqDescriptionLengthIssue([rule])]


def test_validator_SigmahqDescriptionLength_valid():
    validator = SigmahqDescriptionLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: a simple description to test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []
