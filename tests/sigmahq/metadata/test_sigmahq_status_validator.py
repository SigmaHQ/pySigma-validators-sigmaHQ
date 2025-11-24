from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqStatusIssue,
    SigmahqStatusValidator,
)


def test_validator_SigmahqStatus_Unsupported():
    validator = SigmahqStatusValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusIssue([rule])]


def test_validator_SigmahqStatus_Deprecated():
    validator = SigmahqStatusValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: deprecated
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusIssue([rule])]


def test_validator_SigmahqStatus_valid():
    validator = SigmahqStatusValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []
