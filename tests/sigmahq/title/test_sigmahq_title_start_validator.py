from sigma.rule import SigmaRule
from sigma.validators.sigmahq.title import (
    SigmahqTitleStartIssue,
    SigmahqTitleStartValidator,
)


def test_validator_SigmahqTitleStart():
    validator = SigmahqTitleStartValidator()
    rule = SigmaRule.from_yaml(
        """
title: Detects an Alert
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTitleStartIssue([rule])]


def test_validator_SigmahqTitleStart_detection():
    validator = SigmahqTitleStartValidator()
    rule = SigmaRule.from_yaml(
        """
title: Detection of an Alert
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
