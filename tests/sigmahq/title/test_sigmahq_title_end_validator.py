# tests/test_sigmahq_title_end_validator.py

from sigma.rule import SigmaRule
from sigma.validators.sigmahq.title import (
    SigmahqTitleEndIssue,
    SigmahqTitleEndValidator,
)


def test_validator_SigmahqTitleEnd():
    validator = SigmahqTitleEndValidator()
    rule = SigmaRule.from_yaml(
        """
title: Title end with a.
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTitleEndIssue([rule])]


def test_validator_SigmahqTitleEnd_valid():
    validator = SigmahqTitleEndValidator()
    rule = SigmaRule.from_yaml(
        """
title: Title end without a dot
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
