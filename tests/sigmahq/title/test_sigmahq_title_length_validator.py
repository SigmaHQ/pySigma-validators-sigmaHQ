from sigma.rule import SigmaRule
from sigma.validators.sigmahq.title import (
    SigmahqTitleLengthIssue,
    SigmahqTitleLengthValidator,
)


def test_validator_SigmahqTitleLength():
    validator = SigmahqTitleLengthValidator()
    rule = SigmaRule.from_yaml(
        """
title: ThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleTitleThisIsAVeryLongTitle
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTitleLengthIssue([rule])]


def test_validator_SigmahqTitleLength_custom():
    validator = SigmahqTitleLengthValidator(max_length=20)
    rule = SigmaRule.from_yaml(
        """
title: ThisIsAVeryLongTitle123
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTitleLengthIssue([rule])]


def test_validator_SigmahqTitleLength_custom_valid():
    validator = SigmahqTitleLengthValidator(max_length=20)
    rule = SigmaRule.from_yaml(
        """
title: ThisIsAVeryLongTitle
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


def test_validator_SigmahqTitleLength_valid():
    validator = SigmahqTitleLengthValidator()
    rule = SigmaRule.from_yaml(
        """
title: ThisIsNotAVeryLongTitle
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
