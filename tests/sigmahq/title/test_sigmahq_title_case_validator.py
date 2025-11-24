# tests/test_sigmahq_title_case_validator.py

from sigma.rule import SigmaRule
from sigma.validators.sigmahq.title import (
    SigmahqTitleCaseIssue,
    SigmahqTitleCaseValidator,
)


def test_validator_SigmahqTitleCase():
    validator = SigmahqTitleCaseValidator()
    rule = SigmaRule.from_yaml(
        """
title: Case is needed for the Title
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [
        SigmahqTitleCaseIssue([rule], "is"),
        SigmahqTitleCaseIssue([rule], "needed"),
    ]


def test_validator_SigmahqTitleCase_custom():
    validator = SigmahqTitleCaseValidator(word_list=("a", "title", "is", "needed"))
    rule = SigmaRule.from_yaml(
        """
title: Case is needed For a beautiful title
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTitleCaseIssue([rule], "beautiful")]


def test_validator_SigmahqTitleCase_valid():
    validator = SigmahqTitleCaseValidator()
    rule = SigmaRule.from_yaml(
        """
title: Case Is Needed for the Title
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


def test_validator_SigmahqTitleCase_specialchar_valid():
    validator = SigmahqTitleCaseValidator()
    rule = SigmaRule.from_yaml(
        """
title: Case Is Needed for the Title Except test.com
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


def test_validator_SigmahqTitleCase_slash_valid():
    validator = SigmahqTitleCaseValidator()
    rule = SigmaRule.from_yaml(
        """
title: Case Is Needed for the Title Except test/com
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


def test_validator_SigmahqTitleCase_underscore_valid():
    validator = SigmahqTitleCaseValidator()
    rule = SigmaRule.from_yaml(
        """
title: Case Is Needed for the Title Except test_com
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
