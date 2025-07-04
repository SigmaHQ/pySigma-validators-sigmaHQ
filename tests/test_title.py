# tests/test_title.py

from sigma.rule import SigmaRule

from sigma.validators.sigmahq.title import (
    SigmahqTitleLengthIssue,
    SigmahqTitleLengthValidator,
    SigmahqTitleStartIssue,
    SigmahqTitleStartValidator,
    SigmahqTitleEndIssue,
    SigmahqTitleEndValidator,
    SigmahqTitleCaseIssue,
    SigmahqTitleCaseValidator,
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
