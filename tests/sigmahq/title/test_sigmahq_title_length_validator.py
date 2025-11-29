# tests/sigmahq/title/test_sigmahq_title_length_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.title import SigmahqTitleLengthValidator, SigmahqTitleLengthIssue

#
# Detection Rule Tests
#


def test_validator_SigmahqTitleLength_valid():
    """Test that detection rules with titles not exceeding max length pass validation"""
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


def test_validator_SigmahqTitleLength_invalid():
    """Test that detection rules with titles exceeding max length are caught"""
    validator = SigmahqTitleLengthValidator()
    rule = SigmaRule.from_yaml(
        """
title: This is a very long title that exceeds the maximum allowed length of one hundred and twenty characters which should trigger an error
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqTitleLengthIssue)


def test_validator_SigmahqTitleLength_exactly_max():
    """Test that detection rules with titles exactly at max length pass validation"""
    validator = SigmahqTitleLengthValidator()
    # Create a title with exactly max_length characters
    long_title = "A" * 120
    rule = SigmaRule.from_yaml(
        f"""
title: {long_title}
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


#
# Correlation Rule Tests
#


def test_validator_SigmahqTitleLength_valid_correlation():
    """Test that correlation rules with titles not exceeding max length pass validation"""
    validator = SigmahqTitleLengthValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert validator.validate(correlation_rule) == []


def test_validator_SigmahqTitleLength_correlation_invalid():
    """Test that correlation rules with titles exceeding max length are caught"""
    validator = SigmahqTitleLengthValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: This is a very long correlation title that exceeds the maximum allowed length of one hundred and twenty characters which should trigger an error
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    issues = validator.validate(correlation_rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqTitleLengthIssue)


def test_validator_SigmahqTitleLength_correlation_exactly_max():
    """Test that correlation rules with titles exactly at max length pass validation"""
    validator = SigmahqTitleLengthValidator()
    # Create a title with exactly max_length characters
    long_title = "A" * 120
    correlation_rule = SigmaCorrelationRule.from_yaml(
        f"""
title: {long_title}
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert validator.validate(correlation_rule) == []


#
# Edge Case Tests
#


def test_validator_SigmahqTitleLength_empty_title():
    """Test that empty title passes validation (doesn't exceed max length)"""
    validator = SigmahqTitleLengthValidator()
    rule = SigmaRule.from_yaml(
        """
title: ""
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
