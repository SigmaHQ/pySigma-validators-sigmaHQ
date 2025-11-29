# tests/sigmahq/title/test_sigmahq_title_case_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.title import SigmahqTitleCaseValidator, SigmahqTitleCaseIssue

#
# Detection  Rule
#


def test_validator_SigmahqTitleCase_specialchar_valid():
    validator = SigmahqTitleCaseValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqTitleCase_valid_case():
    """Test that valid title casing passes validation"""
    validator = SigmahqTitleCaseValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: This Is A Valid Title
status: test
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqTitleCase_invalid_case():
    """Test that invalid title casing fails validation"""
    validator = SigmahqTitleCaseValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: this is a title with invalid casing
status: test
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"""
    )
    issues = validator.validate(detection_rule)
    assert len(issues) > 0
    assert all(isinstance(issue, SigmahqTitleCaseIssue) for issue in issues)


#
# Corelation  Rule
#


def test_validator_SigmahqTitleCase_specialchar_valid2():
    validator = SigmahqTitleCaseValidator()
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


def test_validator_SigmahqTitleCase_correlation_valid_case():
    """Test that valid title casing passes validation for correlation rules"""
    validator = SigmahqTitleCaseValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: This Is A Valid Correlation Title
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


def test_validator_SigmahqTitleCase_correlation_invalid_case():
    """Test that invalid title casing fails validation for correlation rules"""
    validator = SigmahqTitleCaseValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: this is an invalid title
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
    assert len(issues) > 0
    assert all(isinstance(issue, SigmahqTitleCaseIssue) for issue in issues)
