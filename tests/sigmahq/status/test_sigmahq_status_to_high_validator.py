from datetime import date, timedelta
import pytest
from sigma.rule import SigmaRule, SigmaStatus
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.status import (
    SigmahqStatusToHighIssue,
    SigmahqStatusToHighValidator,
)

# Constants for test parameters with min_days configuration
TEST_PARAMS = [
    # (min_nolog, min_log, days_ago, status, has_regression_tests, expected_has_issue)
    # Default minimum days (60 for non-log, 15 for log)
    (60, 15, 1, SigmaStatus.STABLE, False, True),  # New STABLE rule fails
    (60, 15, 60, SigmaStatus.STABLE, False, True),  # Exactly at min_nolog=60 fails
    (60, 15, 61, SigmaStatus.STABLE, False, False),  # Just over min_nolog=60 passes
    (30, 15, 1, SigmaStatus.STABLE, False, True),  # New STABLE rule fails with min_nolog=30
    (30, 15, 29, SigmaStatus.STABLE, False, True),  # Just under min_nolog=30 fails
    (30, 15, 30, SigmaStatus.STABLE, False, True),  # Exactly at min_nolog=30 fails
    (60, 15, 29, SigmaStatus.STABLE, True, False),  # Regression test rule passes
    (60, 15, 14, SigmaStatus.STABLE, True, True),  # Log rule with regression under min_log=15
    (30, 15, 29, SigmaStatus.TEST, True, False),  # TEST status always passes
]


def create_test_rule(days_ago, status, has_regression_tests):
    """Helper function to create test rules."""
    date_str = (date.today() - timedelta(days=days_ago)).strftime("%Y-%m-%d")

    yaml_content = f"""
title: Test Rule
status: {status.name.lower()}
date: {date_str}
logsource:
    category: test
    product: windows
detection:
    sel:
        candle|exists: true
    condition: sel
"""

    if has_regression_tests:
        yaml_content += "\nregression_tests_path: regression/rule/test_rule.yml"

    return SigmaRule.from_yaml(yaml_content)


def create_correlation_rule(days_ago, status, has_regression_tests):
    """Helper function to create correlation test rules."""
    date_str = (date.today() - timedelta(days=days_ago)).strftime("%Y-%m-%d")

    yaml_content = f"""
title: Test Correlation
id: 12345678-1234-1234-1234-123456789012
status: {status.name.lower()}
date: {date_str}
logsource:
    category: correlation
    product: windows
correlation:
    type: temporal
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
"""

    if has_regression_tests:
        yaml_content += "\nregression_tests_path: regression/rule/test_rule.yml"

    return SigmaCorrelationRule.from_yaml(yaml_content)


@pytest.mark.parametrize(
    "min_nolog, min_log, days_ago, status, has_regression_tests, expected_has_issue", TEST_PARAMS
)
def test_status_validation_detection(
    min_nolog, min_log, days_ago, status, has_regression_tests, expected_has_issue
):
    """Test validation scenarios for detection rules with configurable minimum days."""
    rule = create_test_rule(days_ago, status, has_regression_tests)

    validator = SigmahqStatusToHighValidator(
        min_days_for_nolog_rule=min_nolog, min_days_for_log_rule=min_log
    )

    if expected_has_issue:
        assert validator.validate(rule) == [SigmahqStatusToHighIssue([rule])]
    else:
        assert validator.validate(rule) == []


@pytest.mark.parametrize(
    "min_nolog, min_log, days_ago, status, has_regression_tests, expected_has_issue", TEST_PARAMS
)
def test_status_validation_correlation(
    min_nolog, min_log, days_ago, status, has_regression_tests, expected_has_issue
):
    """Test validation scenarios for correlation rules with configurable minimum days."""
    rule = create_correlation_rule(days_ago, status, has_regression_tests)

    validator = SigmahqStatusToHighValidator(
        min_days_for_nolog_rule=min_nolog, min_days_for_log_rule=min_log
    )
    if expected_has_issue:
        assert validator.validate(rule) == [SigmahqStatusToHighIssue([rule])]
    else:
        assert validator.validate(rule) == []


def test_rules_without_date():
    """Test that rules without dates always pass validation."""
    # Test with different minimum days configurations
    validators = [
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=60, min_days_for_log_rule=15),
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=30, min_days_for_log_rule=15),
    ]

    # Test detection rule without date
    detection_rule = SigmaRule.from_yaml(
        """
title: Rule Without Date
status: stable
logsource:
    category: test
detection:
    sel:
        candle|exists: true
    condition: sel
"""
    )

    # Test correlation rule without date
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Correlation Rule Without Date
id: 12345678-1234-1234-1234-123456789012
status: stable
logsource:
    category: correlation
product: windows
correlation:
    type: temporal
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
"""
    )

    # All validators should pass rules without dates
    for validator in validators:
        assert validator.validate(detection_rule) == []
        assert validator.validate(correlation_rule) == []


def test_rules_without_status():
    """Test that rules without dates always pass validation."""
    # Test with different minimum days configurations
    validators = [
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=60, min_days_for_log_rule=15),
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=30, min_days_for_log_rule=15),
    ]

    # Test detection rule without date
    detection_rule = SigmaRule.from_yaml(
        """
title: Rule Without Status
date: 2030-01-01
logsource:
    category: test
detection:
    sel:
        candle|exists: true
    condition: sel
"""
    )

    # Test correlation rule without date
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Correlation Rule Without Status
id: 12345678-1234-1234-1234-123456789012
date: 2030-01-01
logsource:
    category: correlation
product: windows
correlation:
    type: temporal
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
"""
    )

    # All validators should pass rules without dates
    for validator in validators:
        assert validator.validate(detection_rule) == []
        assert validator.validate(correlation_rule) == []
