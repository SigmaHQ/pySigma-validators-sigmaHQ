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
    # Default minimum days (60 for non-log, 0 for log)
    (60, 0, 1, SigmaStatus.STABLE, False, True),   # New STABLE rule fails
    (60, 0, 60, SigmaStatus.STABLE, False, True),  # Exactly at min_nolog=60 fails
    (60, 0, 61, SigmaStatus.STABLE, False, False), # Just over min_nolog=60 passes

    # Custom minimum days for non-log rules (30 instead of 60)
    (30, 0, 1, SigmaStatus.STABLE, False, True),   # New STABLE rule fails with min_nolog=30
    (30, 0, 29, SigmaStatus.STABLE, False, True),  # Just under min_nolog=30 fails
    (30, 0, 30, SigmaStatus.STABLE, False, True),  # Exactly at min_nolog=30 fails
    (30, 0, 31, SigmaStatus.STABLE, False, False), # Just over min_nolog=30 passes

    # Custom minimum days for log rules (15 instead of 0)
    (60, 15, 1, SigmaStatus.STABLE, True, True),   # New STABLE rule fails with min_log=15
    (60, 15, 14, SigmaStatus.STABLE, True, True),  # Just under min_log=15 fails
    (60, 15, 15, SigmaStatus.STABLE, True, False), # Exactly at min_log=15 passes

    # Both custom minimum days
    (30, 15, 29, SigmaStatus.STABLE, False, True),   # Under min_nolog=30 fails for non-log rule
    (30, 15, 14, SigmaStatus.STABLE, True, True),    # Under min_log=15 fails for log rule

    # Regression test rules should always pass regardless of custom minimums
    (60, 0, 1, SigmaStatus.STABLE, True, False),
    (30, 15, 29, SigmaStatus.TEST, True, False),

    # EXPERIMENTAL status should always pass
    (60, 0, 1, SigmaStatus.EXPERIMENTAL, False, False)
]

def create_test_rule(min_nolog, min_log, days_ago, status, has_regression_tests, rule_type='detection'):
    """Helper function to create test rules with configurable minimum days.

    Args:
        min_nolog: Minimum days for non-log rules (not used in rule creation but passed for context)
        min_log: Minimum days for log rules (not used in rule creation but passed for context)
        days_ago: Number of days since rule creation
        status: Rule status level
        has_regression_tests: Boolean indicating if regression tests exist
        rule_type: Type of rule ('detection' or 'correlation')

    Returns:
        A SigmaRule or SigmaCorrelationRule instance based on the parameters.
    """
    date_str = (date.today() - timedelta(days=days_ago)).strftime('%Y-%m-%d')

    if rule_type == 'detection':
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
    else:  # correlation
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

    return SigmaRule.from_yaml(yaml_content) if rule_type == 'detection' else SigmaCorrelationRule.from_yaml(yaml_content)

def test_status_validation_basic_scenarios():
    """Test basic validation scenarios for both detection and correlation rules with configurable minimum days."""
    # Test all combinations of parameters
    for min_nolog, min_log, days_ago, status, has_regression_tests, expected_has_issue in TEST_PARAMS:
        # Create validator with custom minimum days
        validator = SigmahqStatusToHighValidator(
            min_days_for_nolog_rule=min_nolog,
            min_days_for_log_rule=min_log
        )

        # Test with detection rule
        detection_rule = create_test_rule(min_nolog, min_log, days_ago, status, has_regression_tests)
        if expected_has_issue:
            assert validator.validate(detection_rule) == [SigmahqStatusToHighIssue([detection_rule])]
        else:
            assert validator.validate(detection_rule) == []

        # Test with correlation rule
        correlation_rule = create_test_rule(min_nolog, min_log, days_ago, status, has_regression_tests, 'correlation')
        if expected_has_issue:
            assert validator.validate(correlation_rule) == [SigmahqStatusToHighIssue([correlation_rule])]
        else:
            assert validator.validate(correlation_rule) == []

def test_rules_without_date():
    """Test that rules without dates always pass validation regardless of minimum days settings."""
    # Test with different minimum days configurations
    validators = [
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=60, min_days_for_log_rule=0),
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=30, min_days_for_log_rule=15),
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=0, min_days_for_log_rule=0)
    ]

    # Test detection rule without date
    detection_rule = SigmaRule.from_yaml("""
title: Rule Without Date
status: stable
logsource:
    category: test
detection:
    sel:
        candle|exists: true
    condition: sel
""")

    # Test correlation rule without date
    correlation_rule = SigmaCorrelationRule.from_yaml("""
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
""")

    # All validators should pass rules without dates
    for validator in validators:
        assert validator.validate(detection_rule) == []
        assert validator.validate(correlation_rule) == []

