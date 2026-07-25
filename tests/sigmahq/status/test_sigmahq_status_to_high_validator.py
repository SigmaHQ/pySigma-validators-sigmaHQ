from datetime import date, timedelta

import pytest
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule, SigmaStatus

from sigma.validators.sigmahq.status import (
    SigmahqStatusToHighIssue,
    SigmahqStatusToHighValidator,
)

TEST_PARAMS = [
    (60, 15, 1, SigmaStatus.STABLE, False, True),
    (60, 15, 60, SigmaStatus.STABLE, False, True),
    (60, 15, 61, SigmaStatus.STABLE, False, False),
    (30, 15, 1, SigmaStatus.STABLE, False, True),
    (30, 15, 29, SigmaStatus.STABLE, False, True),
    (30, 15, 30, SigmaStatus.STABLE, False, True),
    (60, 15, 29, SigmaStatus.STABLE, True, False),
    (60, 15, 14, SigmaStatus.STABLE, True, True),
    (30, 15, 29, SigmaStatus.TEST, True, False),
]


def create_test_rule(days_ago, status, has_regression_tests):
    date_str = (date.today() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    yaml_content = f"""title: Test Rule
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
    date_str = (date.today() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    yaml_content = f"""title: Test Correlation
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
    rule = create_correlation_rule(days_ago, status, has_regression_tests)
    validator = SigmahqStatusToHighValidator(
        min_days_for_nolog_rule=min_nolog, min_days_for_log_rule=min_log
    )
    if expected_has_issue:
        assert validator.validate(rule) == [SigmahqStatusToHighIssue([rule])]
    else:
        assert validator.validate(rule) == []


def test_rules_without_date():
    validators = [
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=60, min_days_for_log_rule=15),
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=30, min_days_for_log_rule=15),
    ]
    detection_rule = SigmaRule.from_yaml(
        """title: Rule Without Date
status: stable
logsource:
    category: test
detection:
    sel:
        candle|exists: true
    condition: sel
"""
    )
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """title: Correlation Rule Without Date
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
    for validator in validators:
        assert validator.validate(detection_rule) == []
        assert validator.validate(correlation_rule) == []


def test_rules_without_status():
    validators = [
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=60, min_days_for_log_rule=15),
        SigmahqStatusToHighValidator(min_days_for_nolog_rule=30, min_days_for_log_rule=15),
    ]
    detection_rule = SigmaRule.from_yaml(
        """title: Rule Without Status
date: 2030-01-01
logsource:
    category: test
detection:
    sel:
        candle|exists: true
    condition: sel
"""
    )
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """title: Correlation Rule Without Status
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
    for validator in validators:
        assert validator.validate(detection_rule) == []
        assert validator.validate(correlation_rule) == []
