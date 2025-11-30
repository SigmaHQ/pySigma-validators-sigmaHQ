from datetime import datetime

from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.status import (
    SigmahqStatusToHighIssue,
    SigmahqStatusToHighValidator,
)


def test_validator_SigmahqStatusToHigh():
    validator = SigmahqStatusToHighValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    detection_rule.date = datetime.now().date()
    assert validator.validate(detection_rule) == [SigmahqStatusToHighIssue([detection_rule])]


def test_validator_SigmahqStatusToHigh_valid():
    validator = SigmahqStatusToHighValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqStatusToHigh_with_regression_valid():
    validator = SigmahqStatusToHighValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: test
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    regression_tests_path: regression/rule/test_rule.yml
    """
    )
    detection_rule.date = datetime.now().date()
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqStatusToHigh_correlation():
    validator = SigmahqStatusToHighValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
status: stable
correlation:
    type: temporal
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
"""
    )
    correlation_rule.date = datetime.now().date()
    assert validator.validate(correlation_rule) == [SigmahqStatusToHighIssue([correlation_rule])]


def test_validator_SigmahqStatusToHigh_correlation_valid():
    validator = SigmahqStatusToHighValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
status: test
correlation:
    type: temporal
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
"""
    )
    assert validator.validate(correlation_rule) == []
