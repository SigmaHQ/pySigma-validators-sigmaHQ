# tests/sigmahq/metadata/test_sigmahq_modified_date_order_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.date import (
    SigmahqModifiedDateOrderIssue,
    SigmahqModifiedDateOrderValidator,
)
from datetime import datetime


def test_validator_SigmahqModifiedDateOrder():
    validator = SigmahqModifiedDateOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    date: 2023-01-01
    modified: 2022-01-01
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [SigmahqModifiedDateOrderIssue([detection_rule])]


def test_validator_SigmahqModifiedDateOrder_valid():
    validator = SigmahqModifiedDateOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    date: 2022-01-01
    modified: 2023-01-01
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqModifiedDateOrder_correlation():
    validator = SigmahqModifiedDateOrderValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    date: 2023-01-01
    modified: 2022-01-01
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
    assert validator.validate(correlation_rule) == [
        SigmahqModifiedDateOrderIssue([correlation_rule])
    ]


def test_validator_SigmahqModifiedDateOrder_correlation_valid():
    validator = SigmahqModifiedDateOrderValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    date: 2022-01-01
    modified: 2023-01-01
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
