from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.status import (
    SigmahqStatusExistenceIssue,
    SigmahqStatusExistenceValidator,
)


def test_validator_SigmahqStatusExistence():
    validator = SigmahqStatusExistenceValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [SigmahqStatusExistenceIssue([detection_rule])]


def test_validator_SigmahqStatusExistence_valid():
    validator = SigmahqStatusExistenceValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
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


def test_validator_SigmahqStatus_correlation():
    validator = SigmahqStatusExistenceValidator()
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
    assert validator.validate(correlation_rule) == [SigmahqStatusExistenceIssue([correlation_rule])]


def test_validator_SigmahqStatus_correlation_valid():
    validator = SigmahqStatusExistenceValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: experimental
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
