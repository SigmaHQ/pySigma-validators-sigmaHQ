from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.correlation import (
    SigmahqCorrelationGroupByExistenceIssue,
    SigmahqCorrelationGroupByExistenceValidator,
)


def test_validator_SigmahqCorrelationGroupBy_event_count():
    validator = SigmahqCorrelationGroupByExistenceValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 1h
    condition:
        gte: 100
"""
    )
    assert validator.validate(correlation_rule) == [
        SigmahqCorrelationGroupByExistenceIssue([correlation_rule])
    ]


def test_validator_SigmahqCorrelationGroupBy_temporal():
    validator = SigmahqCorrelationGroupByExistenceValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
    timespan: 5m
"""
    )
    assert validator.validate(correlation_rule) == [
        SigmahqCorrelationGroupByExistenceIssue([correlation_rule])
    ]


def test_validator_SigmahqCorrelationGroupBy_valid():
    validator = SigmahqCorrelationGroupByExistenceValidator()
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


def test_validator_SigmahqCorrelationGroupBy_detection_rule():
    """Test that detection rules don't trigger the validator (should return empty list)"""
    validator = SigmahqCorrelationGroupByExistenceValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Test Detection Rule
id: 0e95725d-7320-415d-80f7-004da920fc12
logsource:
    product: windows
detection:
    selection:
        field: a
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []
