from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.correlation import (
    SigmahqCorrelationGroupByExistenceIssue,
    SigmahqCorrelationGroupByExistenceValidator,
)


def test_validator_SigmahqCorrelationGroupBy_event_count():
    validator = SigmahqCorrelationGroupByExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqCorrelationGroupByExistenceIssue([rule])]


def test_validator_SigmahqCorrelationGroupBy_temporal():
    validator = SigmahqCorrelationGroupByExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqCorrelationGroupByExistenceIssue([rule])]


def test_validator_SigmahqCorrelationGroupBy_valid():
    validator = SigmahqCorrelationGroupByExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(rule) == []
