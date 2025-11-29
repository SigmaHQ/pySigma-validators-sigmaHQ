from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.correlation import (
    SigmahqCorrelationRulesMinimumIssue,
    SigmahqCorrelationRulesMinimumValidator,
)


def test_validator_SigmahqCorrelationRulesMinimum_temporal():
    validator = SigmahqCorrelationRulesMinimumValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: temporal
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
"""
    )
    assert validator.validate(rule) == [SigmahqCorrelationRulesMinimumIssue([rule])]


def test_validator_SigmahqCorrelationRulesMinimum_temporal_valid():
    validator = SigmahqCorrelationRulesMinimumValidator()
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
    group-by:
        - ComputerName
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqCorrelationRulesMinimum_temporal_ordered():
    validator = SigmahqCorrelationRulesMinimumValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: temporal_ordered
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
"""
    )
    assert validator.validate(rule) == [SigmahqCorrelationRulesMinimumIssue([rule])]


def test_validator_SigmahqCorrelationRulesMinimum_event_count_valid():
    validator = SigmahqCorrelationRulesMinimumValidator()
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
