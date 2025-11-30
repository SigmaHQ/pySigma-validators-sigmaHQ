from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.correlation import (
    SigmahqCorrelationRulesMinimumIssue,
    SigmahqCorrelationRulesMinimumValidator,
)


def test_validator_SigmahqCorrelationRulesMinimum_temporal():
    validator = SigmahqCorrelationRulesMinimumValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(correlation_rule) == [
        SigmahqCorrelationRulesMinimumIssue([correlation_rule])
    ]


def test_validator_SigmahqCorrelationRulesMinimum_temporal_valid():
    validator = SigmahqCorrelationRulesMinimumValidator()
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
    group-by:
        - ComputerName
"""
    )
    assert validator.validate(correlation_rule) == []


def test_validator_SigmahqCorrelationRulesMinimum_temporal_ordered():
    validator = SigmahqCorrelationRulesMinimumValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(correlation_rule) == [
        SigmahqCorrelationRulesMinimumIssue([correlation_rule])
    ]


def test_validator_SigmahqCorrelationRulesMinimum_event_count_valid():
    validator = SigmahqCorrelationRulesMinimumValidator()
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


def test_validator_SigmahqCorrelationRulesMinimum_with_regular_sigma_rule():
    """Test that regular SigmaRule objects don't trigger the correlation validation"""
    validator = SigmahqCorrelationRulesMinimumValidator()
    sigma_rule = SigmaRule.from_yaml(
        """
title: Test Regular Rule
id: 0e95725d-7320-415d-80f7-004da920fc12
logsource:
    product: windows
detection:
    selection:
        field: a
    condition: selection
"""
    )
    assert validator.validate(sigma_rule) == []


def test_validator_SigmahqCorrelationRulesMinimum_detection_missing_rules():
    """Test that event_count correlation rules with single rule trigger minimum validation issue"""
    validator = SigmahqCorrelationRulesMinimumValidator()
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


def test_validator_SigmahqCorrelationRulesMinimum_detection_multiple_rules():
    """Test that event_count correlation rules with multiple rules pass validation"""
    validator = SigmahqCorrelationRulesMinimumValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
        - 5638f7c0-ac70-491d-8465-2a65075e0d87
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert validator.validate(correlation_rule) == []
