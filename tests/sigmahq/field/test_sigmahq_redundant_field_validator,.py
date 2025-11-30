from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule

from sigma.validators.sigmahq.field import (
    SigmahqRedundantFieldIssue,
    SigmahqRedundantFieldValidator,
)


def test_validator_SigmahqRedundantField():
    """Test that redundant fields are detected"""
    validator = SigmahqRedundantFieldValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Field Already in the Logsource
    status: test
    logsource:
        category: registry_set
        product: windows
    detection:
        selection:
            EventType: SetValue
            TargetObject|contains: 'SigmaHQ'
            Details|startswith: 'rules'
        condition: selection
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqRedundantFieldIssue([detection_rule], "EventType")
    ]


def test_validator_SigmahqRedundantField_valid():
    """Test that non-redundant fields are accepted"""
    validator = SigmahqRedundantFieldValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Field Already in the Logsource
    status: test
    logsource:
        category: registry_set
        product: windows
    detection:
        selection:
            TargetObject|contains: 'SigmaHQ'
            Details|startswith: 'rules'
        condition: selection
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqRedundantField_correlation():
    """Test that redundant fields are detected in correlation rules"""
    validator = SigmahqRedundantFieldValidator()
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
