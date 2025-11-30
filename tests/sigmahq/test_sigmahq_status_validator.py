from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.status import (
    SigmahqStatusIssue,
    SigmahqStatusValidator,
)


def test_detection_rule():
    validator = SigmahqStatusValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_correlation_rule():
    validator = SigmahqStatusValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: stable
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


def test_detection_rule_deprecated_status():
    """Test that deprecated status triggers an issue"""
    validator = SigmahqStatusValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: deprecated
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert len(validator.validate(detection_rule)) == 1
    assert isinstance(validator.validate(detection_rule)[0], SigmahqStatusIssue)


def test_correlation_rule_deprecated_status():
    """Test that deprecated status triggers an issue for correlation rules"""
    validator = SigmahqStatusValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: deprecated
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
    assert len(validator.validate(correlation_rule)) == 1
    assert isinstance(validator.validate(correlation_rule)[0], SigmahqStatusIssue)


def test_detection_rule_unsupported_status():
    """Test that unsupported status triggers an issue"""
    validator = SigmahqStatusValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: unsupported
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert len(validator.validate(detection_rule)) == 1
    assert isinstance(validator.validate(detection_rule)[0], SigmahqStatusIssue)


def test_correlation_rule_unsupported_status():
    """Test that unsupported status triggers an issue for correlation rules"""
    validator = SigmahqStatusValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: unsupported
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
    assert len(validator.validate(correlation_rule)) == 1
    assert isinstance(validator.validate(correlation_rule)[0], SigmahqStatusIssue)
