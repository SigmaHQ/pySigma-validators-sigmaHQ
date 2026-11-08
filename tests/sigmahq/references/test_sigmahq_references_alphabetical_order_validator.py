from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.references import (
    SigmahqReferencesAlphabeticalOrderIssue,
    SigmahqReferencesAlphabeticalOrderValidator,
)


def test_validator_SigmahqReferencesAlphabeticalOrder():
    validator = SigmahqReferencesAlphabeticalOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - https://example.com/zebra
        - https://example.com/apple
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqReferencesAlphabeticalOrderIssue(
            [detection_rule],
            ["https://example.com/zebra", "https://example.com/apple"],
        )
    ]


def test_validator_SigmahqReferencesAlphabeticalOrder_valid():
    validator = SigmahqReferencesAlphabeticalOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - https://example.com/apple
        - https://example.com/zebra
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqReferencesAlphabeticalOrder_case_insensitive():
    validator = SigmahqReferencesAlphabeticalOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - https://example.com/Apple
        - https://example.com/zebra
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqReferencesAlphabeticalOrder_correlation():
    validator = SigmahqReferencesAlphabeticalOrderValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    references:
        - https://example.com/zebra
        - https://example.com/apple
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
        SigmahqReferencesAlphabeticalOrderIssue(
            [correlation_rule],
            ["https://example.com/zebra", "https://example.com/apple"],
        )
    ]


def test_validator_SigmahqReferencesAlphabeticalOrder_correlation_valid():
    validator = SigmahqReferencesAlphabeticalOrderValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    references:
        - https://example.com/apple
        - https://example.com/zebra
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
