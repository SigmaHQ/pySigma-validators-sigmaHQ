from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.tags import (
    SigmahqTagsAlphabeticalOrderIssue,
    SigmahqTagsAlphabeticalOrderValidator,
)


def test_validator_SigmahqTagsAlphabeticalOrder_namespace_order():
    validator = SigmahqTagsAlphabeticalOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    tags:
        - detection.threat-hunting
        - attack.execution
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqTagsAlphabeticalOrderIssue(
            [detection_rule],
            ["detection.threat-hunting", "attack.execution"],
        )
    ]


def test_validator_SigmahqTagsAlphabeticalOrder_name_order():
    validator = SigmahqTagsAlphabeticalOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    tags:
        - attack.t1059
        - attack.execution
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqTagsAlphabeticalOrderIssue(
            [detection_rule],
            ["attack.t1059", "attack.execution"],
        )
    ]


def test_validator_SigmahqTagsAlphabeticalOrder_valid():
    validator = SigmahqTagsAlphabeticalOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    tags:
        - attack.execution
        - attack.t1059
        - detection.threat-hunting
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqTagsAlphabeticalOrder_case_insensitive():
    validator = SigmahqTagsAlphabeticalOrderValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    tags:
        - Attack.Execution
        - attack.t1059
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqTagsAlphabeticalOrder_correlation():
    validator = SigmahqTagsAlphabeticalOrderValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    tags:
        - detection.threat-hunting
        - attack.execution
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
        SigmahqTagsAlphabeticalOrderIssue(
            [correlation_rule],
            ["detection.threat-hunting", "attack.execution"],
        )
    ]


def test_validator_SigmahqTagsAlphabeticalOrder_correlation_valid():
    validator = SigmahqTagsAlphabeticalOrderValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    tags:
        - attack.execution
        - detection.threat-hunting
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
