from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.falsepositive import (
    SigmahqFalsepositivesTypoWordIssue,
    SigmahqFalsepositivesTypoWordValidator,
)


def test_validator_SigmahqFalsepositivesTypoWord():
    validator = SigmahqFalsepositivesTypoWordValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - Pentest tool
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFalsepositivesTypoWord_unkown():
    validator = SigmahqFalsepositivesTypoWordValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - unkown
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqFalsepositivesTypoWordIssue(detection_rule, word="unkown")
    ]


def test_validator_SigmahqFalsepositivesTypoWord_custom():
    validator = SigmahqFalsepositivesTypoWordValidator(word_list=("maybe",))
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - Mayb tool
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFalsepositivesTypoWord_valid():
    validator = SigmahqFalsepositivesTypoWordValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - legitimate tools
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFalsepositivesTypoWord_correlation():
    validator = SigmahqFalsepositivesTypoWordValidator()
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
    falsepositives:
        - Pentest tool
    """
    )
    assert validator.validate(correlation_rule) == []


def test_validator_SigmahqFalsepositivesTypoWord_correlation_unkown():
    validator = SigmahqFalsepositivesTypoWordValidator()
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
    falsepositives:
        - unkown
    """
    )
    assert validator.validate(correlation_rule) == [
        SigmahqFalsepositivesTypoWordIssue(correlation_rule, word="unkown")
    ]


def test_validator_SigmahqFalsepositivesTypoWord_correlation_valid():
    validator = SigmahqFalsepositivesTypoWordValidator()
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
    falsepositives:
        - legitimate tools
    """
    )
    assert validator.validate(correlation_rule) == []
