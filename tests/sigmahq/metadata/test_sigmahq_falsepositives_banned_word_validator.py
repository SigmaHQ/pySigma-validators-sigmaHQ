# tests/sigmahq/metadata/test_sigmahq_falsepositives_banned_word_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.metadata import (
    SigmahqFalsepositivesBannedWordIssue,
    SigmahqFalsepositivesBannedWordValidator,
)


def test_validator_SigmahqFalsepositivesBannedWord():
    validator = SigmahqFalsepositivesBannedWordValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - Pentest tools
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue([rule], "Pentest")]


def test_validator_SigmahqFalsepositivesBannedWord_custom():
    validator = SigmahqFalsepositivesBannedWordValidator(word_list=("maybe",))
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - Maybe
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue([rule], "Maybe")]


def test_validator_SigmahqFalsepositivesBannedWord_valid():
    validator = SigmahqFalsepositivesBannedWordValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
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
    assert validator.validate(rule) == []


# Correlation Rule Tests
def test_validator_SigmahqFalsepositivesBannedWord_correlation():
    validator = SigmahqFalsepositivesBannedWordValidator()
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
    falsepositives:
        - Pentest tools
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue([rule], "Pentest")]


def test_validator_SigmahqFalsepositivesBannedWord_correlation_valid():
    validator = SigmahqFalsepositivesBannedWordValidator()
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
    falsepositives:
        - legitimate tools
    """
    )
    assert validator.validate(rule) == []
